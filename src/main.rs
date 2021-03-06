pub mod debug;
pub mod process;
pub mod scan;
pub mod thread;
pub mod ui;

use process::Process;
use scan::{Scan, Scannable};
use std::fmt;
use winapi::um::winnt;

/// Environment variable with the process identifier of the process to work with.
/// If the variable if not set (`set PID=...`), it's asked at runtime.
static PROGRAM_PID: Option<&str> = option_env!("PID");

struct ProcessItem {
    pid: u32,
    name: String,
}

impl fmt::Display for ProcessItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (pid={})", self.name, self.pid)
    }
}

fn main() {
    let pid = PROGRAM_PID
        .map(|pid| pid.parse::<u32>().unwrap())
        .unwrap_or_else(|| {
            let processes = process::enum_proc()
                .unwrap()
                .into_iter()
                .flat_map(Process::open)
                .flat_map(|proc| match proc.name() {
                    Ok(name) => Ok(ProcessItem {
                        pid: proc.pid(),
                        name,
                    }),
                    Err(err) => Err(err),
                })
                .collect::<Vec<_>>();

            let item = ui::list_picker(&processes);
            item.pid
        });

    let process = Process::open(pid).unwrap();
    println!("Opened process {:?}", process);

    let mask = winnt::PAGE_EXECUTE_READWRITE
        | winnt::PAGE_EXECUTE_WRITECOPY
        | winnt::PAGE_READWRITE
        | winnt::PAGE_WRITECOPY;

    let regions = process
        .memory_regions()
        .into_iter()
        .filter(|p| (p.Protect & mask) != 0)
        .collect::<Vec<_>>();

    println!("Scanning {} memory regions", regions.len());
    let scan = ui::prompt_scan().unwrap();
    let mut last_scan = process.scan_regions(&regions, scan);
    println!(
        "Found {} locations",
        last_scan.iter().map(|r| r.locations.len()).sum::<usize>()
    );

    while last_scan.iter().map(|r| r.locations.len()).sum::<usize>() != 1 {
        let scan = match ui::prompt_scan() {
            Ok(scan) => scan,
            Err(_) => break,
        };
        last_scan = process.rescan_regions(&last_scan, scan);
        println!(
            "Now have {} locations",
            last_scan.iter().map(|r| r.locations.len()).sum::<usize>()
        );
    }

    if !maybe_do_inject_code(pid, &last_scan, &process) {
        do_change_value(last_scan, process);
    }
}

#[cfg(feature = "patch-nops")]
fn maybe_do_inject_code(pid: u32, last_scan: &[scan::Region], process: &Process) -> bool {
    let action = ui::prompt::<String>(
        "Do you want to inject code on the writes to those locations (y/n)?: ",
    )
    .unwrap();

    if action != "y" && action != "Y" {
        return false;
    }

    let debugger = debug::debug(pid).unwrap();
    let mut threads = thread::enum_threads(pid)
        .unwrap()
        .into_iter()
        .map(thread::Thread::open)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    last_scan.into_iter().for_each(|region| {
        region.locations.iter().for_each(|addr| {
            println!("Watching writes to {:x} for 10s", addr);
            let watchpoints = threads
                .iter_mut()
                .map(|thread| {
                    thread
                        .add_breakpoint(addr, thread::Condition::Write, thread::Size::DoubleWord)
                        .unwrap()
                })
                .collect::<Vec<_>>();

            let addr = loop {
                let event = debugger.wait_event(None).unwrap();
                if event.dwDebugEventCode == winapi::um::minwinbase::EXCEPTION_DEBUG_EVENT {
                    let exc = unsafe { event.u.Exception() };
                    if exc.ExceptionRecord.ExceptionCode
                        == winapi::um::minwinbase::EXCEPTION_SINGLE_STEP
                    {
                        debugger.cont(event, true).unwrap();
                        break exc.ExceptionRecord.ExceptionAddress as usize;
                    }
                }
                debugger.cont(event, true).unwrap();
            };

            drop(watchpoints);

            let action = ui::prompt::<String>(&format!(
                "Do you want to simply inject NOPs replacing the old code at {:x} (y/n)?: ",
                addr
            ))
            .unwrap();

            if action == "y" && action == "Y" {
                process.nop_last_instruction(addr).unwrap();
            } else {
                let region = process
                    .memory_regions()
                    .into_iter()
                    .rev()
                    .find(|p| (p.State & winnt::MEM_FREE) != 0 && (p.BaseAddress as usize) < addr)
                    .unwrap();

                let target_addr = process.alloc(region.BaseAddress as usize + region.RegionSize - 2048, 2048).unwrap();

                // The relative JMP itself are 5 bytes, the last 2 are NOP (hence the -2 in delta calculation).
                // Relative jumps add to the instruction pointer when it *ends* executing the instruction (like JMP).
                //   jmp target_addr
                //   nop 2
                let mut jmp = [0xE9, 0, 0, 0, 0, 0x66, 0x90];
                jmp[1..5].copy_from_slice(&((target_addr as isize - (addr - 2) as isize) as i32).to_le_bytes());
                process.write_memory(addr - jmp.len(), &jmp).unwrap();

                // addr is already where the old instruction ended, no need to re-skip our previously written jump.
                // By the end of the execution of this jump, the instruction pointer will be at (base + code len).
                //   add dword ptr [rsi+000007E0], 2
                //   jmp addr
                let mut injection = [0x83, 0x86, 0xE0, 0x07, 0x00, 0x00, 0x02, 0xE9, 0, 0, 0, 0];
                let inj_len = injection.len();
                injection[8..12].copy_from_slice(&((addr as isize - (target_addr + inj_len) as isize) as i32).to_le_bytes());
                process.write_memory(target_addr, &injection).unwrap();

                println!("Replaced the SUB 1 at {:x} with ADD 2 at {:x} successfully!", addr, target_addr);
            }
        })
    });

    true
}

#[cfg(not(feature = "patch-nops"))]
fn maybe_do_inject_code(_pid: u32, _last_scan: &[scan::Region], _process: &Process) -> bool {
    false
}

fn do_change_value(last_scan: Vec<scan::Region>, process: Process) {
    let scan = ui::prompt::<Scan<Box<dyn Scannable>>>("Enter new memory value: ");
    let new_value = match &scan {
        Ok(Scan::Exact(value)) => value.mem_view(),
        _ => panic!("can only write exact values"),
    };
    last_scan.into_iter().for_each(|region| {
        region.locations.iter().for_each(|addr| {
            match process.write_memory(addr, new_value) {
                Ok(n) => eprintln!("Written {} bytes to [{:x}]", n, addr),
                Err(e) => eprintln!("Failed to write to [{:x}]: {}", addr, e),
            };
        })
    });
}
