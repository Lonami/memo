mod step1;
mod step2;
mod step3;
pub mod ui;

use std::fmt;
use winapi::um::winnt;

/// How many process identifiers will be enumerated at most.
const MAX_PIDS: usize = 1024;

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
            let processes = memo::list_processes(MAX_PIDS)
                .unwrap()
                .into_iter()
                .flat_map(memo::Process::open)
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

    let process = memo::Process::open(pid).unwrap();
    println!("Opened process {:?}", process);

    let mask = winnt::PAGE_EXECUTE_READWRITE
        | winnt::PAGE_EXECUTE_WRITECOPY
        | winnt::PAGE_READWRITE
        | winnt::PAGE_WRITECOPY;

    let regions = process
        .iter_memory_regions()
        .filter(|p| {
            let mut buf = [0];
            (p.protection() & mask) != 0 && process.read_memory(p.addr(), &mut buf).is_ok()
        })
        .collect::<Vec<_>>();

    println!("Found {} memory regions to scan", regions.len());

    match ui::prompt::<u8>("Which tutorial step to run?: ").unwrap() {
        1 => step1::solve(process, regions),
        2 => step2::solve(process, regions),
        3 => step3::solve(process, regions),
        n => println!("Don't know how to solve {} just yet!", n),
    }
}

/*
fn repl_find_value(
    regions: &[winnt::MEMORY_BASIC_INFORMATION],
    process: &Process,
) -> Vec<scan::Region> {
    let scan = ui::prompt_scan().unwrap();
    let mut last_scan = process.scan_regions(regions, scan);
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

    last_scan
}

fn maybe_do_find_ptr_path(
    last_scan: &[scan::Region],
    regions: &[winnt::MEMORY_BASIC_INFORMATION],
    process: &Process,
) -> bool {
    let action = ui::prompt::<String>(
        "Do you want to perform a second scan of the same value to find a stable pointer path to it?: ",
    )
    .unwrap();

    if action != "y" && action != "Y" {
        return false;
    }

    let first_addr = last_scan
        .iter()
        .flat_map(|r| r.locations.iter())
        .next()
        .unwrap();
    let mut first_snap = snapshot::Snapshot::new(&process, &regions);

    println!("Make the address change (for example, log out and back in again).");
    println!("After that, make sure to find the same value you were looking for before.");

    let last_scan = repl_find_value(regions, process);

    let second_addr = last_scan
        .iter()
        .flat_map(|r| r.locations.iter())
        .next()
        .unwrap();
    let mut second_snap = snapshot::Snapshot::new(&process, &regions);

    println!("Process snapshots taken before and after the memory locations changed.");
    println!("Now looking for pointer paths were the offsets match exactly in both.");
    snapshot::prepare_optimized_scan(&mut first_snap);
    snapshot::prepare_optimized_scan(&mut second_snap);
    let offsets = snapshot::find_pointer_paths(
        first_snap.clone(),
        first_addr,
        second_snap.clone(),
        second_addr,
    );

    println!("Here are the offsets I found:");
    let base = process.base_memory_regions().unwrap()[0].BaseAddress as usize;
    let name = process.name().unwrap();
    offsets.iter().enumerate().for_each(|(i, offset_list)| {
        print!("{}. ", i);
        for _offset in offset_list.iter() {
            print!("[");
        }
        let mut first = true;
        for offset in offset_list.iter() {
            if first {
                print!("\"{}\"+{:X}]", name, offset - base);
                first = false;
            } else {
                print!(" + {:X}]", offset);
            }
        }
        println!();
    });

    let index = ui::prompt::<usize>("Which one should I use?: ").unwrap();
    let offset_list = &offsets[index];

    let scan = ui::prompt::<Scan<Box<dyn Scannable>>>("Enter new memory value: ");
    let new_value = match &scan {
        Ok(Scan::Exact(value)) => value.mem_view(),
        _ => panic!("can only write exact values"),
    };

    let addr = offset_list
        .iter()
        .take(offset_list.len() - 1)
        .fold(0, |base, offset| {
            usize::from_ne_bytes(
                process
                    .read_memory(base + offset, 8)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        })
        + offset_list.last().unwrap();

    match process.write_memory(addr, new_value) {
        Ok(n) => eprintln!("Written {} bytes to [{:x}]", n, addr),
        Err(e) => eprintln!("Failed to write to [{:x}]: {}", addr, e),
    };

    true
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

                let target_addr = process
                    .alloc(region.BaseAddress as usize + region.RegionSize - 2048, 2048)
                    .unwrap();

                // The relative JMP itself are 5 bytes, the last 2 are NOP (hence the -2 in delta calculation).
                // Relative jumps add to the instruction pointer when it *ends* executing the instruction (like JMP).
                //   jmp target_addr
                //   nop 2
                let mut jmp = [0xE9, 0, 0, 0, 0, 0x66, 0x90];
                jmp[1..5].copy_from_slice(
                    &((target_addr as isize - (addr - 2) as isize) as i32).to_le_bytes(),
                );
                process.write_memory(addr - jmp.len(), &jmp).unwrap();

                // addr is already where the old instruction ended, no need to re-skip our previously written jump.
                // By the end of the execution of this jump, the instruction pointer will be at (base + code len).
                //   add dword ptr [rsi+000007E0], 2
                //   jmp addr
                let mut injection = [0x83, 0x86, 0xE0, 0x07, 0x00, 0x00, 0x02, 0xE9, 0, 0, 0, 0];
                let inj_len = injection.len();
                injection[8..12].copy_from_slice(
                    &((addr as isize - (target_addr + inj_len) as isize) as i32).to_le_bytes(),
                );
                process.write_memory(target_addr, &injection).unwrap();

                println!(
                    "Replaced the SUB 1 at {:x} with ADD 2 at {:x} successfully!",
                    addr, target_addr
                );
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
*/
