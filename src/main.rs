mod debug;
mod process;
mod scan;
mod thread;
mod ui;

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

    if !maybe_do_nop_instructions(pid, &last_scan, &process) {
        do_change_value(last_scan, process);
    }
}

#[cfg(feature = "patch-nops")]
fn maybe_do_nop_instructions(pid: u32, last_scan: &[scan::Region], process: &Process) -> bool {
    let action =
        ui::prompt::<String>("Do you want to NOP the writes to those locations (y/n)?: ").unwrap();

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
            threads.iter_mut().for_each(|thread| {
                thread.watch_memory_write(addr).unwrap();
            });
            loop {
                let event = debugger.wait_event(None).unwrap();
                if event.dwDebugEventCode == 1 {
                    let exc = unsafe { event.u.Exception() };
                    if exc.ExceptionRecord.ExceptionCode == 2147483652 {
                        process
                            .nop_last_instruction(exc.ExceptionRecord.ExceptionAddress as usize)
                            .unwrap();

                        debugger.cont(event, true).unwrap();
                        break;
                    }
                }
                debugger.cont(event, true).unwrap();
            }
        })
    });

    true
}

#[cfg(not(feature = "patch-nops"))]
fn maybe_do_nop_instructions(_pid: u32, _last_scan: &[scan::Region], _process: &Process) -> bool {
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
