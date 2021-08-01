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
    let last_scan = repl_find_value(&regions, &process);

    if !maybe_do_find_ptr_path(&last_scan, &regions, &process) {
        if !maybe_do_inject_code(pid, &last_scan, &process) {
            do_change_value(last_scan, process);
        }
    }
}

const MAX_OFFSET: usize = 0x20;

// Returns a vector with the vectors of valid offsets.
fn find_pointer_paths(
    first_snap: Snapshot,
    first_addr: usize,
    second_snap: Snapshot,
    second_addr: usize,
) -> Vec<Vec<usize>> {
    const TOP_DEPTH: u8 = 7;
    let pf = PathFinder {
        first_snap,
        second_snap,
        addresses: std::cell::Cell::new(Vec::new()),
    };
    pf.run(first_addr, second_addr, TOP_DEPTH);

    /*
    The found `pf.addresses` form a tree, for example (values at the bottom come first):

    100


    400
    500             550

    */
    //

    let mut offsets = Vec::new();

    for (base, depth, addr) in pf.addresses.into_inner() {
        if base {
            // Abuse capacity to determine which depths have been filled in.
            offsets.push(Vec::with_capacity((TOP_DEPTH - depth + 1) as usize));
        }

        for offs in offsets.iter_mut() {
            let desired_depth = TOP_DEPTH - (offs.capacity() - offs.len()) as u8 + 1;
            if depth == desired_depth {
                offs.push(addr);
            }
        }
    }

    for offs in offsets.iter_mut() {
        // The top-most address wasn't pushed. Push it now.
        offs.push(second_addr);

        // `slice::windows_mut` isn't a thing, so use a good ol' loop.
        for i in (1..offs.len()).rev() {
            let ptr_value = usize::from_ne_bytes(
                pf.second_snap
                    .read_memory(offs[i - 1], std::mem::size_of::<usize>())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            offs[i] -= ptr_value;
        }
    }

    /*
    base = base addr
    for offset in offsets[..-1] {
        base = [base + offset]
    }
    value = [base + offsets[-1]]
    */

    offsets
}

struct PathFinder {
    first_snap: Snapshot,
    second_snap: Snapshot,
    addresses: std::cell::Cell<Vec<(bool, u8, usize)>>,
}

impl PathFinder {
    fn run(&self, first_addr: usize, second_addr: usize, depth: u8) -> bool {
        // In the second snapshot, look for all pointer values where `ptr_value + offset = second_addr`
        // for all `offset in 0..=MAX_OFFSET`.
        //
        // For every `ptr_value` with a given `offset`, look EXACTLY for `first_addr - offset` in the
        // first snapshot. Once found, we have a candidate offset valid in both snapshots, and then we
        // can recurse to find subsequent offsets on the real addresses of these pointer values.
        //
        // F: first, S: second; RA: Real Address; PV: Pointer Value
        let depth = depth - 1;

        let mut any = false;
        for (sra, spv) in self.second_snap.iter_addr().filter(|(_sra, spv)| {
            if let Some(offset) = second_addr.checked_sub(*spv) {
                offset <= MAX_OFFSET
            } else {
                false
            }
        }) {
            if self.second_snap.is_base_addr(sra) {
                unsafe { &mut *self.addresses.as_ptr() }.push((true, depth + 1, sra));
                any = true;
                continue;
            }
            if depth == 0 {
                continue;
            }
            let offset = second_addr - spv;
            for (fra, _fpv) in self
                .first_snap
                .iter_addr()
                .filter(|(_fra, fpv)| fpv.wrapping_add(offset) == first_addr)
            {
                if self.run(fra, sra, depth) {
                    unsafe { &mut *self.addresses.as_ptr() }.push((false, depth + 1, sra));
                    any = true;
                }
            }
        }

        any
    }
}

use std::convert::TryInto;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

struct Block {
    real_addr: usize,
    mem_offset: usize,
    len: usize,
    base: bool,
}

struct Snapshot {
    memory: Vec<u8>,
    blocks: Vec<Block>,
}

impl Snapshot {
    fn new(process: &Process, regions: &[MEMORY_BASIC_INFORMATION]) -> Self {
        let modules = process.enum_modules().unwrap();
        let mut blocks = regions
            .iter()
            .map(|r| Block {
                real_addr: r.BaseAddress as usize,
                mem_offset: 0,
                len: r.RegionSize,
                base: modules.iter().any(|module| {
                    let base = r.AllocationBase as usize;
                    let addr = *module as usize;
                    base == addr
                }),
            })
            .collect::<Vec<_>>();

        blocks.sort_by_key(|b| b.real_addr);

        let mut memory = Vec::new();
        let blocks = blocks
            .into_iter()
            .filter_map(|b| match process.read_memory(b.real_addr, b.len) {
                Ok(mut chunk) => {
                    let len = chunk.len();
                    let mem_offset = memory.len();
                    memory.append(&mut chunk);
                    Some(Block {
                        real_addr: b.real_addr,
                        mem_offset,
                        len,
                        base: b.base,
                    })
                }
                Err(_) => None,
            })
            .collect();

        Self { memory, blocks }
    }

    pub fn read_memory(&self, addr: usize, n: usize) -> Option<&[u8]> {
        let index = match self.blocks.binary_search_by_key(&addr, |b| b.real_addr) {
            Ok(index) => index,
            Err(index) => index - 1,
        };

        let block = &self.blocks[index];
        let delta = addr - block.real_addr;
        if delta + n > block.len {
            None
        } else {
            let offset = block.mem_offset + delta;
            Some(&self.memory[offset..offset + n])
        }
    }

    pub fn is_base_addr(&self, addr: usize) -> bool {
        let index = match self.blocks.binary_search_by_key(&addr, |b| b.real_addr) {
            Ok(index) => index,
            Err(index) => index - 1,
        };
        self.blocks[index].base
    }

    // Iterate over (memory address, pointer value at said address)
    pub fn iter_addr(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        let mut blocks = self.blocks.iter().peekable();
        self.memory
            .chunks_exact(8)
            .enumerate()
            .map(move |(i, chunk)| {
                let mut block = *blocks.peek().unwrap();
                if i * 8 >= block.mem_offset + block.len {
                    // Roll over to the next block.
                    block = blocks.next().unwrap();
                }

                (
                    block.real_addr + (i * 8 - block.mem_offset),
                    usize::from_ne_bytes(chunk.try_into().unwrap()),
                )
            })
    }
}

fn repl_find_value(regions: &[MEMORY_BASIC_INFORMATION], process: &Process) -> Vec<scan::Region> {
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
    regions: &[MEMORY_BASIC_INFORMATION],
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
    let first_snap = Snapshot::new(&process, &regions);

    println!("Make the address change (for example, log out and back in again).");
    println!("After that, make sure to find the same value you were looking for before.");

    // >>>
    let last_scan = repl_find_value(regions, process);

    let second_addr = last_scan
        .iter()
        .flat_map(|r| r.locations.iter())
        .next()
        .unwrap();
    let second_snap = Snapshot::new(&process, &regions);
    // <<<

    println!("Process snapshots taken before and after the memory locations changed.");
    println!("Now looking for pointer paths were the offsets match exactly in both.");
    let offsets = find_pointer_paths(first_snap, first_addr, second_snap, second_addr);

    println!("Here are the offsets I found:\n{:?}", offsets);

    for offs in offsets {
        let base = offs.iter().take(offs.len() - 1).fold(0, |base, offset| {
            usize::from_ne_bytes(
                process
                    .read_memory(base + offset, 8)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        });

        dbg!(i32::from_ne_bytes(
            process
                .read_memory(base + offs[offs.len() - 1], 4)
                .unwrap()
                .try_into()
                .unwrap()
        ));
    }

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
