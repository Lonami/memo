mod scan;
mod ui;

pub use scan::{CandidateLocations, Region, Scan, Value};

use std::fmt;
use std::io;
use std::mem::{self, MaybeUninit};
use std::ptr::NonNull;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE};
use winapi::um::winnt;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

/// How many process identifiers will be enumerated at most.
const MAX_PIDS: usize = 1024;

/// How many ASCII characters to read for a process name at most.
const MAX_PROC_NAME_LEN: usize = 64;

/// Environment variable with the process identifier of the process to work with.
/// If the variable if not set (`set PID=...`), it's asked at runtime.
static PROGRAM_PID: Option<&str> = option_env!("PID");

/// A handle to an opened process.
#[derive(Debug)]
pub struct Process {
    pid: u32,
    handle: NonNull<c_void>,
}

/// Enumerate the process identifiers of all programs currently running.
pub fn enum_proc() -> io::Result<Vec<u32>> {
    let mut size = 0;
    let mut pids = Vec::<DWORD>::with_capacity(MAX_PIDS);
    // SAFETY: the pointer is valid and the size matches the capacity.
    if unsafe {
        winapi::um::psapi::EnumProcesses(
            pids.as_mut_ptr(),
            (pids.capacity() * mem::size_of::<DWORD>()) as u32,
            &mut size,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }

    let count = size as usize / mem::size_of::<DWORD>();
    // SAFETY: the call succeeded and count equals the right amount of items.
    unsafe { pids.set_len(count) };
    Ok(pids)
}

impl Process {
    /// Open a process handle given its process identifier.
    pub fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: the call doesn't have dangerous side-effects
        NonNull::new(unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                winnt::PROCESS_QUERY_INFORMATION
                    | winnt::PROCESS_VM_READ
                    | winnt::PROCESS_VM_WRITE
                    | winnt::PROCESS_VM_OPERATION,
                FALSE,
                pid,
            )
        })
        .map(|handle| Self { pid, handle })
        .ok_or_else(io::Error::last_os_error)
    }

    /// Return the process identifier.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Return the base name of the first module loaded by this process.
    pub fn name(&self) -> io::Result<String> {
        let mut module = MaybeUninit::<HMODULE>::uninit();
        let mut size = 0;
        // SAFETY: the pointer is valid and the size is correct.
        if unsafe {
            winapi::um::psapi::EnumProcessModules(
                self.handle.as_ptr(),
                module.as_mut_ptr(),
                mem::size_of::<HMODULE>() as u32,
                &mut size,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the call succeeded, so module is initialized.
        let module = unsafe { module.assume_init() };

        let mut buffer = Vec::<u8>::with_capacity(MAX_PROC_NAME_LEN);
        // SAFETY: the handle, module and buffer are all valid.
        let length = unsafe {
            winapi::um::psapi::GetModuleBaseNameA(
                self.handle.as_ptr(),
                module,
                buffer.as_mut_ptr().cast(),
                buffer.capacity() as u32,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the call succeeded and length represents bytes.
        unsafe { buffer.set_len(length as usize) };
        Ok(String::from_utf8(buffer).unwrap())
    }

    pub fn memory_regions(&self) -> Vec<MEMORY_BASIC_INFORMATION> {
        let mut base = 0;
        let mut regions = Vec::new();
        let mut info = MaybeUninit::uninit();

        loop {
            // SAFETY: the info structure points to valid memory.
            let written = unsafe {
                winapi::um::memoryapi::VirtualQueryEx(
                    self.handle.as_ptr(),
                    base as *const _,
                    info.as_mut_ptr(),
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                break regions;
            }
            // SAFETY: a non-zero amount was written to the structure
            let info = unsafe { info.assume_init() };
            base = info.BaseAddress as usize + info.RegionSize;
            regions.push(info);
        }
    }

    pub fn read_memory(&self, addr: usize, n: usize) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(n);
        let mut read = 0;

        // SAFETY: the buffer points to valid memory, and the buffer size is correctly set.
        if unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                self.handle.as_ptr(),
                addr as *const _,
                buffer.as_mut_ptr().cast(),
                buffer.capacity(),
                &mut read,
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: the call succeeded and `read` contains the amount of bytes written.
            unsafe { buffer.set_len(read as usize) };
            Ok(buffer)
        }
    }

    pub fn write_memory(&self, addr: usize, value: &[u8]) -> io::Result<usize> {
        let mut written = 0;

        // SAFETY: the input value buffer points to valid memory.
        if unsafe {
            winapi::um::memoryapi::WriteProcessMemory(
                self.handle.as_ptr(),
                addr as *mut _,
                value.as_ptr().cast(),
                value.len(),
                &mut written,
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(written)
        }
    }

    pub fn scan_regions(&self, regions: &[MEMORY_BASIC_INFORMATION], scan: Scan) -> Vec<Region> {
        regions
            .iter()
            .flat_map(|region| match scan {
                Scan::Exact(n) => {
                    let target = n.to_ne_bytes();
                    let mut locations = Vec::new();
                    match self.read_memory(region.BaseAddress as _, region.RegionSize) {
                        Ok(memory) => memory
                            .windows(target.len())
                            .enumerate()
                            .step_by(4)
                            .for_each(|(offset, window)| {
                                if window == target {
                                    locations.push(region.BaseAddress as usize + offset);
                                }
                            }),
                        Err(err) => eprintln!(
                            "Failed to read {} bytes at {:?}: {}",
                            region.RegionSize, region.BaseAddress, err,
                        ),
                    }
                    Some(Region {
                        info: region.clone(),
                        locations: CandidateLocations::Discrete { locations },
                        value: Value::Exact(n),
                    })
                }
                Scan::Unknown => {
                    let base = region.BaseAddress as usize;
                    match self.read_memory(region.BaseAddress as _, region.RegionSize) {
                        Ok(memory) => Some(Region {
                            info: region.clone(),
                            locations: CandidateLocations::Dense {
                                range: base..base + region.RegionSize,
                            },
                            value: Value::AnyWithin(memory),
                        }),
                        Err(err) => {
                            eprintln!(
                                "Failed to read {} bytes at {:?}: {}",
                                region.RegionSize, region.BaseAddress, err,
                            );
                            None
                        }
                    }
                }
            })
            .collect()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and non-null
        let ret = unsafe { winapi::um::handleapi::CloseHandle(self.handle.as_mut()) };
        assert_ne!(ret, FALSE);
    }
}

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
            let processes = enum_proc()
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
    let last_scan = process.scan_regions(&regions, scan);
    println!(
        "Found {} locations",
        last_scan.iter().map(|r| r.locations.len()).sum::<usize>()
    );

    todo!("subsequent scans and rewriting memory");
}
