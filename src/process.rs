use crate::scan::{Region, Scan, Scannable};
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

    pub fn scan_regions<T: Scannable>(
        &self,
        regions: &[MEMORY_BASIC_INFORMATION],
        scan: Scan<T>,
    ) -> Vec<Region> {
        regions
            .iter()
            .flat_map(
                |region| match self.read_memory(region.BaseAddress as _, region.RegionSize) {
                    Ok(memory) => Some(scan.run(region.clone(), memory)),
                    Err(err) => {
                        eprintln!(
                            "Failed to read {} bytes at {:?}: {}",
                            region.RegionSize, region.BaseAddress, err,
                        );
                        None
                    }
                },
            )
            .collect()
    }

    pub fn rescan_regions<T: Scannable>(&self, regions: &[Region], scan: Scan<T>) -> Vec<Region> {
        regions
            .iter()
            .flat_map(|region| {
                match self.read_memory(region.info.BaseAddress as _, region.info.RegionSize) {
                    Ok(memory) => Some(scan.rerun(region, memory)),
                    Err(err) => {
                        eprintln!(
                            "Failed to read {} bytes at {:?}: {}",
                            region.info.RegionSize, region.info.BaseAddress, err,
                        );
                        None
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

pub struct DebugToken {
    pid: u32,
}

/// Attach the current process (the debugger) to the process with the corresponding identifier
/// (the debuggee).
pub fn debug(pid: u32) -> io::Result<DebugToken> {
    // SAFETY: the call doesn't have dangerous side-effects.
    if unsafe { winapi::um::debugapi::DebugActiveProcess(pid) } == FALSE {
        return Err(io::Error::last_os_error());
    };
    let token = DebugToken { pid };

    // Avoid killing the debuggee if the debugger dies.
    if unsafe { winapi::um::winbase::DebugSetProcessKillOnExit(FALSE) } == FALSE {
        return Err(io::Error::last_os_error());
    };

    Ok(token)
}

impl Drop for DebugToken {
    fn drop(&mut self) {
        // SAFETY: the token is only created if debugging succeeded.
        let ret = unsafe { winapi::um::debugapi::DebugActiveProcessStop(self.pid) };
        assert_ne!(ret, FALSE);
    }
}
