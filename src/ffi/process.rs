use super::Module;

use std::io;
use std::mem::{self, MaybeUninit};
use std::ptr::{self, NonNull};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE};
use winapi::um::winnt;

/// How many ASCII characters to read for a process name at most.
const MAX_PROC_NAME_LEN: usize = 64;

/// A handle to an opened process.
#[derive(Debug)]
pub struct Process {
    pub(crate) pid: u32,
    pub(crate) handle: NonNull<c_void>,
}

/// Enumerate up to `n` Process IDentifiers (PIDs) of all programs currently running.
pub fn list_processes(n: usize) -> io::Result<Vec<u32>> {
    let mut size = 0;
    let mut pids = Vec::<DWORD>::with_capacity(n);
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
    /// Open a process handle given its Process IDentifier (PID).
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

    /// Return the Process IDentifier.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Return the first module loaded by this process.
    pub fn base_module(&self) -> io::Result<Module<'_>> {
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
        Ok(Module {
            process: self,
            module,
        })
    }

    /// Enumerate all modules currently loaded by this process.
    pub fn list_modules(&self) -> io::Result<Vec<Module<'_>>> {
        let mut size = 0;
        // SAFETY: the pointer is valid and the indicated size is 0.
        if unsafe {
            winapi::um::psapi::EnumProcessModules(
                self.handle.as_ptr(),
                ptr::null_mut(),
                0,
                &mut size,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }

        let mut modules = Vec::with_capacity(size as usize / mem::size_of::<HMODULE>());
        // SAFETY: the pointer is valid and the size is correct.
        if unsafe {
            winapi::um::psapi::EnumProcessModules(
                self.handle.as_ptr(),
                modules.as_mut_ptr(),
                (modules.capacity() * mem::size_of::<HMODULE>()) as u32,
                &mut size,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the call succeeded, so modules up to `size` are initialized.
        unsafe {
            modules.set_len(size as usize / mem::size_of::<HMODULE>());
        }

        Ok(modules
            .into_iter()
            .map(|module| Module {
                process: self,
                module,
            })
            .collect())
    }

    /// Begin debugging this process.
    ///
    /// This is equivalent to using [`crate::debug_process`] with the current PID.
    pub fn begin_debugging(&self) -> io::Result<super::DebugToken> {
        crate::debug_process(self.pid)
    }

    /// Enumerate all thread identifiers where the owning process is this one.
    ///
    /// This is equivalent to using [`crate::iter_threads`] and filtering by the owning PID.
    pub fn list_threads(&self) -> io::Result<Vec<u32>> {
        Ok(crate::iter_threads()?
            .into_iter()
            .flat_map(|entry| match entry.owner_pid {
                Some(pid) if pid == self.pid => Some(entry.tid),
                _ => None,
            })
            .collect())
    }

    /// Fetch the base name of the first module loaded by this process.
    ///
    /// This is equivalent to using [`Self::base_module`] and retrieving its name.
    pub fn name(&self) -> io::Result<String> {
        self.base_module()?.truncated_name(MAX_PROC_NAME_LEN)
    }

    /// Return a iterator over all the memory regions along with the access of the process.
    ///
    /// When a [`crate::ffi::Region::addr`] is equal to a [`crate::ffi::Module::addr`], you can
    /// consider every address within that page "stable" (i.e. it will always be the same,
    /// regardless of any dynamic allocation the process may perform).
    pub fn iter_memory_regions(&self) -> super::region::Iter<'_> {
        super::region::Iter {
            process: self,
            base: 0,
        }
    }

    /// Read the process' memory at the given address `addr` and copy it into the local buffer
    /// `buffer`. The address belongs to the address space of the process, not an address of the
    /// current process.
    ///
    /// The amount of bytes copied is returned, which may be less than `buffer.len()`.
    pub fn read_memory(&self, addr: usize, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;

        // SAFETY: the buffer points to valid memory, and the buffer size is correctly set.
        if unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                self.handle.as_ptr(),
                addr as *const _,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut read,
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }

    /// Like [`Self::read_memory`] but retries until the buffer is filled.
    pub fn read_memory_exact(&self, mut addr: usize, mut buffer: &mut [u8]) -> io::Result<()> {
        while !buffer.is_empty() {
            let read = self.read_memory(addr, buffer)?;
            buffer = &mut buffer[read..];
            addr += read;
        }
        Ok(())
    }

    /// Copy memory from the local buffer into the process' memory at the given address `addr`.
    ///
    /// The amount of bytes written is returned, which may be less than `buffer.len()`.
    pub fn write_memory(&self, addr: usize, buffer: &[u8]) -> io::Result<usize> {
        let mut written = 0;

        // SAFETY: the input value buffer points to valid memory.
        if unsafe {
            winapi::um::memoryapi::WriteProcessMemory(
                self.handle.as_ptr(),
                addr as *mut _,
                buffer.as_ptr().cast(),
                buffer.len(),
                &mut written,
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(written)
        }
    }

    /// Like [`Self::write_memory`] but retries until the entire buffer is written.
    pub fn write_memory_all(&self, mut addr: usize, mut buffer: &[u8]) -> io::Result<()> {
        while !buffer.is_empty() {
            let written = self.write_memory(addr, buffer)?;
            buffer = &buffer[written..];
            addr += written;
        }
        Ok(())
    }

    /*
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

    /// Flushes the instruction cache.
    ///
    /// Should be called when writing to memory regions that contain code.
    pub fn flush_instruction_cache(&self) -> io::Result<()> {
        // SAFETY: the call doesn't have dangerous side-effects.
        if unsafe {
            winapi::um::processthreadsapi::FlushInstructionCache(
                self.handle.as_ptr(),
                ptr::null(),
                0,
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Parse the instructions in the memory region containing the given address.
    ///
    /// Fails if the address is not within any valid region, the region can't be read, the region
    /// cannot be decoded, or the patch cannot be applied.
    #[cfg(feature = "patch-nops")]
    pub fn nop_last_instruction(&self, addr: usize) -> io::Result<()> {
        use iced_x86::{Decoder, DecoderOptions, Instruction};

        let region = self
            .memory_regions()
            .into_iter()
            .find(|region| {
                let base = region.BaseAddress as usize;
                base <= addr && addr < base + region.RegionSize
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no matching region found"))?;

        let bytes = self.read_memory(region.BaseAddress as usize, region.RegionSize)?;

        let mut decoder = Decoder::new(64, &bytes, DecoderOptions::NONE);
        decoder.set_ip(region.BaseAddress as _);

        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.next_ip() as usize == addr {
                return self
                    .write_memory(instruction.ip() as usize, &vec![0x90; instruction.len()])
                    .map(drop);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "no matching instruction found",
        ))
    }
    */

    /// Allocate `size` bytes in the process' memory, as close as possible to `addr`.
    ///
    /// The newly-allocated memory is initialized to zero.
    ///
    /// If `size` crosses page boundaries, more than one page will be allocated.
    pub fn alloc(&self, addr: usize, size: usize) -> io::Result<usize> {
        // SAFETY valid handle, no nasty side-effects.
        let res = unsafe {
            winapi::um::memoryapi::VirtualAllocEx(
                self.handle.as_ptr(),
                addr as _,
                size,
                winnt::MEM_COMMIT | winnt::MEM_RESERVE,
                winnt::PAGE_EXECUTE_READWRITE,
            )
        };
        if res == ptr::null_mut() {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as _)
        }
    }

    /// Free previously-allocated memory.
    pub fn dealloc(&self, addr: usize) -> io::Result<()> {
        // SAFETY valid handle, no nasty side-effects.
        if unsafe {
            winapi::um::memoryapi::VirtualFreeEx(
                self.handle.as_ptr(),
                addr as _,
                0,
                winnt::MEM_RELEASE,
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and non-null.
        let ret = unsafe { winapi::um::handleapi::CloseHandle(self.handle.as_mut()) };
        assert_ne!(ret, FALSE);
    }
}
