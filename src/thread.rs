use std::io;
use std::mem::{self, MaybeUninit};
use std::ptr::NonNull;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, FALSE};

/// A handle to an opened thread.
#[derive(Debug)]
pub struct Thread {
    tid: u32,
    handle: NonNull<c_void>,
}

#[must_use]
pub struct Watchpoint<'a> {
    thread: &'a Thread,
}

#[derive(Debug)]
pub struct Toolhelp {
    handle: winapi::um::winnt::HANDLE,
}

impl Drop for Toolhelp {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and not invalid
        let ret = unsafe { winapi::um::handleapi::CloseHandle(self.handle) };
        assert_ne!(ret, FALSE);
    }
}

/// Enumerate the thread identifiers owned by the specified process.
pub fn enum_threads(pid: u32) -> io::Result<Vec<u32>> {
    const ENTRY_SIZE: u32 = mem::size_of::<winapi::um::tlhelp32::THREADENTRY32>() as u32;

    // size_of(dwSize + cntUsage + th32ThreadID + th32OwnerProcessID)
    const NEEDED_ENTRY_SIZE: u32 = 4 * mem::size_of::<DWORD>() as u32;

    // SAFETY: it is always safe to attempt to call this function.
    let handle = unsafe {
        winapi::um::tlhelp32::CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPTHREAD, 0)
    };
    if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let toolhelp = Toolhelp { handle };

    let mut result = Vec::new();
    let mut entry = winapi::um::tlhelp32::THREADENTRY32 {
        dwSize: ENTRY_SIZE,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    // SAFETY: we have a valid handle, and point to memory we own with the right size.
    if unsafe { winapi::um::tlhelp32::Thread32First(toolhelp.handle, &mut entry) } != FALSE {
        loop {
            if entry.dwSize >= NEEDED_ENTRY_SIZE && entry.th32OwnerProcessID == pid {
                result.push(entry.th32ThreadID);
            }

            entry.dwSize = ENTRY_SIZE;
            // SAFETY: we have a valid handle, and point to memory we own with the right size.
            if unsafe { winapi::um::tlhelp32::Thread32Next(toolhelp.handle, &mut entry) } == FALSE {
                break;
            }
        }
    }

    Ok(result)
}

impl Thread {
    /// Open a thread handle given its thread identifier.
    pub fn open(tid: u32) -> io::Result<Self> {
        // SAFETY: the call doesn't have dangerous side-effects
        NonNull::new(unsafe {
            winapi::um::processthreadsapi::OpenThread(
                winapi::um::winnt::THREAD_SUSPEND_RESUME
                    | winapi::um::winnt::THREAD_GET_CONTEXT
                    | winapi::um::winnt::THREAD_SET_CONTEXT
                    | winapi::um::winnt::THREAD_QUERY_INFORMATION,
                FALSE,
                tid,
            )
        })
        .map(|handle| Self { tid, handle })
        .ok_or_else(io::Error::last_os_error)
    }

    /// Return the thread identifier.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Suspend the execution of this thread until it's resumed later.
    ///
    /// Returns the previous suspend count.
    pub fn suspend(&mut self) -> io::Result<usize> {
        // SAFETY: the handle is valid.
        let ret = unsafe { winapi::um::processthreadsapi::SuspendThread(self.handle.as_ptr()) };
        if ret == -1i32 as u32 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Resumes the execution of this thread after it was suspended.
    pub fn resume(&mut self) -> io::Result<usize> {
        // SAFETY: the handle is valid.
        let ret = unsafe { winapi::um::processthreadsapi::ResumeThread(self.handle.as_ptr()) };
        if ret == -1i32 as u32 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Get the current thread context.
    ///
    /// The thread should be suspended before calling this function, or it will fail.
    pub fn get_context(&self) -> io::Result<winapi::um::winnt::CONTEXT> {
        let context = MaybeUninit::<winapi::um::winnt::CONTEXT>::zeroed();
        // SAFETY: it's a C struct, and all-zero is a valid bit-pattern for the type.
        let mut context = unsafe { context.assume_init() };
        context.ContextFlags = winapi::um::winnt::CONTEXT_ALL;

        // SAFETY: the handle is valid and structure points to valid memory.
        if unsafe {
            winapi::um::processthreadsapi::GetThreadContext(self.handle.as_ptr(), &mut context)
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(context)
        }
    }

    /// Set the current thread context.
    ///
    /// The thread should be suspended before calling this function, or it will fail.
    pub fn set_context(&self, context: &winapi::um::winnt::CONTEXT) -> io::Result<()> {
        // SAFETY: the handle is valid and structure points to valid memory.
        if unsafe { winapi::um::processthreadsapi::SetThreadContext(self.handle.as_ptr(), context) }
            == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Watch the memory at the given address for changes.
    ///
    /// Note that if there is no debugger attached, the exception will likely crash the thread,
    /// so it is recommended to debug the corresponding process before using this method.
    ///
    /// The watchpoint will be reset on drop, so the result must be used.
    pub fn watch_memory_write<'a>(&'a self, addr: usize) -> io::Result<Watchpoint<'a>> {
        let mut context = self.get_context()?;
        context.Dr0 = addr as u64;
        context.Dr7 = 0x00000000000d0001;
        self.set_context(&context)?;
        Ok(Watchpoint { thread: self })
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and non-null
        let ret = unsafe { winapi::um::handleapi::CloseHandle(self.handle.as_mut()) };
        assert_ne!(ret, FALSE);
    }
}

impl<'a> Drop for Watchpoint<'a> {
    fn drop(&mut self) {
        match self.thread.get_context() {
            Ok(mut context) => {
                context.Dr0 = 0;
                context.Dr7 = 0;
                if let Err(e) = self.thread.set_context(&context) {
                    eprintln!("failed to reset debug register on watchpoint drop: {}", e);
                }
            }
            Err(e) => {
                eprintln!("failed to reset debug register on watchpoint drop: {}", e);
            }
        }
    }
}
