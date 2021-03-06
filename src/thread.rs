use std::io;
use std::mem::{self};
use std::ptr::NonNull;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, FALSE};

/// A handle to an opened thread.
#[derive(Debug)]
pub struct Thread {
    tid: u32,
    handle: NonNull<c_void>,
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
                winapi::um::winnt::THREAD_SUSPEND_RESUME,
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
}

impl Drop for Thread {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and non-null
        let ret = unsafe { winapi::um::handleapi::CloseHandle(self.handle.as_mut()) };
        assert_ne!(ret, FALSE);
    }
}
