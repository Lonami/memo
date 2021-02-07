use std::io;
use std::mem;
use std::ptr::NonNull;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, FALSE};

#[derive(Debug)]
pub struct Process {
    pid: u32,
    handle: NonNull<c_void>,
}

pub fn enum_proc() -> io::Result<Vec<u32>> {
    let mut size = 0;
    let mut pids = Vec::<DWORD>::with_capacity(1024);
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
    pub fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: the call doesn't have dangerous side-effects
        NonNull::new(unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::PROCESS_QUERY_INFORMATION,
                FALSE,
                pid,
            )
        })
        .map(|handle| Self { pid, handle })
        .ok_or_else(io::Error::last_os_error)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and non-null
        let ret = unsafe { winapi::um::handleapi::CloseHandle(self.handle.as_mut()) };
        assert_ne!(ret, FALSE);
    }
}

fn main() {
    let mut success = 0;
    let mut failed = 0;
    enum_proc()
        .unwrap()
        .into_iter()
        .for_each(|pid| match Process::open(pid) {
            Ok(_) => success += 1,
            Err(_) => failed += 1,
        });

    eprintln!(
        "Successfully opened {}/{} processes",
        success,
        success + failed
    );
}
