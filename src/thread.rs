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
