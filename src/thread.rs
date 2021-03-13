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

/// Breakpoint condition.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum Condition {
    /// Break when attempting to execute at the specified address.
    Execute = 0b00,
    /// Break when attempting to write to the specified address.
    Write = 0b01,
    /// Break when attempting to read from or write to the specified address.
    Access = 0b11,
}

/// Breakpoint size.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Size {
    /// Watch a single byte in memory.
    Byte = 0b00,
    /// Watch two consecutive bytes in memory.
    Word = 0b01,
    /// Watch four consecutive bytes in memory.
    DoubleWord = 0b11,
    /// Watch eight consecutive bytes in memory.
    QuadWord = 0b10,
}

#[derive(Debug, PartialEq, Eq)]
enum DebugRegister {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

#[must_use]
pub struct Breakpoint<'a> {
    thread: &'a Thread,
    clear_mask: u64,
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

    /// Add a breakpoint at the given address.
    ///
    /// The condition determines when the breakpoint will trigger, and the size how much memory
    /// should be watched.
    ///
    /// Note that if there is no debugger attached, the exception will likely crash the thread,
    /// so it is recommended to debug the corresponding process before using this method.
    ///
    /// The breakpoint will be reset on drop, so the result must be used.
    pub fn add_breakpoint<'a>(
        &'a self,
        addr: usize,
        cond: Condition,
        size: Size,
    ) -> io::Result<Breakpoint<'a>> {
        let mut context = self.get_context()?;
        let (clear_mask, dr, dr7) = Breakpoint::update_dbg_control(context.Dr7, cond, size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no debug register available"))?;

        let addr = addr as u64;
        match dr {
            DebugRegister::Dr0 => context.Dr0 = addr,
            DebugRegister::Dr1 => context.Dr1 = addr,
            DebugRegister::Dr2 => context.Dr2 = addr,
            DebugRegister::Dr3 => context.Dr3 = addr,
        }
        context.Dr7 = dr7;

        self.set_context(&context)?;
        Ok(Breakpoint {
            thread: self,
            clear_mask,
        })
    }
}

impl<'a> Breakpoint<'a> {
    // Update DR7 to add a new breakpoint with the given parameters, or return `None` on failure.
    fn update_dbg_control(
        mut dr7: u64,
        cond: Condition,
        size: Size,
    ) -> Option<(u64, DebugRegister, u64)> {
        let index = (0..4).find_map(|i| ((dr7 & (0b11 << (i * 2))) == 0).then(|| i))?;

        let dr = match index {
            0 => DebugRegister::Dr0,
            1 => DebugRegister::Dr1,
            2 => DebugRegister::Dr2,
            3 => DebugRegister::Dr3,
            _ => unreachable!(),
        };

        // Prepare clear mask (to clear on drop) and to make sure there's no garbage left in the
        // condition or size bits.
        let clear_mask = !((0b1111 << (16 + index * 4)) | (0b11 << (index * 2)));
        dr7 &= clear_mask;

        // Enable corresponding local breakpoint (diagram represents 1 byte per cell).
        // DR7 = [ .. | G3 | L3 | G2 | L2 | G1 | L1 | G0 | L0 ]
        dr7 |= 1 << (index * 2);

        // Toggle the correct bits on conditon and size (diagram represents 2 bytes per cell).
        // DR7 = [ .. | S3 |  C3 | S2 | C2 | S1 | C1 | S0 | C0 | .. ]
        let sc = (((size as u8) << 2) | (cond as u8)) as u64;
        dr7 |= sc << (16 + index * 4);

        Some((clear_mask, dr, dr7))
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // SAFETY: the handle is valid and non-null
        let ret = unsafe { winapi::um::handleapi::CloseHandle(self.handle.as_mut()) };
        assert_ne!(ret, FALSE);
    }
}

impl<'a> Drop for Breakpoint<'a> {
    fn drop(&mut self) {
        let did_suspend = self.thread.suspend().is_ok();
        match self.thread.get_context() {
            Ok(mut context) => {
                context.Dr7 &= self.clear_mask;
                if let Err(e) = self.thread.set_context(&context) {
                    eprintln!("failed to reset debug register on watchpoint drop: {}", e);
                }
            }
            Err(e) => {
                eprintln!("failed to reset debug register on watchpoint drop: {}", e);
            }
        }
        if did_suspend {
            drop(self.thread.resume());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brk_add_one() {
        // DR7 starts with garbage which should be respected.
        let (clear_mask, dr, dr7) =
            Breakpoint::update_dbg_control(0x1700, Condition::Write, Size::DoubleWord).unwrap();

        assert_eq!(clear_mask, 0xffff_ffff_fff0_fffc);
        assert_eq!(dr, DebugRegister::Dr0);
        assert_eq!(dr7, 0x0000_0000_000d_1701);
    }

    #[test]
    fn brk_add_two() {
        let (clear_mask, dr, dr7) = Breakpoint::update_dbg_control(
            0x0000_0000_000d_0001,
            Condition::Write,
            Size::DoubleWord,
        )
        .unwrap();

        assert_eq!(clear_mask, 0xffff_ffff_ff0f_fff3);
        assert_eq!(dr, DebugRegister::Dr1);
        assert_eq!(dr7, 0x0000_0000_00dd_0005);
    }

    #[test]
    fn brk_try_add_when_max() {
        assert!(Breakpoint::update_dbg_control(
            0x0000_0000_dddd_0055,
            Condition::Write,
            Size::DoubleWord
        )
        .is_none());
    }
}
