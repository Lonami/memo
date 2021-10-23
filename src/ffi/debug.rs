use std::convert::TryInto;
use std::io;
use std::mem::MaybeUninit;
use std::time::Duration;
use winapi::shared::minwindef::FALSE;

/// Proof that the current process is currently debugging another process.
///
/// When dropped, the current process stops being a debugger of the debuggee.
pub struct DebugToken {
    pid: u32,
}

/// Attach the current process (the debugger) to the process with the corresponding Process
/// IDentifier (the PID of the debuggee).
pub fn debug_process(pid: u32) -> io::Result<DebugToken> {
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

impl DebugToken {
    /// Return the Process IDentifier of the debuggee represented by this token.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for a debugging event to occur within the specified duration.
    ///
    /// The debuggee is paused until execution is resumed through [`Self::cont`].
    ///
    /// The raw debug event structure is returned.
    pub fn wait_event_raw(
        &self,
        timeout: Option<Duration>,
    ) -> io::Result<winapi::um::minwinbase::DEBUG_EVENT> {
        let mut result = MaybeUninit::uninit();
        let timeout = timeout
            .map(|d| d.as_millis().try_into().ok())
            .flatten()
            .unwrap_or(winapi::um::winbase::INFINITE);

        // SAFETY: can only wait for events with a token, so the debugger is active.
        if unsafe { winapi::um::debugapi::WaitForDebugEvent(result.as_mut_ptr(), timeout) } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: the call returned non-zero, so the structure is initialized.
            Ok(unsafe { result.assume_init() })
        }
    }

    /// Continue the execution of the debuggee.
    ///
    /// The value of `handled` should be `true` when the exception was appropriately handled,
    /// or `false` for the exception to be dispatched to a different handler.
    pub fn cont(
        &self,
        event: winapi::um::minwinbase::DEBUG_EVENT,
        handled: bool,
    ) -> io::Result<()> {
        // SAFETY: the call doesn't have dangerous side-effects.
        if unsafe {
            winapi::um::debugapi::ContinueDebugEvent(
                event.dwProcessId,
                event.dwThreadId,
                if handled {
                    winapi::um::winnt::DBG_CONTINUE
                } else {
                    winapi::um::winnt::DBG_EXCEPTION_NOT_HANDLED
                },
            )
        } == FALSE
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for DebugToken {
    fn drop(&mut self) {
        // SAFETY: the token is only created if debugging succeeded.
        let ret = unsafe { winapi::um::debugapi::DebugActiveProcessStop(self.pid) };
        assert_ne!(ret, FALSE);
    }
}
