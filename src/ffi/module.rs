use std::io;
use winapi::shared::minwindef::HMODULE;

/// A handle to a [`crate::Process`]' module.
#[derive(Debug)]
pub struct Module<'p> {
    pub(crate) process: &'p crate::Process,
    pub(crate) module: HMODULE,
}

impl<'p> Module<'p> {
    /// Return the module name, truncated to `n` bytes, excluding the NULL byte.
    pub fn truncated_name(&self, n: usize) -> io::Result<String> {
        let mut buffer = Vec::<u8>::with_capacity(n + 1);
        // SAFETY: the handle, module and buffer are all valid.
        let length = unsafe {
            winapi::um::psapi::GetModuleBaseNameA(
                self.process.handle.as_ptr(),
                self.module,
                buffer.as_mut_ptr().cast(),
                buffer.capacity() as u32,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the call succeeded and length represents bytes.
        unsafe { buffer.set_len(length as usize - 1) };
        Ok(String::from_utf8(buffer).unwrap())
    }

    /// Return the memory address where this module has been loaded into memory.
    pub fn addr(&self) -> usize {
        self.module as usize
    }
}
