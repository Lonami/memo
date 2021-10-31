use std::mem::{self, MaybeUninit};
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

/// A memory region obtained from a [`crate::Process`].
///
/// Contains information about a certain page range.
#[derive(Clone)]
pub struct Region(pub(crate) MEMORY_BASIC_INFORMATION);

pub struct Iter<'p> {
    pub(crate) process: &'p crate::Process,
    pub(crate) base: usize,
}

impl<'p> Iterator for Iter<'p> {
    type Item = Region;

    fn next(&mut self) -> Option<Self::Item> {
        let mut info = MaybeUninit::uninit();

        // SAFETY: the info structure points to valid memory.
        let written = unsafe {
            winapi::um::memoryapi::VirtualQueryEx(
                self.process.handle.as_ptr(),
                self.base as *const _,
                info.as_mut_ptr(),
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            None
        } else {
            // SAFETY: a non-zero amount was written to the structure
            let info = unsafe { info.assume_init() };
            self.base = info.BaseAddress as usize + info.RegionSize;
            Some(Region(info))
        }
    }
}

impl Region {
    /// Return the base address of this region (i.e. where it starts in memory).
    pub fn addr(&self) -> usize {
        self.0.BaseAddress as usize
    }

    /// Return the size of this region (i.e. how many bytes does it occupy in memory).
    pub fn size(&self) -> usize {
        self.0.RegionSize
    }

    /// Return the access protection of the pages in this region.
    pub fn protection(&self) -> u32 {
        self.0.Protect
    }
}
