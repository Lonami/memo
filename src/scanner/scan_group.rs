use super::{LiveScan, Predicate, Scan};
use crate::ffi::{Process, Region};
use std::io;
use std::mem;

struct LiveRegionScan {
    scan: LiveScan,
    region: Region,
}

/// Behaves like a [`LiveScan`] but over an entire process.
///
/// When re-running the scan, errors that occur from reading the process memory are ignored
/// instead of eagerly returned. The rationale for this is that a region may have been returned
/// to the OS or be no longer accessible, so effectively the value that was once there is no
/// longer there to us.
pub struct LiveProcessScan<'p> {
    process: &'p Process,
    active_regions: Vec<LiveRegionScan>,
}

pub struct CandidateProcessLocations<'s> {
    scan: &'s LiveProcessScan<'s>,
}

impl<F> Scan<F>
where
    F: FnMut(&[u8]) -> bool,
{
    /// Run the scan on the given regions of the process memory.
    pub fn run_on_process<'p, I>(
        &mut self,
        process: &'p Process,
        regions: I,
    ) -> io::Result<LiveProcessScan<'p>>
    where
        I: IntoIterator<Item = Region>,
    {
        let mut active_regions = Vec::new();

        for region in regions {
            let mut buffer = vec![0; region.size()];
            process.read_memory_exact(region.addr(), &mut buffer)?;
            let live_scan = self.run_on(buffer);

            if !live_scan.locations().is_empty() {
                active_regions.push(LiveRegionScan {
                    scan: live_scan,
                    region,
                });
            }
        }

        Ok(LiveProcessScan {
            process,
            active_regions,
        })
    }
}

impl<'p> LiveProcessScan<'p> {
    /// Run [`LiveScan::with_value_size`] over all the memory regions of a given process.
    pub fn with_value_size<I>(size: usize, process: &'p Process, regions: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = Region>,
    {
        let mut active_regions = Vec::new();

        for region in regions {
            let mut buffer = vec![0; region.size()];
            process.read_memory_exact(region.addr(), &mut buffer)?;
            active_regions.push(LiveRegionScan {
                scan: LiveScan::with_value_size(size, buffer),
                region,
            });
        }

        Ok(LiveProcessScan {
            process,
            active_regions,
        })
    }

    /// Run [`LiveScan::keep`] on the currently-stored regions.
    pub fn keep<P: Predicate>(&mut self) {
        // `Vec::retain` does not give a &mut T so we fallback to `filter_map`.
        let active_regions = mem::take(&mut self.active_regions);
        self.active_regions = active_regions
            .into_iter()
            .filter_map(|mut ar| {
                let mut buffer = vec![0; ar.region.size()];
                match self
                    .process
                    .read_memory_exact(ar.region.addr(), &mut buffer)
                {
                    Ok(_) => {
                        ar.scan.keep::<P>(buffer);
                        !ar.scan.locations().is_empty()
                    }
                    Err(_) => false,
                }
                .then(|| ar)
            })
            .collect::<Vec<_>>();
    }

    /// Run [`LiveScan::keep_unchanged`] on the currently-stored regions.
    pub fn keep_unchanged(&mut self) {
        self.keep_with(|a, b| a == b);
    }

    /// Run [`LiveScan::keep_changed`] on the currently-stored regions.
    pub fn keep_changed(&mut self) {
        self.keep_with(|a, b| a != b);
    }

    /// Run [`LiveScan::keep_with`] on the currently-stored regions.
    pub fn keep_with<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        let active_regions = mem::take(&mut self.active_regions);
        self.active_regions = active_regions
            .into_iter()
            .filter_map(|mut ar| {
                // Take &mut predicate (otherwise the closure captures by value).
                let predicate = &mut predicate;
                let mut buffer = vec![0; ar.region.size()];
                match self
                    .process
                    .read_memory_exact(ar.region.addr(), &mut buffer)
                {
                    Ok(_) => {
                        ar.scan.keep_with(predicate, buffer);
                        !ar.scan.locations().is_empty()
                    }
                    Err(_) => false,
                }
                .then(|| ar)
            })
            .collect::<Vec<_>>();
    }

    /// Return a iterator over all the candidate locations.
    pub fn locations(&self) -> CandidateProcessLocations<'_> {
        CandidateProcessLocations { scan: self }
    }
}

impl<'s> CandidateProcessLocations<'s> {
    /// Return the amount of candidate locations.
    pub fn len(&self) -> usize {
        self.scan
            .active_regions
            .iter()
            .map(|ar| ar.scan.locations().len())
            .sum()
    }

    /// Return whether there are no more candidate locations.
    pub fn is_empty(&self) -> bool {
        self.scan
            .active_regions
            .iter()
            .all(|ar| ar.scan.locations().is_empty())
    }

    /// Return a iterator over the locations.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.scan.active_regions.iter().flat_map(|ar| {
            ar.scan
                .locations()
                .iter()
                .map(move |offset| ar.region.addr() + offset)
        })
    }
}
