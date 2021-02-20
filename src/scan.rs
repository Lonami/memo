use std::ops::Range;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

/// A scan type.
///
/// The variant determines how a memory scan should be performed.
pub enum Scan {
    /// Perform an exact memory scan.
    /// Only memory locations containing this exact value will be considered.
    Exact(i32),
    /// The value is unknown.
    /// Every memory location is considered valid. This only makes sense for a first scan.
    Unknown,
    /// The value has decreased by some unknown amount since the last scan.
    /// This only makes sense for subsequent scans.
    Decreased,
}

/// Candidate memory locations for holding our desired value.
#[derive(Clone)]
pub enum CandidateLocations {
    /// Multiple, separated locations.
    Discrete { locations: Vec<usize> },
    ///
    Dense { range: Range<usize> },
}

/// A value found in memory.
#[derive(Clone)]
pub enum Value {
    /// All the values exactly matched this at the time of the scan.
    Exact(i32),
    /// The value is not known, so anything represented within this chunk must be considered.
    AnyWithin(Vec<u8>),
}

/// A memory region.
#[derive(Clone)]
pub struct Region {
    /// The raw information about this memory region.
    pub info: MEMORY_BASIC_INFORMATION,
    /// Candidate locations that should be considered during subsequent scans.
    pub locations: CandidateLocations,
    /// The value (or value range) to compare against during subsequent scans.
    pub value: Value,
}

impl Scan {
    /// Run the scan over the memory corresponding to the given region information.
    ///
    /// Returns a scanned region with all the results found.
    pub fn run(&self, info: MEMORY_BASIC_INFORMATION, memory: Vec<u8>) -> Region {
        let base = info.BaseAddress as usize;
        match self {
            Scan::Exact(n) => {
                let target = n.to_ne_bytes();
                let locations = memory
                    .windows(target.len())
                    .enumerate()
                    .step_by(4)
                    .flat_map(|(offset, window)| {
                        if window == target {
                            Some(base + offset)
                        } else {
                            None
                        }
                    })
                    .collect();
                Region {
                    info,
                    locations: CandidateLocations::Discrete { locations },
                    value: Value::Exact(*n),
                }
            }
            // For scans that make no sense on a first run, treat them as unknown.
            Scan::Unknown | Scan::Decreased => Region {
                info,
                locations: CandidateLocations::Dense {
                    range: base..base + info.RegionSize,
                },
                value: Value::AnyWithin(memory),
            },
        }
    }

    /// Re-run the scan over a previously-scanned memory region.
    ///
    /// Returns the new scanned region with all the results found.
    pub fn rerun(&self, region: &Region, memory: Vec<u8>) -> Region {
        match self {
            // Exact scan does not care about any previous value.
            Scan::Exact(_) => self.run(region.info.clone(), memory),
            // Unknown scan won't narrow down the region at all.
            Scan::Unknown => region.clone(),
            Scan::Decreased => Region {
                info: region.info.clone(),
                locations: CandidateLocations::Discrete {
                    locations: region
                        .iter_locations(&memory)
                        .flat_map(|(addr, old, new)| if new < old { Some(addr) } else { None })
                        .collect(),
                },
                value: Value::AnyWithin(memory),
            },
        }
    }
}

impl CandidateLocations {
    /// Return the amount of candidate locations.
    pub fn len(&self) -> usize {
        match self {
            CandidateLocations::Discrete { locations } => locations.len(),
            CandidateLocations::Dense { range } => range.len(),
        }
    }
}

impl Region {
    /// Return the value stored at `addr`.
    fn value_at(&self, addr: usize) -> i32 {
        match &self.value {
            Value::AnyWithin(chunk) => {
                let base = addr - self.info.BaseAddress as usize;
                let bytes = &chunk[base..base + 4];
                i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
            _ => todo!(),
        }
    }

    /// Iterate over `(address, old value, new value)`.
    fn iter_locations<'a>(
        &'a self,
        new_memory: &'a [u8],
    ) -> impl Iterator<Item = (usize, i32, i32)> + 'a {
        match &self.locations {
            CandidateLocations::Dense { range } => range.clone().step_by(4).map(move |addr| {
                let old = self.value_at(addr);
                let base = addr - self.info.BaseAddress as usize;
                let bytes = &new_memory[base..base + 4];
                let new = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                (addr, old, new)
            }),
            _ => todo!(),
        }
    }
}
