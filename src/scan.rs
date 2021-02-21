use std::ops::{Range, RangeInclusive};
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

/// A scan type.
///
/// The variant determines how a memory scan should be performed.
#[derive(Clone, Debug)]
pub enum Scan {
    /// Perform an exact memory scan.
    /// Only memory locations containing this exact value will be considered.
    Exact(i32),
    /// The value is unknown.
    /// Every memory location is considered valid. This only makes sense for a first scan.
    Unknown,
    /// The value is contained within a given range.
    InRange(RangeInclusive<i32>),
    /// The value has not changed since the last scan.
    /// This only makes sense for subsequent scans.
    Unchanged,
    /// The value has changed since the last scan.
    /// This only makes sense for subsequent scans.
    Changed,
    /// The value has decreased by some unknown amount since the last scan.
    /// This only makes sense for subsequent scans.
    Decreased,
    /// The value has increased by some unknown amount since the last scan.
    /// This only makes sense for subsequent scans.
    Increased,
    /// The value has decreased by the given amount since the last scan.
    /// This only makes sense for subsequent scans.
    DecreasedBy(i32),
    /// The value has increased by the given amount since the last scan.
    /// This only makes sense for subsequent scans.
    IncreasedBy(i32),
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
            Scan::InRange(range) => {
                let locations = memory
                    .windows(4)
                    .enumerate()
                    .step_by(4)
                    .flat_map(|(offset, window)| {
                        let n = i32::from_ne_bytes([window[0], window[1], window[2], window[3]]);
                        if range.contains(&n) {
                            Some(base + offset)
                        } else {
                            None
                        }
                    })
                    .collect();
                Region {
                    info,
                    locations: CandidateLocations::Discrete { locations },
                    value: Value::AnyWithin(memory),
                }
            }
            // For scans that make no sense on a first run, treat them as unknown.
            Scan::Unknown
            | Scan::Unchanged
            | Scan::Changed
            | Scan::Decreased
            | Scan::Increased
            | Scan::DecreasedBy(_)
            | Scan::IncreasedBy(_) => Region {
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
            // Optimization: unknown scan won't narrow down the region at all.
            Scan::Unknown => region.clone(),
            _ => Region {
                info: region.info.clone(),
                locations: CandidateLocations::Discrete {
                    locations: region
                        .iter_locations(&memory)
                        .flat_map(|(addr, old, new)| {
                            if self.acceptable(old, new) {
                                Some(addr)
                            } else {
                                None
                            }
                        })
                        .collect(),
                },
                value: Value::AnyWithin(memory),
            },
        }
    }

    /// Check if the change from the given `old` value to the `new` value is acceptable according
    /// to the current scan type.
    ///
    /// # Examples
    ///
    /// ```
    /// let scan = Scan::Increased;
    /// assert!(scan.acceptable(5, 7));
    /// ```
    fn acceptable(&self, old: i32, new: i32) -> bool {
        match self.clone() {
            Scan::Exact(n) => new == n,
            Scan::Unknown => true,
            Scan::InRange(range) => range.contains(&new),
            Scan::Unchanged => new == old,
            Scan::Changed => new != old,
            Scan::Decreased => new < old,
            Scan::Increased => new > old,
            Scan::DecreasedBy(n) => old.wrapping_sub(new) == n,
            Scan::IncreasedBy(n) => new.wrapping_sub(old) == n,
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
    ) -> Box<dyn Iterator<Item = (usize, i32, i32)> + 'a> {
        match &self.locations {
            CandidateLocations::Discrete { locations } => {
                Box::new(locations.iter().map(move |&addr| {
                    let old = self.value_at(addr);
                    let base = addr - self.info.BaseAddress as usize;
                    let bytes = &new_memory[base..base + 4];
                    let new = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    (addr, old, new)
                }))
            }
            CandidateLocations::Dense { range } => {
                Box::new(range.clone().step_by(4).map(move |addr| {
                    let old = self.value_at(addr);
                    let base = addr - self.info.BaseAddress as usize;
                    let bytes = &new_memory[base..base + 4];
                    let new = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    (addr, old, new)
                }))
            }
        }
    }
}
