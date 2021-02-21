use std::convert::TryInto;
use std::mem;
use std::ops::Range;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

/// A scan type.
///
/// The variant determines how a memory scan should be performed.
#[derive(Clone, Copy, Debug)]
pub enum Scan {
    /// Perform an exact memory scan.
    /// Only memory locations containing this exact value will be considered.
    Exact(i32),
    /// The value is unknown.
    /// Every memory location is considered valid. This only makes sense for a first scan.
    Unknown,
    /// The value is contained within a given range.
    InRange(i32, i32),
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateLocations {
    /// Multiple, separated locations.
    ///
    /// It is a logic error to have the locations in non-ascending order.
    Discrete { locations: Vec<usize> },
    /// Like `Discrete`, but uses less memory.
    // TODO this could also assume 4-byte aligned so we'd gain 2 bits for offsets.
    SmallDiscrete { base: usize, offsets: Vec<u16> },
    /// A dense memory location. Everything within here should be considered.
    Dense { range: Range<usize> },
    /// A sparse memory location. Pretty much like `Dense`, but only items within the mask apply.
    /// The mask assumes 4-byte aligned data  (so one byte for every 4).
    Sparse { base: usize, mask: Vec<bool> },
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
        match *self {
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
                    value: Value::Exact(n),
                }
            }
            Scan::InRange(low, high) => {
                let locations = memory
                    .windows(4)
                    .enumerate()
                    .step_by(4)
                    .flat_map(|(offset, window)| {
                        let n = i32::from_ne_bytes([window[0], window[1], window[2], window[3]]);
                        if low <= n && n <= high {
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
            _ => {
                let mut locations = CandidateLocations::Discrete {
                    locations: region
                        .locations
                        .iter()
                        .flat_map(|addr| {
                            let old = region.value_at(addr);
                            let base = addr - region.info.BaseAddress as usize;
                            let bytes = &memory[base..base + 4];
                            let new = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                            if self.acceptable(old, new) {
                                Some(addr)
                            } else {
                                None
                            }
                        })
                        .collect(),
                };
                locations.try_compact();

                Region {
                    info: region.info.clone(),
                    locations,
                    value: Value::AnyWithin(memory),
                }
            }
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
        match *self {
            Scan::Exact(n) => new == n,
            Scan::Unknown => true,
            Scan::InRange(low, high) => low <= new && new <= high,
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
            CandidateLocations::SmallDiscrete { offsets, .. } => offsets.len(),
            CandidateLocations::Dense { range } => range.len(),
            CandidateLocations::Sparse { mask, .. } => mask.iter().filter(|x| **x).count(),
        }
    }

    /// Tries to compact the candidate locations into a more efficient representation.
    pub fn try_compact(&mut self) {
        let locations = match self {
            CandidateLocations::Discrete { locations } if locations.len() >= 2 => {
                mem::take(locations)
            }
            _ => return,
        };

        // It is assumed that locations are always sorted in ascending order.
        let low = *locations.first().unwrap();
        let high = *locations.last().unwrap();
        let size = high - low;

        // Can the entire region be represented with a base and 16-bit offsets?
        // And is it more worth than using a single byte per 4-byte aligned location?
        if size <= u16::MAX as _ && locations.len() * mem::size_of::<u16>() < size / 4 {
            // We will always store a `0` offset, but that's fine, it makes iteration easier and
            // getting rid of it would only gain usu 2 bytes.
            *self = CandidateLocations::SmallDiscrete {
                base: low,
                offsets: locations
                    .into_iter()
                    .map(|loc| (loc - low).try_into().unwrap())
                    .collect(),
            };
            return;
        }

        // Would using a byte-mask for the entire region be more worth it?
        if size / 4 < locations.len() * mem::size_of::<usize>() {
            assert_eq!(low % 4, 0);

            let mut locations = locations.into_iter();
            let mut next_set = locations.next();
            *self = CandidateLocations::Sparse {
                base: low,
                mask: (low..high)
                    .step_by(4)
                    .map(|addr| {
                        if Some(addr) == next_set {
                            next_set = locations.next();
                            true
                        } else {
                            false
                        }
                    })
                    .collect(),
            };
            return;
        }

        // Neither of the attempts is really better than just storing the locations.
        // Revert to using a discrete representation.
        *self = CandidateLocations::Discrete { locations };
    }

    /// Return a iterator over the locations.
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = usize> + 'a> {
        match self {
            CandidateLocations::Discrete { locations } => Box::new(locations.iter().copied()),
            CandidateLocations::SmallDiscrete { base, offsets } => {
                Box::new(offsets.iter().map(move |&offset| base + offset as usize))
            }
            CandidateLocations::Dense { range } => Box::new(range.clone().step_by(4)),
            CandidateLocations::Sparse { base, mask } => Box::new(
                mask.iter()
                    .enumerate()
                    .filter(|(_, &set)| set)
                    .map(move |(i, _)| base + i * 4),
            ),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_uncompactable() {
        // Dense
        let mut locations = CandidateLocations::Dense {
            range: 0x2000..0x2100,
        };
        locations.try_compact();
        assert!(matches!(locations, CandidateLocations::Dense { .. }));

        // Already compacted
        let mut locations = CandidateLocations::SmallDiscrete {
            base: 0x2000,
            offsets: vec![0, 0x20, 0x40],
        };
        locations.try_compact();
        assert!(matches!(locations, CandidateLocations::SmallDiscrete { .. }));

        let mut locations = CandidateLocations::Sparse {
            base: 0x2000,
            mask: vec![true, false, false, false],
        };
        locations.try_compact();
        assert!(matches!(locations, CandidateLocations::Sparse { .. }));
    }

    #[test]
    fn compact_not_worth() {
        // Too small
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000],
        };
        let original = locations.clone();
        locations.try_compact();
        assert_eq!(locations, original);

        // Too sparse and too large to fit in `SmallDiscrete`.
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000, 0x42000],
        };
        let original = locations.clone();
        locations.try_compact();
        assert_eq!(locations, original);
    }

    #[test]
    fn compact_small_discrete() {
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000, 0x2004, 0x2040],
        };
        locations.try_compact();
        assert_eq!(
            locations,
            CandidateLocations::SmallDiscrete {
                base: 0x2000,
                offsets: vec![0x0000, 0x0004, 0x0040],
            }
        );
    }

    #[test]
    fn compact_sparse() {
        let mut locations = CandidateLocations::Discrete {
            locations: vec![
                0x2000, 0x2004, 0x200c, 0x2010, 0x2014, 0x2018, 0x201c, 0x2020,
            ],
        };
        locations.try_compact();
        assert_eq!(
            locations,
            CandidateLocations::Sparse {
                base: 0x2000,
                mask: vec![true, true, false, true, true, true, true, true],
            }
        );
    }

    #[test]
    fn iter_discrete() {
        let locations = CandidateLocations::Discrete {
            locations: vec![0x2000, 0x2004, 0x200c],
        };
        assert_eq!(
            locations.iter().collect::<Vec<_>>(),
            vec![0x2000, 0x2004, 0x200c]
        );
    }

    #[test]
    fn iter_small_discrete() {
        let locations = CandidateLocations::SmallDiscrete {
            base: 0x2000,
            offsets: vec![0x0000, 0x0004, 0x000c],
        };
        assert_eq!(
            locations.iter().collect::<Vec<_>>(),
            vec![0x2000, 0x2004, 0x200c]
        );
    }

    #[test]
    fn iter_dense() {
        let locations = CandidateLocations::Dense {
            range: 0x2000..0x2010,
        };
        assert_eq!(
            locations.iter().collect::<Vec<_>>(),
            vec![0x2000, 0x2004, 0x2008, 0x200c]
        );
    }

    #[test]
    fn iter_sparse() {
        let locations = CandidateLocations::Sparse {
            base: 0x2000,
            mask: vec![true, true, false, true],
        };
        assert_eq!(
            locations.iter().collect::<Vec<_>>(),
            vec![0x2000, 0x2004, 0x200c]
        );
    }
}
