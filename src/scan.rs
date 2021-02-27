use std::cmp::Ordering;
use std::convert::TryInto;
use std::mem;
use std::ops::Range;
use std::str::FromStr;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

/// Represents types that can be scanned for in memory.
pub unsafe trait Scannable {
    /// Returns `true` if the current instance is considered equal to the given chunk of memory.
    ///
    /// Callers must `assert_eq!(memory.len(), Scannable::size(self))`.
    unsafe fn eq(&self, memory: &[u8]) -> bool;

    /// Compares `self` to the given chunk of memory.
    ///
    /// Callers must `assert_eq!(memory.len(), Scannable::size(self))`.
    unsafe fn cmp(&self, memory: &[u8]) -> Ordering;

    /// Substracts the given chunk of memory from `self`.
    ///
    /// Callers must `assert_eq!(memory.len(), Scannable::size(self))`.
    unsafe fn sub(&mut self, memory: &[u8]);

    /// Substracts `self` from the given chunk of memory.
    ///
    /// Callers must `assert_eq!(memory.len(), Scannable::size(self))`.
    unsafe fn rsub(&mut self, memory: &[u8]);

    /// Return the memory view corresponding to this value.
    fn mem_view(&self) -> &[u8];

    /// Return the size of this object's representation in memory.
    ///
    /// Implementors must always return the same size for a specific value, and it must correspond
    /// to the actual size of the value.
    fn size(&self) -> usize;
}

/// A scan type.
///
/// The variant determines how a memory scan should be performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scan<T: Scannable + Clone> {
    /// Perform an exact memory scan.
    /// Only memory locations containing this exact value will be considered.
    Exact(T),
    /// The value is unknown.
    /// Every memory location is considered valid. This only makes sense for a first scan.
    Unknown,
    /// The value is contained within a given range.
    InRange(T, T),
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
    DecreasedBy(T),
    /// The value has increased by the given amount since the last scan.
    /// This only makes sense for subsequent scans.
    IncreasedBy(T),
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
pub enum Value<T: Scannable> {
    /// All the values exactly matched this at the time of the scan.
    Exact(T),
    /// The value is not known, so anything represented within this chunk must be considered.
    AnyWithin(Vec<u8>),
}

/// A memory region.
#[derive(Clone)]
pub struct Region<T: Scannable> {
    /// The raw information about this memory region.
    pub info: MEMORY_BASIC_INFORMATION,
    /// Candidate locations that should be considered during subsequent scans.
    pub locations: CandidateLocations,
    /// The value (or value range) to compare against during subsequent scans.
    pub value: Value<T>,
}

macro_rules! impl_scannable_for_int {
    ( $( $ty:ty ),* ) => {
        $(
            #[allow(unused_unsafe)] // mind you, it is necessary
            unsafe impl Scannable for $ty {
                unsafe fn eq(&self, memory: &[u8]) -> bool {
                    // SAFETY: caller is responsible to `assert_eq!(memory.len(), Scannable::size(T))`
                    let other = unsafe { memory.as_ptr().cast::<$ty>().read_unaligned() };
                    *self == other
                }

                unsafe fn cmp(&self, memory: &[u8]) -> Ordering {
                    // SAFETY: caller is responsible to `assert_eq!(memory.len(), Scannable::size(T))`
                    let other = unsafe { memory.as_ptr().cast::<$ty>().read_unaligned() };
                    <$ty as Ord>::cmp(self, &other)
                }

                unsafe fn sub(&mut self, memory: &[u8]) {
                    // SAFETY: caller is responsible to `assert_eq!(memory.len(), Scannable::size(T))`
                    let other = unsafe { memory.as_ptr().cast::<$ty>().read_unaligned() };
                    *self = self.wrapping_sub(other);
                }

                unsafe fn rsub(&mut self, memory: &[u8]) {
                    // SAFETY: caller is responsible to `assert_eq!(memory.len(), Scannable::size(T))`
                    let other = unsafe { memory.as_ptr().cast::<$ty>().read_unaligned() };
                    *self = other.wrapping_sub(*self);
                }

                fn mem_view(&self) -> &[u8] {
                    // SAFETY: output slice len matches Self size.
                    unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, mem::size_of::<$ty>()) }
                }

                // SAFETY: the returned value corresponds to the size of the integer type
                fn size(&self) -> usize {
                    mem::size_of::<$ty>()
                }
            }
        )*
    };
}

macro_rules! impl_scannable_for_float {
    ( $( $ty:ty : $int_ty:ty ),* ) => {
        $(
            #[allow(unused_unsafe)] // mind you, it is necessary
            unsafe impl Scannable for $ty {
                unsafe fn eq(&self, memory: &[u8]) -> bool {
                    const MASK: $int_ty = !((1 << (<$ty>::MANTISSA_DIGITS / 2)) - 1);

                    // SAFETY: caller is responsible to `assert_eq!(memory.len(), Scannable::size(T))`
                    let other = unsafe { memory.as_ptr().cast::<$ty>().read_unaligned() };
                    let left = <$ty>::from_bits(self.to_bits() & MASK);
                    let right = <$ty>::from_bits(other.to_bits() & MASK);
                    left == right
                }

                unsafe fn cmp(&self, memory: &[u8]) -> Ordering {
                    // SAFETY: caller is responsible to `assert_eq!(memory.len(), Scannable::size(T))`
                    let other = unsafe { memory.as_ptr().cast::<$ty>().read_unaligned() };
                    // FIXME: https://github.com/rust-lang/rust/issues/72599
                    self.partial_cmp(&other).unwrap_or(Ordering::Less)
                }

                unsafe fn sub(&mut self, memory: &[u8]) {
                    // SAFETY: caller is responsible to `assert_eq!(memory.len(), Scannable::size(T))`
                    let other = unsafe { memory.as_ptr().cast::<$ty>().read_unaligned() };
                    *self = *self - other;
                }

                unsafe fn rsub(&mut self, memory: &[u8]) {
                    // SAFETY: caller is responsible to `assert_eq!(memory.len(), Scannable::size(T))`
                    let other = unsafe { memory.as_ptr().cast::<$ty>().read_unaligned() };
                    *self = other - *self;
                }

                fn mem_view(&self) -> &[u8] {
                    // SAFETY: output slice len matches Self size.
                    unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, mem::size_of::<$ty>()) }
                }

                // SAFETY: the returned value corresponds to the size of the integer type
                fn size(&self) -> usize {
                    mem::size_of::<$ty>()
                }
            }
        )*
    };
}

impl_scannable_for_int!(i8, u8, i16, u16, i32, u32, i64, u64);
impl_scannable_for_float!(f32: u32, f64: u64);

impl<T: Scannable + Clone> Scan<T> {
    /// Run the scan over the memory corresponding to the given region information.
    ///
    /// Returns a scanned region with all the results found.
    pub fn run(&self, info: MEMORY_BASIC_INFORMATION, memory: Vec<u8>) -> Region<T> {
        let base = info.BaseAddress as usize;
        match self {
            Scan::Exact(target) => {
                let locations = memory
                    .windows(target.size())
                    .enumerate()
                    .step_by(mem::align_of::<T>())
                    .flat_map(|(offset, window)| {
                        // SAFETY: `window.len() == Scannable::size(target)`.
                        if unsafe { target.eq(window) } {
                            Some(base + offset)
                        } else {
                            None
                        }
                    })
                    .collect();
                Region {
                    info,
                    locations: CandidateLocations::Discrete { locations },
                    value: Value::Exact(target.clone()),
                }
            }
            Scan::InRange(low, high) => {
                assert_eq!(low.size(), high.size());
                let locations = memory
                    .windows(low.size())
                    .enumerate()
                    .step_by(mem::align_of::<T>())
                    .flat_map(|(offset, window)| {
                        // SAFETY: `window.len() == Scannable::size(target)`.
                        if unsafe {
                            low.cmp(window) != Ordering::Greater
                                && high.cmp(window) != Ordering::Less
                        } {
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
    pub fn rerun(&self, region: &Region<T>, memory: Vec<u8>) -> Region<T> {
        match self {
            // Optimization: unknown scan won't narrow down the region at all.
            Scan::Unknown => region.clone(),
            _ => {
                let mut locations = CandidateLocations::Discrete {
                    locations: region
                        .locations
                        .iter::<T>()
                        .flat_map(|addr| {
                            let old = region.value_at(addr);
                            let base = addr - region.info.BaseAddress as usize;
                            let bytes = &memory[base..base + mem::size_of::<T>()];
                            // SAFETY: `bytes.len() == mem::size_of::<T>()`.
                            if unsafe { self.acceptable(old, bytes) } {
                                Some(addr)
                            } else {
                                None
                            }
                        })
                        .collect(),
                };
                locations.try_compact::<T>();

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
    ///
    /// # Safety
    ///
    /// Caller must `assert_eq!(new.len(), mem::size_of::<T>())`.
    unsafe fn acceptable(&self, old: T, new: &[u8]) -> bool {
        match self {
            Scan::Exact(n) => n.eq(new),
            Scan::Unknown => true,
            Scan::InRange(low, high) => {
                low.cmp(new) != Ordering::Greater && high.cmp(new) != Ordering::Less
            }
            Scan::Unchanged => old.eq(new),
            Scan::Changed => !old.eq(new),
            Scan::Decreased => old.cmp(new) == Ordering::Greater,
            Scan::Increased => old.cmp(new) == Ordering::Less,
            Scan::DecreasedBy(n) => {
                let mut delta = old.clone();
                delta.sub(new);
                n.eq(delta.mem_view())
            }
            Scan::IncreasedBy(n) => {
                let mut delta = old.clone();
                delta.rsub(new);
                n.eq(delta.mem_view())
            }
        }
    }
}

impl FromStr for Scan<i32> {
    type Err = std::num::ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value.as_bytes()[0] {
            b'u' => Scan::Unknown,
            b'=' => Scan::Unchanged,
            b'~' => Scan::Changed,
            t @ b'd' | t @ b'i' => {
                let n = value[1..].trim();
                if n.is_empty() {
                    if t == b'd' {
                        Scan::Decreased
                    } else {
                        Scan::Increased
                    }
                } else {
                    let n = n.parse()?;
                    if t == b'd' {
                        Scan::DecreasedBy(n)
                    } else {
                        Scan::IncreasedBy(n)
                    }
                }
            }
            _ => {
                let (low, high) = if let Some(i) = value.find("..=") {
                    (value[..i].parse()?, value[i + 3..].parse()?)
                } else if let Some(i) = value.find("..") {
                    (value[..i].parse()?, value[i + 2..].parse::<i32>()? - 1)
                } else {
                    let n = value.parse()?;
                    (n, n)
                };

                if low == high {
                    Scan::Exact(low)
                } else {
                    Scan::InRange(low, high)
                }
            }
        })
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
    pub fn try_compact<T>(&mut self) {
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
        let size_for_aligned = size / mem::align_of::<T>();

        // Can the entire region be represented with a base and 16-bit offsets?
        // And is it more worth than using a single byte per 4-byte aligned location?
        if size <= u16::MAX as _ && locations.len() * mem::size_of::<u16>() < size_for_aligned {
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
        if size_for_aligned < locations.len() * mem::size_of::<usize>() {
            assert_eq!(low % 4, 0);

            let mut locations = locations.into_iter();
            let mut next_set = locations.next();
            *self = CandidateLocations::Sparse {
                base: low,
                mask: (low..high)
                    .step_by(mem::align_of::<T>())
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
    pub fn iter<'a, T>(&'a self) -> Box<dyn Iterator<Item = usize> + 'a> {
        match self {
            CandidateLocations::Discrete { locations } => Box::new(locations.iter().copied()),
            CandidateLocations::SmallDiscrete { base, offsets } => {
                Box::new(offsets.iter().map(move |&offset| base + offset as usize))
            }
            CandidateLocations::Dense { range } => {
                Box::new(range.clone().step_by(mem::align_of::<T>()))
            }
            CandidateLocations::Sparse { base, mask } => Box::new(
                mask.iter()
                    .enumerate()
                    .filter(|(_, &set)| set)
                    .map(move |(i, _)| base + i * 4),
            ),
        }
    }
}

impl<T: Scannable + Clone> Region<T> {
    /// Return the value stored at `addr`.
    fn value_at(&self, addr: usize) -> T {
        match &self.value {
            Value::Exact(n) => n.clone(),
            Value::AnyWithin(chunk) => {
                let base = addr - self.info.BaseAddress as usize;
                let bytes = &chunk[base..base + mem::size_of::<T>()];
                // SAFETY: `bytes` has the same length as the size of `T`
                unsafe { bytes.as_ptr().cast::<T>().read_unaligned() }
            }
        }
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    #[test]
    fn exact() {
        assert_eq!("42".parse(), Ok(Scan::Exact(42)));
        assert_eq!("-42".parse(), Ok(Scan::Exact(-42)));
    }

    #[test]
    fn unknown() {
        assert_eq!("u".parse(), Ok(Scan::Unknown));
    }

    #[test]
    fn in_range() {
        assert_eq!("12..34".parse(), Ok(Scan::InRange(12, 33)));
        assert_eq!("12..=34".parse(), Ok(Scan::InRange(12, 34)));
    }

    #[test]
    fn unchanged() {
        assert_eq!("=".parse(), Ok(Scan::Unchanged));
    }

    #[test]
    fn changed() {
        assert_eq!("~".parse(), Ok(Scan::Changed));
    }

    #[test]
    fn decreased() {
        assert_eq!("d".parse(), Ok(Scan::Decreased));
    }

    #[test]
    fn increased() {
        assert_eq!("i".parse(), Ok(Scan::Increased));
    }

    #[test]
    fn decreased_by() {
        assert_eq!("d42".parse(), Ok(Scan::DecreasedBy(42)));
        assert_eq!("d 42".parse(), Ok(Scan::DecreasedBy(42)));
        assert_eq!("d-42".parse(), Ok(Scan::DecreasedBy(-42)));
    }

    #[test]
    fn increased_by() {
        assert_eq!("i42".parse(), Ok(Scan::IncreasedBy(42)));
        assert_eq!("i 42".parse(), Ok(Scan::IncreasedBy(42)));
        assert_eq!("i-42".parse(), Ok(Scan::IncreasedBy(-42)));
    }
}

#[cfg(test)]
mod candidate_location_tests {
    use super::*;

    #[test]
    fn f32_roughly_eq() {
        let left = 0.25f32;
        let right = 0.25000123f32;
        let memory = unsafe { mem::transmute::<_, [u8; 4]>(right) };
        assert_ne!(left, right);
        assert!(unsafe { Scannable::eq(&left, &memory) });
    }

    #[test]
    fn compact_uncompactable() {
        // Dense
        let mut locations = CandidateLocations::Dense {
            range: 0x2000..0x2100,
        };
        locations.try_compact::<i32>();
        assert!(matches!(locations, CandidateLocations::Dense { .. }));

        // Already compacted
        let mut locations = CandidateLocations::SmallDiscrete {
            base: 0x2000,
            offsets: vec![0, 0x20, 0x40],
        };
        locations.try_compact::<i32>();
        assert!(matches!(locations, CandidateLocations::SmallDiscrete { .. }));

        let mut locations = CandidateLocations::Sparse {
            base: 0x2000,
            mask: vec![true, false, false, false],
        };
        locations.try_compact::<i32>();
        assert!(matches!(locations, CandidateLocations::Sparse { .. }));
    }

    #[test]
    fn compact_not_worth() {
        // Too small
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000],
        };
        let original = locations.clone();
        locations.try_compact::<i32>();
        assert_eq!(locations, original);

        // Too sparse and too large to fit in `SmallDiscrete`.
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000, 0x42000],
        };
        let original = locations.clone();
        locations.try_compact::<i32>();
        assert_eq!(locations, original);
    }

    #[test]
    fn compact_small_discrete() {
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000, 0x2004, 0x2040],
        };
        locations.try_compact::<i32>();
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
        locations.try_compact::<i32>();
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
            locations.iter::<i32>().collect::<Vec<_>>(),
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
            locations.iter::<i32>().collect::<Vec<_>>(),
            vec![0x2000, 0x2004, 0x200c]
        );
    }

    #[test]
    fn iter_dense() {
        let locations = CandidateLocations::Dense {
            range: 0x2000..0x2010,
        };
        assert_eq!(
            locations.iter::<i32>().collect::<Vec<_>>(),
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
            locations.iter::<i32>().collect::<Vec<_>>(),
            vec![0x2000, 0x2004, 0x200c]
        );
    }
}
