use std::cmp::Ordering;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::mem;
use std::ops::Range;
use std::str::FromStr;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

/// Represents the scan mode according associated to a certain type.
pub trait ScanMode {
    /// Returns `true` if the current instance is considered equal to the given chunk of memory.
    ///
    /// Callers must `assert_eq!(left.len(), right.len())`, and the length must also match that of
    /// the length represented by `Self`.
    unsafe fn eq(left: &[u8], right: &[u8]) -> bool;

    /// Compares `self` to the given chunk of memory.
    ///
    /// Callers must `assert_eq!(left.len(), right.len())`, and the length must also match that of
    /// the length represented by `Self`.
    unsafe fn cmp(left: &[u8], right: &[u8]) -> Ordering;

    /// Substracts the given chunk of memory from `self`.
    ///
    /// Callers must `assert_eq!(left.len(), right.len())`, and the length must also match that of
    /// the length represented by `Self`.
    unsafe fn sub(left: &mut [u8], right: &[u8]);

    /// Substracts `self` from the given chunk of memory.
    ///
    /// Callers must `assert_eq!(left.len(), right.len())`, and the length must also match that of
    /// the length represented by `Self`.
    unsafe fn rsub(left: &mut [u8], right: &[u8]);
}

pub unsafe trait Scannable {
    /// The `ScanMode` used by this `Scannable`.
    ///
    /// For a given `T: Scannable`, `T.mem_view().len()` must be equal to the length expected
    /// by this `ScanMode`.
    type Mode: ScanMode;

    /// Return the memory view corresponding to this value.
    ///
    /// The returned length should always be the same for the same `self`.
    fn mem_view(&self) -> &[u8];
}

/// A scan type.
///
/// The variant determines how a memory scan should be performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scan<M: ScanMode> {
    /// Perform an exact memory scan.
    /// Only memory locations containing this exact value will be considered.
    Exact(Vec<u8>, PhantomData<M>),
    /// The value is unknown.
    /// Every memory location is considered valid. This only makes sense for a first scan.
    Unknown(usize),
    /// The value is contained within a given range.
    InRange(Vec<u8>, Vec<u8>),
    /// The value has not changed since the last scan.
    /// This only makes sense for subsequent scans.
    Unchanged(usize),
    /// The value has changed since the last scan.
    /// This only makes sense for subsequent scans.
    Changed(usize),
    /// The value has decreased by some unknown amount since the last scan.
    /// This only makes sense for subsequent scans.
    Decreased(usize),
    /// The value has increased by some unknown amount since the last scan.
    /// This only makes sense for subsequent scans.
    Increased(usize),
    /// The value has decreased by the given amount since the last scan.
    /// This only makes sense for subsequent scans.
    DecreasedBy(Vec<u8>),
    /// The value has increased by the given amount since the last scan.
    /// This only makes sense for subsequent scans.
    IncreasedBy(Vec<u8>),
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
    Exact(Vec<u8>),
    /// The value is not known, so anything represented within this chunk must be considered.
    AnyWithin { memory: Vec<u8>, size: usize },
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

macro_rules! impl_scannable_for_int {
    ( $( $ty:ty ),* ) => {
        $(
            #[allow(unused_unsafe)] // mind you, it is necessary
            impl ScanMode for $ty {
                unsafe fn eq(left: &[u8], right: &[u8]) -> bool {
                    // SAFETY: caller is responsible to uphold the invariants.
                    let lhs = unsafe { left.as_ptr().cast::<$ty>().read_unaligned() };
                    let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                    lhs == rhs
                }

                unsafe fn cmp(left: &[u8], right: &[u8]) -> Ordering {
                    // SAFETY: caller is responsible to uphold the invariants.
                    let lhs = unsafe { left.as_ptr().cast::<$ty>().read_unaligned() };
                    let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                    Ord::cmp(&lhs, &rhs)
                }

                unsafe fn sub(left: &mut [u8], right: &[u8]) {
                    // SAFETY: caller is responsible to uphold the invariants.
                    let left = left.as_mut_ptr().cast::<$ty>();
                    let lhs = unsafe { left.read_unaligned() };
                    let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                    unsafe { left.write_unaligned(lhs.wrapping_sub(rhs)) }
                }

                unsafe fn rsub(left: &mut [u8], right: &[u8]) {
                    // SAFETY: caller is responsible to uphold the invariants.
                    let left = left.as_mut_ptr().cast::<$ty>();
                    let lhs = unsafe { left.read_unaligned() };
                    let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                    unsafe { left.write_unaligned(rhs.wrapping_sub(lhs)) }
                }
            }

            // SAFETY: output `slice::len` matches `mem::size_of::<Self>()`.
            unsafe impl Scannable for $ty {
                type Mode = $ty;

                fn mem_view(&self) -> &[u8] {
                    unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, mem::size_of::<$ty>()) }
                }
            }
        )*
    };
}

macro_rules! impl_scannable_for_float {
    ( $( $ty:ty : $int_ty:ty ),* ) => {
        $(
            #[allow(unused_unsafe)] // mind you, it is necessary
            impl ScanMode for $ty {
                unsafe fn eq(left: &[u8], right: &[u8]) -> bool {
                    const MASK: $int_ty = !((1 << (<$ty>::MANTISSA_DIGITS / 2)) - 1);

                    // SAFETY: caller is responsible to uphold the invariants.
                    let lhs = unsafe { left.as_ptr().cast::<$ty>().read_unaligned() };
                    let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                    let lhs = <$ty>::from_bits(lhs.to_bits() & MASK);
                    let rhs = <$ty>::from_bits(rhs.to_bits() & MASK);
                    lhs == rhs
                }

                unsafe fn cmp(left: &[u8], right: &[u8]) -> Ordering {
                    // SAFETY: caller is responsible to uphold the invariants.
                    let lhs = unsafe { left.as_ptr().cast::<$ty>().read_unaligned() };
                    let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                    // FIXME: https://github.com/rust-lang/rust/issues/72599
                    lhs.partial_cmp(&rhs).unwrap_or(Ordering::Less)
                }

                unsafe fn sub(left: &mut [u8], right: &[u8]) {
                    // SAFETY: caller is responsible to uphold the invariants.
                    let left = left.as_mut_ptr().cast::<$ty>();
                    let lhs = unsafe { left.read_unaligned() };
                    let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                    unsafe { left.write_unaligned(lhs - rhs) }
                }

                unsafe fn rsub(left: &mut [u8], right: &[u8]) {
                    // SAFETY: caller is responsible to uphold the invariants.
                    let left = left.as_mut_ptr().cast::<$ty>();
                    let lhs = unsafe { left.read_unaligned() };
                    let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                    unsafe { left.write_unaligned(rhs - lhs) }
                }
            }

            // SAFETY: output `slice::len` matches `mem::size_of::<Self>()`.
            unsafe impl Scannable for $ty {
                type Mode = $ty;

                fn mem_view(&self) -> &[u8] {
                    unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, mem::size_of::<$ty>()) }
                }
            }
        )*
    };
}

impl_scannable_for_int!(i8, u8, i16, u16, i32, u32, i64, u64);
impl_scannable_for_float!(f32: u32, f64: u64);

unsafe impl<T: ScanMode + AsRef<dyn Scannable<Mode = Self>>> Scannable for T {
    type Mode = Self;

    fn mem_view(&self) -> &[u8] {
        self.as_ref().mem_view()
    }
}

impl<T: Scannable + ScanMode> Scan<T> {
    /// Run the scan over the memory corresponding to the given region information.
    ///
    /// Returns a scanned region with all the results found.
    pub fn run(&self, info: MEMORY_BASIC_INFORMATION, memory: Vec<u8>) -> Region {
        let base = info.BaseAddress as usize;
        match self {
            Scan::Exact(target, _) => {
                let locations = memory
                    .windows(target.len())
                    .enumerate()
                    .step_by(mem::align_of::<T>())
                    .flat_map(|(offset, window)| {
                        // SAFETY: `window.len() == Scannable::size(target)`.
                        if unsafe { T::eq(target, window) } {
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
                assert_eq!(low.len(), high.len());
                let locations = memory
                    .windows(low.len())
                    .enumerate()
                    .step_by(mem::align_of::<T>())
                    .flat_map(|(offset, window)| {
                        // SAFETY: `window.len() == Scannable::size(target)`.
                        if unsafe {
                            T::cmp(low, window) != Ordering::Greater
                                && T::cmp(high, window) != Ordering::Less
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
                    value: Value::AnyWithin {
                        memory,
                        size: low.len(),
                    },
                }
            }
            // For scans that make no sense on a first run, treat them as unknown.
            Scan::Unknown(size)
            | Scan::Unchanged(size)
            | Scan::Changed(size)
            | Scan::Decreased(size)
            | Scan::Increased(size) => Region {
                info,
                locations: CandidateLocations::Dense {
                    range: base..base + info.RegionSize,
                },
                value: Value::AnyWithin {
                    memory,
                    size: *size,
                },
            },

            Scan::DecreasedBy(value) | Scan::IncreasedBy(value) => Region {
                info,
                locations: CandidateLocations::Dense {
                    range: base..base + info.RegionSize,
                },
                value: Value::AnyWithin {
                    memory,
                    size: value.len(),
                },
            },
        }
    }

    /// Re-run the scan over a previously-scanned memory region.
    ///
    /// Returns the new scanned region with all the results found.
    pub fn rerun(&self, region: &Region, memory: Vec<u8>) -> Region {
        let size = match self {
            // Optimization: unknown scan won't narrow down the region at all.
            Scan::Unknown(_) => return region.clone(),
            Scan::Exact(value, _) => value.len(),
            Scan::InRange(low, high) => {
                assert_eq!(low.len(), high.len());
                low.len()
            }
            Scan::Unchanged(size)
            | Scan::Changed(size)
            | Scan::Decreased(size)
            | Scan::Increased(size) => *size,
            Scan::DecreasedBy(value) | Scan::IncreasedBy(value) => value.len(),
        };

        let mut locations = CandidateLocations::Discrete {
            locations: region
                .locations
                .iter::<T>()
                .flat_map(|addr| {
                    let old = region.value_at(addr);
                    let base = addr - region.info.BaseAddress as usize;
                    let bytes = &memory[base..base + size];
                    // SAFETY: `bytes.len() == size`.
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
            value: Value::AnyWithin { memory, size },
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
    unsafe fn acceptable(&self, old: &[u8], new: &[u8]) -> bool {
        match self {
            Scan::Exact(n, _) => T::eq(n, new),
            Scan::Unknown(_) => true,
            Scan::InRange(low, high) => {
                T::cmp(low, new) != Ordering::Greater && T::cmp(high, new) != Ordering::Less
            }
            Scan::Unchanged(_) => T::eq(old, new),
            Scan::Changed(_) => !T::eq(old, new),
            Scan::Decreased(_) => T::cmp(old, new) == Ordering::Greater,
            Scan::Increased(_) => T::cmp(old, new) == Ordering::Less,
            Scan::DecreasedBy(n) => {
                let mut delta = old.to_vec();
                T::sub(delta.as_mut(), new);
                T::eq(n, delta.as_ref())
            }
            Scan::IncreasedBy(n) => {
                let mut delta = old.to_vec();
                T::rsub(delta.as_mut(), new);
                T::eq(n, delta.as_ref())
            }
        }
    }
}

impl FromStr for Scan<i32> {
    type Err = std::num::ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let size = mem::size_of::<i32>();
        Ok(match value.as_bytes()[0] {
            b'u' => Scan::Unknown(size),
            b'=' => Scan::Unchanged(size),
            b'~' => Scan::Changed(size),
            t @ b'd' | t @ b'i' => {
                let n = value[1..].trim();
                if n.is_empty() {
                    if t == b'd' {
                        Scan::Decreased(size)
                    } else {
                        Scan::Increased(size)
                    }
                } else {
                    let n = n.parse::<i32>()?;
                    if t == b'd' {
                        Scan::DecreasedBy(n.mem_view().to_vec())
                    } else {
                        Scan::IncreasedBy(n.mem_view().to_vec())
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
                    Scan::Exact(low.mem_view().to_vec(), PhantomData)
                } else {
                    Scan::InRange(low.mem_view().to_vec(), high.mem_view().to_vec())
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

impl Region {
    /// Return the value stored at `addr`.
    fn value_at(&self, addr: usize) -> &[u8] {
        match &self.value {
            Value::Exact(n) => n,
            Value::AnyWithin { memory, size } => {
                let base = addr - self.info.BaseAddress as usize;
                &memory[base..base + size]
            }
        }
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    #[test]
    fn exact() {
        assert_eq!(
            "42".parse(),
            Ok(Scan::Exact(42.mem_view().to_vec(), PhantomData))
        );
        assert_eq!(
            "-42".parse(),
            Ok(Scan::Exact((-42).mem_view().to_vec(), PhantomData))
        );
    }

    #[test]
    fn unknown() {
        assert_eq!("u".parse(), Ok(Scan::Unknown(4)));
    }

    #[test]
    fn in_range() {
        assert_eq!(
            "12..34".parse(),
            Ok(Scan::InRange(
                12.mem_view().to_vec(),
                33.mem_view().to_vec()
            ))
        );
        assert_eq!(
            "12..=34".parse(),
            Ok(Scan::InRange(
                12.mem_view().to_vec(),
                34.mem_view().to_vec()
            ))
        );
    }

    #[test]
    fn unchanged() {
        assert_eq!("=".parse(), Ok(Scan::Unchanged(4)));
    }

    #[test]
    fn changed() {
        assert_eq!("~".parse(), Ok(Scan::Changed(4)));
    }

    #[test]
    fn decreased() {
        assert_eq!("d".parse(), Ok(Scan::Decreased(4)));
    }

    #[test]
    fn increased() {
        assert_eq!("i".parse(), Ok(Scan::Increased(4)));
    }

    #[test]
    fn decreased_by() {
        assert_eq!("d42".parse(), Ok(Scan::DecreasedBy(42.mem_view().to_vec())));
        assert_eq!(
            "d 42".parse(),
            Ok(Scan::DecreasedBy(42.mem_view().to_vec()))
        );
        assert_eq!(
            "d-42".parse(),
            Ok(Scan::DecreasedBy((-42).mem_view().to_vec()))
        );
    }

    #[test]
    fn increased_by() {
        assert_eq!("i42".parse(), Ok(Scan::IncreasedBy(42.mem_view().to_vec())));
        assert_eq!(
            "i 42".parse(),
            Ok(Scan::IncreasedBy(42.mem_view().to_vec()))
        );
        assert_eq!(
            "i-42".parse(),
            Ok(Scan::IncreasedBy((-42).mem_view().to_vec()))
        );
    }
}

#[cfg(test)]
mod candidate_location_tests {
    use super::*;

    #[test]
    fn f32_roughly_eq() {
        let left = 0.25f32;
        let lhs = unsafe { mem::transmute::<_, [u8; 4]>(left) };
        let right = 0.25000123f32;
        let rhs = unsafe { mem::transmute::<_, [u8; 4]>(right) };
        assert_ne!(left, right);
        assert!(unsafe { <f32 as ScanMode>::eq(&lhs, &rhs) });
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
