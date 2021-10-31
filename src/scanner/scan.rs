use std::convert::TryInto as _;
use std::marker::PhantomData;
use std::mem;
use std::ops::Range;

pub unsafe trait Predicate {
    /// The mandated size for the memory views in [`Self::applicable`].
    ///
    /// This is a constant because the size must be known at compile time, as there are no values
    /// which could be used to determine the size of this predicate type during runtime.
    ///
    /// The trait is unsafe to implement because the value used here must be faithful to the
    /// length required by [`Self::applicable`].
    const SIZE: usize;

    /// Return `true` if the change between the old and new memory view is of the current type,
    /// that is, this type of operation is applicable between the two memory snapshots.
    ///
    /// It is unsafe to call because the caller must assert that a certain type can be read from
    /// at given pointers, and it is unsafe to implement because the address may be unaligned,
    /// and guarantees any bit-pattern is valid.
    unsafe fn applicable(old: *const u8, new: *const u8) -> bool;
}

// These types are used when we know the layout and desired change at compile-time.
// We cannot use any values here, because those inherently belong to runtime checks.

/// Predicate which is true when the values have changed when interpreted as numbers.
pub struct Changed<T>(PhantomData<T>);

/// Predicate which is true when the values have not changed when interpreted as numbers.
pub struct Unchanged<T>(PhantomData<T>);

/// Predicate which is true when the value has decreased when interpreted as numbers.
pub struct Decreased<T>(PhantomData<T>);

/// Predicate which is true when the value has increased when interpreted as numbers.
pub struct Increased<T>(PhantomData<T>);

/// Predicate which always true. Useful to represent padding values with [`Chain`].
pub struct Any<T>(PhantomData<T>);

/// Predicate which is true when either of the predicates is true on the same value.
pub struct Either<P, Q>(PhantomData<P>, PhantomData<Q>);

/// Predicate which is true when both of the predicates are true on the same value.
pub struct Both<P, Q>(PhantomData<P>, PhantomData<Q>);

/// Predicate which is true when both of the predicates are true on adjacent values.
pub struct Chain<P, Q>(PhantomData<P>, PhantomData<Q>);

/// Candidate memory locations for holding our desired value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateLocations {
    /// Multiple, separated locations.
    ///
    /// It is a logic error to have the locations in non-ascending order.
    Discrete { locations: Vec<usize> },
    /// Like `Discrete`, but uses less memory.
    SmallDiscrete { base: usize, offsets: Vec<u16> },
    /// A dense memory location. Everything within here should be considered.
    Dense { range: Range<usize>, step: usize },
    /// A sparse memory location. Pretty much like `Dense`, but only items within the mask apply.
    /// The mask assumes 4-byte aligned data  (so one byte for every 4).
    Sparse {
        base: usize,
        mask: Vec<bool>,
        scale: usize,
    },
}

/// Scan settings used to produce a [`LiveScan`].
///
/// The methods take owned vectors so that memory can be automatically freed once no longer
/// needed, and the caller has the choice to clone or pass a previously-owned value which it
/// no longer has a need to store.
pub struct Scan<F>
where
    F: FnMut(&[u8]) -> bool,
{
    /// The size of the chunks that will be checked for a match.
    pub size: usize,
    /// The stride of the scan (number of bytes from the start of one chunk to the next).
    pub stride: usize,
    /// The predicate that will be used to determine whether a chunk should be kept or discarded.
    ///
    /// The predicate can range from something really trivial (e.g. keep all chunks, or only those
    /// matching a specific value) to more complex checks (e.g. keep chunks that, when interpreted
    /// as integers, fall within a specific range).
    ///
    /// If no guess can be made for the initial value, it is better to use
    /// [`LiveScan::with_value_size`], which will be far more space-efficient.
    pub predicate: F,
}

/// A live scan on which re-scans can be executed.
#[derive(Clone)]
pub struct LiveScan {
    /// Candidate locations that should be considered during subsequent scans.
    locations: CandidateLocations,
    /// The memory snapshot from the last run, used to compare against during subsequent scans.
    ///
    /// If an exact-value scan is followed only by unchanged-value scans, this could be optimized
    /// to only store said value. However, as soon as the subsequent scans differ from unchanged,
    /// or if the initial scan was something other than exact-value, we would need to allocate a
    /// new buffer to snapshot the memory at this point. Therefore, the trade-off here favours the
    /// common case (different scans) to avoid de-allocating and re-allocating this memory buffer.
    memory: Vec<u8>,
    /// The size of the value scanned during the initial scan.
    value_size: usize,
}

impl CandidateLocations {
    /// Retain only the locations for which the predicate returns true.
    ///
    /// This reuses the existing buffer for the locations.
    fn retain<F>(&mut self, mut predicate: F)
    where
        F: FnMut(usize) -> bool,
    {
        match self {
            CandidateLocations::Discrete { locations } => {
                locations.retain(|loc| predicate(*loc));
            }
            CandidateLocations::SmallDiscrete { base, offsets } => {
                offsets.retain(|off| predicate(*base + *off as usize));
            }
            CandidateLocations::Dense { range, step } => {
                *self = if range.len() / *step <= u16::MAX as usize {
                    CandidateLocations::SmallDiscrete {
                        base: range.start,
                        offsets: range
                            .clone()
                            .step_by(*step)
                            .filter_map(|loc| predicate(loc).then(|| (loc - range.start) as u16))
                            .collect(),
                    }
                } else {
                    CandidateLocations::Discrete {
                        locations: range
                            .clone()
                            .step_by(*step)
                            .filter(|loc| predicate(*loc))
                            .collect(),
                    }
                }
            }
            CandidateLocations::Sparse { base, mask, scale } => {
                let mut i = 0;
                mask.retain(|b| {
                    let keep = *b && predicate(*base + i * *scale);
                    i += 1;
                    keep
                });
            }
        }
    }

    /// Return the amount of candidate locations.
    pub fn len(&self) -> usize {
        match self {
            CandidateLocations::Discrete { locations } => locations.len(),
            CandidateLocations::SmallDiscrete { offsets, .. } => offsets.len(),
            CandidateLocations::Dense { range, step } => range.len() / step,
            CandidateLocations::Sparse { mask, .. } => mask.iter().filter(|x| **x).count(),
        }
    }

    /// Return whether there are no more candidate locations.
    pub fn is_empty(&self) -> bool {
        match self {
            CandidateLocations::Discrete { locations } => locations.is_empty(),
            CandidateLocations::SmallDiscrete { offsets, .. } => offsets.is_empty(),
            CandidateLocations::Dense { range, .. } => range.is_empty(),
            CandidateLocations::Sparse { mask, .. } => !mask.iter().any(|x| *x),
        }
    }

    /// Tries to compact the candidate locations into a more efficient representation.
    pub fn try_compact(&mut self, value_size: usize) {
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
        let size_for_aligned = size / value_size;

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
            assert_eq!(low % value_size, 0);

            let mut locations = locations.into_iter();
            let mut next_set = locations.next();
            *self = CandidateLocations::Sparse {
                base: low,
                mask: (low..high)
                    .step_by(value_size)
                    .map(|addr| {
                        if Some(addr) == next_set {
                            next_set = locations.next();
                            true
                        } else {
                            false
                        }
                    })
                    .collect(),
                scale: value_size,
            };
            return;
        }

        // Neither of the attempts is really better than just storing the locations.
        // Revert to using a discrete representation.
        *self = CandidateLocations::Discrete { locations };
    }

    /// Return a iterator over the locations.
    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = usize> + 'a> {
        match self {
            CandidateLocations::Discrete { locations } => Box::new(locations.iter().copied()),
            CandidateLocations::SmallDiscrete { base, offsets } => {
                Box::new(offsets.iter().map(move |&offset| base + offset as usize))
            }
            CandidateLocations::Dense { range, step } => Box::new(range.clone().step_by(*step)),
            CandidateLocations::Sparse { base, mask, scale } => Box::new(
                mask.iter()
                    .enumerate()
                    .filter(|(_, &set)| set)
                    .map(move |(i, _)| base + i * scale),
            ),
        }
    }
}

impl<F> Scan<F>
where
    F: FnMut(&[u8]) -> bool,
{
    /// Run the scan on some memory.
    ///
    /// Panics if either [`Self::size`] or [`Self::stride`] are zero.
    ///
    /// This method should be used when certain properties are known about a value, so that
    /// the number of stored locations is reduced when compared to [`LiveScan::with_value_size`].
    pub fn run_on(&mut self, memory: Vec<u8>) -> LiveScan {
        assert_ne!(self.size, 0);
        assert_ne!(self.stride, 0);

        LiveScan {
            locations: CandidateLocations::Discrete {
                locations: memory
                    .windows(self.size)
                    .enumerate()
                    .step_by(self.stride)
                    .flat_map(|(offset, window)| {
                        if (self.predicate)(window) {
                            Some(offset)
                        } else {
                            None
                        }
                    })
                    .collect(),
            },
            memory,
            value_size: self.size,
        }
    }
}

/// A re-scan cannot grow to contain more locations than it did before.
///
/// If a certain address was lost during a re-scan, a new scan must be made,
/// because the scan history is not persisted. Therefore, is not possible to go back.
///
/// The old memory buffer is returned so that it can be re-used.
impl LiveScan {
    /// Create a new scan on some memory.
    ///
    /// This method should be used when the initial value is not known at all
    /// (i.e. [`Scan::predicate`] would always return `true`).
    /// More specifically, a dense representation can be used for the found locations.
    pub fn with_value_size(size: usize, memory: Vec<u8>) -> Self {
        Self {
            locations: CandidateLocations::Dense {
                range: 0..memory.len(),
                step: size,
            },
            memory,
            value_size: size,
        }
    }

    /// Perform a re-scan and keep only those values matching the predicate known at compile-time.
    ///
    /// Return the previous memory buffer.
    ///
    /// Panics when the [`Predicate::SIZE`] does not match the size of the values previously-used.
    /// It also panics if the input memory size does not match the size of the previous snapshot.
    ///
    /// ```compile_fail,E0080
    /// # use memo::scanner::*;
    /// type Comparator = Either<Unchanged<u8>, Unchanged<u16>>;
    ///                                    ^^             ^^^ note the different sizes
    /// let mut scan = LiveScan::with_value_size(1, vec![1]);
    /// scan.keep::<Comparator>(vec![1]);
    /// ```
    pub fn keep<P: Predicate>(&mut self, memory: Vec<u8>) -> Vec<u8> {
        assert_eq!(self.memory.len(), memory.len());

        // We're trying to evaluate P::SIZE here, which will fail if the predicate is malformed.
        // This is part of the unsafe call below, because we must make sure this size makes sense.
        assert_eq!(self.value_size, P::SIZE);

        let self_memory_ptr = self.memory.as_ptr();
        self.locations.retain(|addr| {
            // SAFETY: the locations fall within bounds, adding value_size won't be OOB,
            // the trait implementor guarantees unaligned reads are supported, and any
            // bit-pattern is valid.
            unsafe { P::applicable(self_memory_ptr.add(addr), memory.as_ptr().add(addr)) }
        });
        self.locations.try_compact(self.value_size);

        mem::replace(&mut self.memory, memory)
    }

    /// Perform a re-scan and keep only those values which have not changed.
    ///
    /// Equivalent to calling [`Self::keep_with`] with a closure that checks for equality.
    pub fn keep_unchanged(&mut self, memory: Vec<u8>) -> Vec<u8> {
        self.keep_with(|a, b| a == b, memory)
    }

    /// Perform a re-scan and keep only those values which have changed.
    ///
    /// Equivalent to calling [`Self::keep_with`] with a closure that checks for inequality.
    pub fn keep_changed(&mut self, memory: Vec<u8>) -> Vec<u8> {
        self.keep_with(|a, b| a != b, memory)
    }

    /// Perform a re-scan and keep only those values for which the predicate returns `true`.
    ///
    /// The length of the slices passed to the predicate will equal the size of the values from the
    /// first scan.
    ///
    /// This is useful when it would be too tedious to define a new type and implement [`Predicate`]
    /// on it, or when a runtime value is needed (e.g., "keep values which were decreased by 5 units").
    ///
    /// Return the previous memory buffer.
    ///
    /// Panics if the input memory size does not match the size of the previous snapshot.
    pub fn keep_with<F>(&mut self, mut predicate: F, memory: Vec<u8>) -> Vec<u8>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        assert_eq!(self.memory.len(), memory.len());

        let self_memory = &self.memory;
        let value_size = self.value_size;
        self.locations.retain(|addr| {
            // SAFETY: the locations fall within bounds even after adding `value_size`.
            unsafe {
                predicate(
                    &self_memory.get_unchecked(addr..addr + value_size),
                    &memory.get_unchecked(addr..addr + value_size),
                )
            }
        });
        self.locations.try_compact(self.value_size);

        mem::replace(&mut self.memory, memory)
    }

    /// Finish the live scan, and reclaim the original memory buffer.
    pub fn finish(self) -> Vec<u8> {
        self.memory
    }

    pub fn locations(&self) -> &CandidateLocations {
        &self.locations
    }
}

macro_rules! impl_any_pred_for_ty {
    ($($ty:ty),*) => {
        $(
            // SAFETY: the SIZE accurately represents the size of the types being read.
            unsafe impl Predicate for Any<$ty> {
                const SIZE: usize = mem::size_of::<$ty>();

                // SAFETY: this method does not read memory.
                #[inline(always)]
                unsafe fn applicable(_old: *const u8, _new: *const u8) -> bool {
                    true
                }
            }
        )*
    };
}

macro_rules! impl_int_pred {
    ($comparer:ident<$ty:ty> using $cmp:tt) => {
        // SAFETY: the SIZE accurately represents the size of the types being read.
        unsafe impl Predicate for $comparer<$ty> {
            const SIZE: usize = mem::size_of::<$ty>();

            // SAFETY: unaligned reads are supported and any bit-pattern is valid for the type.
            #[inline(always)]
            unsafe fn applicable(old: *const u8, new: *const u8) -> bool {
                new.cast::<$ty>().read_unaligned() $cmp old.cast::<$ty>().read_unaligned()
            }
        }
    };
}

macro_rules! impl_pred_for_ints {
    ($($ty:ty),*) => {
        $(
            impl_int_pred!(Changed<$ty> using !=);
            impl_int_pred!(Unchanged<$ty> using ==);
            impl_int_pred!(Decreased<$ty> using <);
            impl_int_pred!(Increased<$ty> using >);
        )*
    };
}

macro_rules! impl_pred_for_floats {
    ($($ty:ty : $int_ty:ty),*) => {
        $(
            impl_float_pred!(Changed<$ty: $int_ty> using !=);
            impl_float_pred!(Unchanged<$ty: $int_ty> using ==);
            impl_int_pred!(Decreased<$ty> using <);
            impl_int_pred!(Increased<$ty> using >);
        )*
    };
}

macro_rules! impl_float_pred {
    ( $( $comparer:ident<$ty:ty : $int_ty:ty> using $cmp:tt ),* ) => {
        $(
            /// This implementation checks for a close-enough value, not an exact bit-pattern.
            // SAFETY: the SIZE accurately represents the size of the types being read.
            unsafe impl Predicate for $comparer<$ty> {
                const SIZE: usize = mem::size_of::<$ty>();

                // SAFETY: unaligned reads are supported and any bit-pattern is valid for the type.
                #[inline]
                unsafe fn applicable(old: *const u8, new: *const u8) -> bool {
                    const MASK: $int_ty = !((1 << (<$ty>::MANTISSA_DIGITS / 2)) - 1);

                    let lhs = old.cast::<$ty>().read_unaligned();
                    let rhs = new.cast::<$ty>().read_unaligned();
                    let lhs = <$ty>::from_bits(lhs.to_bits() & MASK);
                    let rhs = <$ty>::from_bits(rhs.to_bits() & MASK);
                    lhs $cmp rhs
                }
            }
        )*
    };
}

impl_any_pred_for_ty!(i8, u8, i16, u16, i32, u32, i64, u64, isize, usize, f32, f64);
impl_pred_for_ints!(i8, u8, i16, u16, i32, u32, i64, u64, isize, usize);
impl_pred_for_floats!(f32: u32, f64: u64);

// SAFETY: the SIZE accurately represents the size of the types being read.
unsafe impl<P, Q> Predicate for Either<P, Q>
where
    P: Predicate,
    Q: Predicate,
{
    // If P::SIZE were to be different to Q::SIZE, this would panic at compile-time.
    const SIZE: usize = [P::SIZE][(P::SIZE != Q::SIZE) as usize];

    // SAFETY: unaligned reads are supported and any bit-pattern is valid for the type.
    #[inline(always)]
    unsafe fn applicable(old: *const u8, new: *const u8) -> bool {
        P::applicable(old, new) || Q::applicable(old, new)
    }
}

// SAFETY: the SIZE accurately represents the size of the types being read.
unsafe impl<P, Q> Predicate for Both<P, Q>
where
    P: Predicate,
    Q: Predicate,
{
    // If P::SIZE were to be different to Q::SIZE, this would panic at compile-time.
    const SIZE: usize = [P::SIZE][(P::SIZE != Q::SIZE) as usize];

    // SAFETY: unaligned reads are supported and any bit-pattern is valid for the type.
    #[inline(always)]
    unsafe fn applicable(old: *const u8, new: *const u8) -> bool {
        assert_eq!(P::SIZE, Q::SIZE);
        P::applicable(old, new) && Q::applicable(old, new)
    }
}

// SAFETY: the SIZE accurately represents the size of the types being read.
unsafe impl<P, Q> Predicate for Chain<P, Q>
where
    P: Predicate,
    Q: Predicate,
{
    const SIZE: usize = P::SIZE + Q::SIZE;

    // SAFETY: unaligned reads are supported and any bit-pattern is valid for the type.
    #[inline(always)]
    unsafe fn applicable(old: *const u8, new: *const u8) -> bool {
        P::applicable(old, new) && Q::applicable(old.add(P::SIZE), new.add(P::SIZE))
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
        assert!(unsafe { Unchanged::<f32>::applicable(lhs.as_ptr(), rhs.as_ptr()) });
    }

    #[test]
    fn len_is_accurate() {
        let loc = CandidateLocations::Discrete {
            locations: vec![1, 2, 3, 4],
        };
        assert_eq!(loc.len(), loc.iter().count());

        let loc = CandidateLocations::SmallDiscrete {
            base: 0,
            offsets: vec![1, 2, 3, 4],
        };
        assert_eq!(loc.len(), loc.iter().count());

        let loc = CandidateLocations::Dense {
            range: 0..4,
            step: 2,
        };
        assert_eq!(loc.len(), loc.iter().count());

        let loc = CandidateLocations::Sparse {
            base: 0,
            mask: vec![true, false],
            scale: 2,
        };
        assert_eq!(loc.len(), loc.iter().count());
    }

    #[test]
    fn chain() {
        type Comparer = Chain<Increased<i8>, Increased<i8>>;

        let mut scan = LiveScan::with_value_size(2, vec![1, 2]);
        assert_eq!(scan.locations().len(), 1);

        scan.keep::<Comparer>(vec![2, 3]);
        assert_eq!(scan.locations().len(), 1);

        scan.keep::<Comparer>(vec![1, 2]);
        assert_eq!(scan.locations().len(), 0);
    }

    #[test]
    fn complex_predicate() {
        type Comparer =
            Either<Chain<Unchanged<i8>, Unchanged<i8>>, Chain<Increased<i8>, Decreased<i8>>>;

        let mut scan = LiveScan::with_value_size(2, vec![4, 6]);
        assert_eq!(scan.locations().len(), 1);

        scan.keep::<Comparer>(vec![4, 6]);
        assert_eq!(scan.locations().len(), 1);

        scan.keep::<Comparer>(vec![5, 5]);
        assert_eq!(scan.locations().len(), 1);

        scan.keep::<Comparer>(vec![4, 6]);
        assert_eq!(scan.locations().len(), 0);
    }

    #[test]
    fn compact_uncompactable() {
        // Dense
        let mut locations = CandidateLocations::Dense {
            range: 0x2000..0x2100,
            step: 4,
        };
        locations.try_compact(4);
        assert!(matches!(locations, CandidateLocations::Dense { .. }));

        // Already compacted
        let mut locations = CandidateLocations::SmallDiscrete {
            base: 0x2000,
            offsets: vec![0, 0x20, 0x40],
        };
        locations.try_compact(4);
        assert!(matches!(
            locations,
            CandidateLocations::SmallDiscrete { .. }
        ));

        let mut locations = CandidateLocations::Sparse {
            base: 0x2000,
            mask: vec![true, false, false, false],
            scale: 4,
        };
        locations.try_compact(4);
        assert!(matches!(locations, CandidateLocations::Sparse { .. }));
    }

    #[test]
    fn compact_not_worth() {
        // Too small
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000],
        };
        let original = locations.clone();
        locations.try_compact(4);
        assert_eq!(locations, original);

        // Too sparse and too large to fit in `SmallDiscrete`.
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000, 0x42000],
        };
        let original = locations.clone();
        locations.try_compact(4);
        assert_eq!(locations, original);
    }

    #[test]
    fn compact_small_discrete() {
        let mut locations = CandidateLocations::Discrete {
            locations: vec![0x2000, 0x2004, 0x2040],
        };
        locations.try_compact(4);
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
        locations.try_compact(4);
        assert_eq!(
            locations,
            CandidateLocations::Sparse {
                base: 0x2000,
                mask: vec![true, true, false, true, true, true, true, true],
                scale: 4,
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
            step: 4,
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
            scale: 4,
        };
        assert_eq!(
            locations.iter().collect::<Vec<_>>(),
            vec![0x2000, 0x2004, 0x200c]
        );
    }
}
