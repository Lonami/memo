use std::ops::Range;

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
}

/// Candidate memory locations for holding our desired value.
pub enum CandidateLocations {
    /// Multiple, separated locations.
    Discrete { locations: Vec<usize> },
    ///
    Dense { range: Range<usize> },
}

/// A value found in memory.
pub enum Value {
    /// All the values exactly matched this at the time of the scan.
    Exact(i32),
    /// The value is not known, so anything represented within this chunk must be considered.
    AnyWithin(Vec<u8>),
}

/// A memory region.
pub struct Region {
    ///
    pub info: winapi::um::winnt::MEMORY_BASIC_INFORMATION,
    pub locations: CandidateLocations,
    pub value: Value,
}

impl CandidateLocations {
    pub fn len(&self) -> usize {
        match self {
            CandidateLocations::Discrete { locations } => locations.len(),
            CandidateLocations::Dense { range } => range.len(),
        }
    }
}
