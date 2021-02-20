/// A scan type.
///
/// The variant determines how a memory scan should be performed.
pub enum Scan {
    /// Perform an exact memory scan.
    /// Only memory locations containing this exact value will be considered.
    Exact(i32),
}
