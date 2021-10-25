//! Utility module to scan memory for values or pointer paths.
pub mod pointer_path;
pub mod scan;
pub mod snapshot;

pub use pointer_path::PointerPathFinder;
pub use scan::{
    Both, CandidateLocations, Chain, Changed, Decreased, Either, Increased, LiveScan, Predicate,
    Scan, Unchanged,
};
pub use snapshot::{take_memory_snapshot, Snapshot};
