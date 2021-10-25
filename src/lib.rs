pub mod ffi;
pub mod scanner;

pub use ffi::debug::{debug_process, DebugToken};
pub use ffi::module::Module;
pub use ffi::process::{list_processes, Process};
pub use ffi::region::Region;
pub use ffi::thread::{iter_threads, Breakpoint, Thread};

pub use scanner::pointer_path::find_pointer_paths;
pub use scanner::scan::{
    Both, CandidateLocations, Chain, Changed, Decreased, Either, Increased, LiveScan, Predicate,
    Scan, Unchanged,
};
pub use scanner::snapshot::{take_memory_snapshot, Snapshot};
