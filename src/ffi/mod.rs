//! Abstract over the Windows API to provide a more convenient interface.
pub mod debug;
pub mod module;
pub mod process;
pub mod region;
pub mod thread;

pub use debug::{debug_process, DebugToken};
pub use module::Module;
pub use process::{list_processes, Process};
pub use region::Region;
pub use thread::{iter_threads, Breakpoint, Thread};
