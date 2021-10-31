use memo::ffi::{Process, Region};

pub fn solve(process: Process, _regions: Vec<Region>) {
    const PROCESS_NAME: &str = "Tutorial";

    assert_eq!(
        PROCESS_NAME,
        process
            .base_module()
            .unwrap()
            .truncated_name(PROCESS_NAME.len())
            .unwrap()
    );

    println!("Success! You've opened a Tutorial executable!");
}
