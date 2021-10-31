use crate::ui;

use memo::ffi::{Process, Region};
use memo::Scan;
use std::mem;

pub fn solve(process: Process, regions: Vec<Region>) {
    let life = ui::prompt::<i32>("Enter initial life value: ").unwrap();

    let mut scan = Scan {
        size: mem::size_of::<i32>(),
        stride: mem::size_of::<i32>(),
        predicate: |v| life.to_le_bytes() == v,
    }
    .run_on_process(&process, regions.iter().cloned())
    .unwrap();
    println!("Found {} locations", scan.locations().len());

    while let Ok(life) = ui::prompt::<i32>("Enter new value (or invalid to stop): ") {
        scan.keep_with(|_old, new| life.to_le_bytes() == new);
        println!("Now have {} locations", scan.locations().len());
        if scan.locations().len() <= 1 {
            break;
        }
    }

    let life = ui::prompt::<i32>("Enter new life value: ").unwrap();
    for addr in scan.locations().iter() {
        process.write_memory_all(addr, &life.to_le_bytes()).unwrap();
    }

    println!("Done!");
}
