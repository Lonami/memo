use crate::ui;

use memo::ffi::{Process, Region};
use memo::Scan;
use std::convert::TryInto;
use std::mem;

pub fn solve(process: Process, regions: Vec<Region>) {
    let life = ui::prompt::<i32>("Enter maximum life value: ").unwrap();

    let mut scan = Scan {
        size: mem::size_of::<i32>(),
        stride: mem::size_of::<i32>(),
        predicate: |v| (0..=life).contains(&i32::from_le_bytes(v.try_into().unwrap())),
    }
    .run_on_process(&process, regions.iter().cloned())
    .unwrap();
    println!("Found {} locations", scan.locations().len());

    while let Ok(delta) = ui::prompt::<i32>("Enter decreased-by amount (or invalid to stop): ") {
        scan.keep_with(|old, new| {
            i32::from_le_bytes(old.try_into().unwrap())
                .wrapping_sub(i32::from_le_bytes(new.try_into().unwrap()))
                == delta
        });
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
