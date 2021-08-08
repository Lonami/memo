use crate::Process;
use std::collections::BinaryHeap;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::thread;

const MAX_OFFSET: usize = 0x400;

use serde::{Serialize, Deserialize};

#[derive(Clone, Debug)]
#[derive(Serialize, Deserialize)]
struct Block {
    real_addr: usize,
    mem_offset: usize,
    len: usize,
    base: bool,
}

#[derive(Clone, Debug, Default)]
#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    memory: Vec<u8>,
    blocks: Vec<Block>,
}

struct PathFinder {
    first_snap: Snapshot,
    second_snap: Snapshot,
    addresses: std::cell::Cell<Vec<(bool, u8, usize)>>,
}

// Returns a vector with the vectors of valid offsets.
pub fn find_pointer_paths(
    first_snap: Snapshot,
    first_addr: usize,
    second_snap: Snapshot,
    second_addr: usize,
) -> Vec<Vec<usize>> {
    const TOP_DEPTH: u8 = 7;
    let pf = PathFinder {
        first_snap,
        second_snap,
        addresses: std::cell::Cell::new(Vec::new()),
    };
    pf.run(first_addr, second_addr, TOP_DEPTH);

    let mut offsets = Vec::new();

    for (base, depth, addr) in pf.addresses.into_inner() {
        if base {
            // Abuse capacity to determine which depths have been filled in.
            offsets.push(Vec::with_capacity((TOP_DEPTH - depth + 1) as usize));
        }

        for offs in offsets.iter_mut() {
            let desired_depth = TOP_DEPTH - (offs.capacity() - offs.len()) as u8 + 1;
            if depth == desired_depth {
                offs.push(addr);
            }
        }
    }

    for offs in offsets.iter_mut() {
        // The top-most address wasn't pushed. Push it now.
        offs.push(second_addr);

        // `slice::windows_mut` isn't a thing, so use a good ol' loop.
        for i in (1..offs.len()).rev() {
            let ptr_value = usize::from_ne_bytes(
                pf.second_snap
                    .read_memory(offs[i - 1], std::mem::size_of::<usize>())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            offs[i] -= ptr_value;
        }
    }

    /*
    The reverse operation (in pseudo-code) would be:
        base = base addr
        for offset in offsets[..-1] {
            base = [base + offset]
        }
        value = [base + offsets[-1]]
    */

    offsets
}

// Returns a vector with the vectors of valid offsets.
pub fn queued_find_pointer_paths(
    first_snap: Snapshot,
    first_addr: usize,
    second_snap: Snapshot,
    second_addr: usize,
) -> Vec<Vec<usize>> {
    const TOP_DEPTH: u8 = 7;

    let qpf = Arc::new(
        QueuePathFinderBuilder {
            first_snap,
            first_addr,
            second_snap,
            second_addr,
            depth: TOP_DEPTH,
        }
        .finish(),
    );

    let threads = [
        thread::spawn({
            let qpf = Arc::clone(&qpf);
            || run_find_pointer_paths(qpf)
        }),
        thread::spawn({
            let qpf = Arc::clone(&qpf);
            || run_find_pointer_paths(qpf)
        }),
        thread::spawn({
            let qpf = Arc::clone(&qpf);
            || run_find_pointer_paths(qpf)
        }),
    ];

    run_find_pointer_paths(Arc::clone(&qpf));
    for thread in threads {
        thread.join().unwrap();
    }

    let qpf = Arc::try_unwrap(qpf).unwrap();

    let second_snap = qpf.second_snap;
    let good_finds = qpf.good_finds.into_inner().unwrap();
    let nodes_walked = qpf.nodes_walked.into_inner().unwrap();

    good_finds
        .into_iter()
        .map(|node_idx| {
            let mut addresses = Vec::with_capacity((TOP_DEPTH + 1) as usize);
            // Walk the linked list.
            let mut node = nodes_walked[node_idx].clone();
            addresses.push(node.addr);
            while let Some(node_idx) = node.parent {
                node = nodes_walked[node_idx].clone();
                addresses.push(node.addr);
            }

            // Now update the list of addresses to turn them into offsets.
            let mut offsets = addresses;
            for i in (1..offsets.len()).rev() {
                let ptr_value = usize::from_ne_bytes(
                    second_snap
                        .read_memory(offsets[i - 1], std::mem::size_of::<usize>())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                );
                offsets[i] -= ptr_value;
            }

            offsets
        })
        .collect()
}

fn run_find_pointer_paths(qpf: Arc<QueuePathFinder>) {
    while qpf.step() {}
}

impl Snapshot {
    pub fn new(process: &Process, regions: &[winapi::um::winnt::MEMORY_BASIC_INFORMATION]) -> Self {
        let modules = process.enum_modules().unwrap();
        let mut blocks = regions
            .iter()
            .map(|r| Block {
                real_addr: r.BaseAddress as usize,
                mem_offset: 0,
                len: r.RegionSize,
                base: modules.iter().any(|module| {
                    let base = r.AllocationBase as usize;
                    let addr = *module as usize;
                    base == addr
                }),
            })
            .collect::<Vec<_>>();

        blocks.sort_by_key(|b| b.real_addr);

        let mut memory = Vec::new();
        let blocks = blocks
            .into_iter()
            .filter_map(|b| match process.read_memory(b.real_addr, b.len) {
                Ok(mut chunk) => {
                    let len = chunk.len();
                    let mem_offset = memory.len();
                    memory.append(&mut chunk);
                    Some(Block {
                        real_addr: b.real_addr,
                        mem_offset,
                        len,
                        base: b.base,
                    })
                }
                Err(_) => None,
            })
            .collect();

        Self { memory, blocks }
    }

    pub fn read_memory(&self, addr: usize, n: usize) -> Option<&[u8]> {
        let index = match self.blocks.binary_search_by_key(&addr, |b| b.real_addr) {
            Ok(index) => index,
            Err(index) => index - 1,
        };

        let block = &self.blocks[index];
        let delta = addr - block.real_addr;
        if delta + n > block.len {
            None
        } else {
            let offset = block.mem_offset + delta;
            Some(&self.memory[offset..offset + n])
        }
    }

    pub fn is_base_addr(&self, addr: usize) -> bool {
        let index = match self.blocks.binary_search_by_key(&addr, |b| b.real_addr) {
            Ok(index) => index,
            Err(index) => index - 1,
        };
        self.blocks[index].base
    }

    // Iterate over (memory address, pointer value at said address)
    pub fn iter_addr(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        let mut blocks = self.blocks.iter().peekable();
        self.memory
            .chunks_exact(8)
            .enumerate()
            .map(move |(i, chunk)| {
                let mut block = *blocks.peek().unwrap();
                if i * 8 >= block.mem_offset + block.len {
                    // Roll over to the next block.
                    block = blocks.next().unwrap();
                }

                (
                    block.real_addr + (i * 8 - block.mem_offset),
                    usize::from_ne_bytes(chunk.try_into().unwrap()),
                )
            })
    }
}

impl PathFinder {
    fn run(&self, first_addr: usize, second_addr: usize, depth: u8) -> bool {
        // In the second snapshot, look for all pointer values where `ptr_value + offset = second_addr`
        // for all `offset in 0..=MAX_OFFSET`.
        //
        // For every `ptr_value` with a given `offset`, look EXACTLY for `first_addr - offset` in the
        // first snapshot. Once found, we have a candidate offset valid in both snapshots, and then we
        // can recurse to find subsequent offsets on the real addresses of these pointer values.
        //
        // F: first, S: second; RA: Real Address; PV: Pointer Value
        let depth = depth - 1;

        let mut any = false;
        for (sra, spv) in self.second_snap.iter_addr().filter(|(_sra, spv)| {
            if let Some(offset) = second_addr.checked_sub(*spv) {
                offset <= MAX_OFFSET
            } else {
                false
            }
        }) {
            if self.second_snap.is_base_addr(sra) {
                unsafe { &mut *self.addresses.as_ptr() }.push((true, depth + 1, sra));
                any = true;
                continue;
            }
            if depth == 0 {
                continue;
            }
            let offset = second_addr - spv;
            for (fra, _fpv) in self
                .first_snap
                .iter_addr()
                .filter(|(_fra, fpv)| fpv.wrapping_add(offset) == first_addr)
            {
                if self.run(fra, sra, depth) {
                    unsafe { &mut *self.addresses.as_ptr() }.push((false, depth + 1, sra));
                    any = true;
                }
            }
        }

        any
    }
}

#[derive(Clone, Debug)]
struct CandidateNode {
    parent: Option<usize>,
    addr: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FutureNode {
    depth: u8,
    node_idx: usize,
    first_addr: usize,
    second_addr: usize,
}

#[derive(Debug)]
struct QueuePathFinder {
    first_snap: Snapshot,
    second_snap: Snapshot,
    /// Indices of `nodes_walked` which are "good" (i.e. have reached a base address).
    good_finds: Mutex<Vec<usize>>,
    /// Shared "tree" of nodes we've walked over, so all threads can access and reference them.
    nodes_walked: Mutex<Vec<CandidateNode>>,
    /// Nodes to be used in the future, where the `node_idx` references `nodes_walked`.
    new_work: Mutex<BinaryHeap<FutureNode>>,
}

struct QueuePathFinderBuilder {
    first_snap: Snapshot,
    first_addr: usize,
    second_snap: Snapshot,
    second_addr: usize,
    depth: u8,
}

impl QueuePathFinderBuilder {
    pub fn finish(self) -> QueuePathFinder {
        QueuePathFinder {
            first_snap: self.first_snap,
            second_snap: self.second_snap,
            good_finds: Mutex::new(Vec::new()),
            nodes_walked: Mutex::new(vec![CandidateNode {
                parent: None,
                addr: self.second_addr,
            }]),
            new_work: {
                let mut new_work = BinaryHeap::new();
                new_work.push(FutureNode {
                    node_idx: 0,
                    first_addr: self.first_addr,
                    second_addr: self.second_addr,
                    depth: self.depth,
                });
                Mutex::new(new_work)
            },
        }
    }
}

impl QueuePathFinder {
    pub fn step(&self) -> bool {
        let future_node = {
            let mut new_work = self.new_work.lock().unwrap();
            if let Some(future_node) = new_work.pop() {
                future_node
            } else {
                println!("i'm done");
                return false;
            }
        };

        for (sra, spv) in self.second_snap.iter_addr().filter(|(_sra, spv)| {
            if let Some(offset) = future_node.second_addr.checked_sub(*spv) {
                offset <= MAX_OFFSET
            } else {
                false
            }
        }) {
            if self.second_snap.is_base_addr(sra) {
                let mut nodes_walked = self.nodes_walked.lock().unwrap();
                self.good_finds.lock().unwrap().push(nodes_walked.len());
                nodes_walked.push(CandidateNode {
                    parent: Some(future_node.node_idx),
                    addr: sra,
                });
                continue;
            }
            if future_node.depth == 0 {
                continue;
            }
            let offset = future_node.second_addr - spv;
            for (fra, _fpv) in self
                .first_snap
                .iter_addr()
                .filter(|(_fra, fpv)| fpv.wrapping_add(offset) == future_node.first_addr)
            {
                let mut nodes_walked = self.nodes_walked.lock().unwrap();
                self.new_work.lock().unwrap().push(FutureNode {
                    node_idx: nodes_walked.len(),
                    first_addr: fra,
                    second_addr: sra,
                    depth: future_node.depth - 1,
                });
                nodes_walked.push(CandidateNode {
                    parent: Some(future_node.node_idx),
                    addr: sra,
                });
            }
        }

        true
    }
}
