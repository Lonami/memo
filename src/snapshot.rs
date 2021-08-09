use crate::Process;
use std::collections::BinaryHeap;
use std::convert::TryInto;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

const MAX_OFFSET: usize = 0x400;

use serde::{Deserialize, Serialize};

define_serdes! {
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Block {
        real_addr: usize,
        mem_offset: usize,
        len: usize,
        base: bool,
    }
}

define_serdes! {
    #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
    pub struct Snapshot {
        pub memory: Vec<u8>,
        pub blocks: Vec<Block>,
    }
}

// Returns a vector with the vectors of valid offsets.
pub fn find_pointer_paths(
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

            // A parent pointing to itself represents the end.
            // This is similar to trying to `cd ..` when already at `/`.
            while node.parent != nodes_walked[node.parent].parent {
                node = nodes_walked[node.parent].clone();
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

            /*
            The reverse operation (in pseudo-code) would be:
                base = base addr
                for offset in offsets[..-1] {
                    base = [base + offset]
                }
                value = [base + offsets[-1]]
            */

            offsets
        })
        .collect()
}

// For some reason, the free-standing function seems to be faster than putting
// it inside the `impl`, or else the runtime is increased from ~360ms to ~410ms.
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
        AddrIter {
            blocks: self.blocks.as_slice(),
            memory: self.memory.as_slice(),
            offset: 0,
        }
    }
}

// A naive custom iterator (storing snapshot, block index and memory offset)
// increases the runtime from ~360ms to ~890ms. However, a somewhat smarter
// one (such as this one) decreases it from ~360ms to ~340ms.
pub struct AddrIter<'a> {
    blocks: &'a [Block],
    memory: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for AddrIter<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.memory.is_empty() {
            return None;
        }

        if self.offset >= self.blocks[0].mem_offset + self.blocks[0].len {
            // Roll over to the next block.
            self.blocks = &self.blocks[1..];
        }

        // Updating chunk and memory before the `if` check above increases
        // runtime from ~300ms to ~350ms.
        let chunk = &self.memory[..8];
        self.memory = &self.memory[8..];
        self.offset += 8;

        Some((
            self.blocks[0].real_addr + (self.offset - 8 - self.blocks[0].mem_offset),
            usize::from_ne_bytes(chunk.try_into().unwrap()),
        ))
    }
}

#[derive(Clone, Debug)]
struct CandidateNode {
    parent: usize,
    addr: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FutureNode {
    // Changing the depth for an `usize` increases runtime from ~300ms to ~420ms.
    depth: u8,
    // Changing the node index for an `u32` increases runtime from ~300ms to ~360ms.
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
    /// Used to lock on `new_work` when empty.
    work_cvar: Condvar,
    /// How many threads are working right now.
    /// Once there is no work and nobody is working, exit, as there won't ever be more work.
    working_now: AtomicU8,
    // Adding another `usize` here would increase the runtime from ~300ms to ~420ms.
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
                parent: 0,
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
            work_cvar: Condvar::new(),
            working_now: AtomicU8::new(0),
        }
    }
}

impl QueuePathFinder {
    // Changing `step` into a `run` with a `loop` that simply returns
    // when done increases the runtime from ~360ms to ~410ms.
    //
    // On the tests, this method is "only" called 34 times!
    pub fn step(&self) -> bool {
        let future_node = {
            let mut new_work = self.new_work.lock().unwrap();
            loop {
                if let Some(future_node) = new_work.pop() {
                    // We're now working. It's MANDATORY we decrement this later.
                    self.working_now.fetch_add(1, Ordering::SeqCst);
                    break future_node;
                } else if self.working_now.load(Ordering::SeqCst) == 0 {
                    // Once there is no work left AND nobody else is working, we're done.
                    return false;
                } else {
                    // Wait on `new_work` to be updated.
                    new_work = self.work_cvar.wait(new_work).unwrap();
                }
            }
        };

        // Moving the `filter` inside the loop and changing it with `continue`
        // worsens the performance. Also, using internal iteration `for_each`
        // runtime is also increased (either in the outer or inner loop).
        for (sra, spv) in self.second_snap.iter_addr().filter(|(_sra, spv)| {
            // Changing this for a `wrapping_sub` increases runtime from ~300ms to ~480ms.
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
                    parent: future_node.node_idx,
                    addr: sra,
                });
                continue;
            }
            // This check doesn't run a lot. Hoisting it and duplicating the code that checks for
            // base addreses increases the runtime from ~500ms to ~600ms.
            if future_node.depth == 0 {
                continue;
            }

            let offset = future_node.second_addr - spv;
            // Optimization: (fpv + offset = fra) -> (fpv = fra - offset).
            // This used to worsen performance by ~50ms, but without `filter`,
            // it actually improves it by ~20ms.
            let first_addr = future_node.first_addr - offset;
            for (fra, fpv) in self.first_snap.iter_addr() {
                if fpv != first_addr {
                    continue;
                }

                let mut nodes_walked = self.nodes_walked.lock().unwrap();
                self.new_work.lock().unwrap().push(FutureNode {
                    node_idx: nodes_walked.len(),
                    first_addr: fra,
                    second_addr: sra,
                    depth: future_node.depth - 1,
                });
                // Removing this line and placing an unconditional `notify_all` after
                // `working_now -= 1` instead increases the runtime from ~500ms to ~650ms.
                self.work_cvar.notify_one();
                nodes_walked.push(CandidateNode {
                    parent: future_node.node_idx,
                    addr: sra,
                });
            }
        }

        if self.working_now.fetch_sub(1, Ordering::SeqCst) == 1 {
            // We were the last thread working, and now nobody is, so wake everyone up.
            // There's probably no more work left to do, so we're done.
            self.work_cvar.notify_all();
        }

        true
    }
}
