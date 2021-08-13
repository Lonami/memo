use crate::Process;
use std::collections::{BinaryHeap, HashSet};
use std::convert::TryInto;
use std::mem;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

const MAX_OFFSET: usize = 0x400;

define_serdes! {
    #[derive(Clone, Debug, PartialEq)]
    pub struct Block {
        pub real_addr: usize,
        pub mem_offset: usize,
        pub len: usize,
        pub base: bool,
    }
}

define_serdes! {
    #[derive(Clone, Debug, Default, PartialEq)]
    pub struct Snapshot {
        pub memory: Vec<u8>,
        pub blocks: Vec<Block>,
        // Has the same length as `blocks`. A given index represents that the
        // block at this index (very likely) is pointed-to from pointer-values
        // in the blocks in the child indices.
        //
        // For example, if `map[4] = [1, 4, 7]`, then all of `blocks[1]`,
        // `blocks[4]` and `blocks[7]` have aligned pointer-values in their
        // corresponding memory that point into `blocks[4]`.
        pub block_idx_pointed_from: Vec<Vec<usize>>,
    }
}

pub fn prepare_optimized_scan(snap: &mut Snapshot) {
    let mut block_idx_pointed_from = (0..snap.blocks.len())
        .map(|_| HashSet::new())
        .collect::<Vec<_>>();

    // SAFETY: we need the 'static lifetime for the threads, but they're not actually used for the
    // 'static lifetime, because we make sure to join them before.
    let (snap_ref, bipf_tail) = unsafe {
        (
            mem::transmute::<&'_ _, &'static _>(snap),
            mem::transmute::<&'_ mut _, &'static mut [_]>(block_idx_pointed_from.as_mut_slice()),
        )
    };

    // Split the workload of filling `block_idx_pointed_from` by making multiple chunks and
    // filling each of them on its own thread.
    let chunk_size = block_idx_pointed_from.len() / 4;
    let (bipf_a, bipf_tail) = bipf_tail.split_at_mut(chunk_size);
    let (bipf_b, bipf_tail) = bipf_tail.split_at_mut(chunk_size);
    let (bipf_c, bipf_tail) = bipf_tail.split_at_mut(chunk_size);

    fn fill_map(snap: &Snapshot, block_map: &mut [HashSet<usize>], offset: usize) {
        // For each block...
        for (i, block) in snap
            .blocks
            .iter()
            .skip(offset)
            .take(block_map.len())
            .enumerate()
        {
            // ...scan all the pointer-values...
            for (ra, pv) in snap.iter_all_addr() {
                // ...and if any of the pointer-values points inside this block...
                if let Some(delta) = pv.checked_sub(block.real_addr) {
                    if delta < block.len {
                        // ...then we know that the block with this pointer-value points to our original block.
                        block_map[i].insert(snap.get_block_idx(ra));
                    }
                }
            }
        }
    }

    let threads = [
        thread::spawn(move || fill_map(snap_ref, bipf_a, chunk_size * 0)),
        thread::spawn(move || fill_map(snap_ref, bipf_b, chunk_size * 1)),
        thread::spawn(move || fill_map(snap_ref, bipf_c, chunk_size * 2)),
    ];
    fill_map(snap_ref, bipf_tail, chunk_size * 3);

    for thread in threads {
        // Ignore errors or else threads could actually refer to the 'static references after drop.
        drop(thread.join());
    }

    // Convert set into a sorted vector.
    snap.block_idx_pointed_from = block_idx_pointed_from
        .into_iter()
        .map(|set| {
            let mut vec = set.into_iter().collect::<Vec<_>>();
            // TODO would it help to sort by "closest block" first?
            // and stop scanning after a match in any block is found?
            vec.sort();
            vec
        })
        .collect::<Vec<_>>();
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
            .collect::<Vec<_>>();

        // Without running the "optimization", we have to assume every block
        // can point to any other block (such `block_map` is cloned for every
        // block index).
        let block_map = (0..blocks.len()).collect::<Vec<_>>();
        let block_idx_pointed_from = (0..blocks.len())
            .map(|_| block_map.clone())
            .collect::<Vec<_>>();

        Self {
            memory,
            blocks,
            block_idx_pointed_from,
        }
    }

    pub fn read_memory(&self, addr: usize, n: usize) -> Option<&[u8]> {
        let block = &self.blocks[self.get_block_idx(addr)];
        let delta = addr - block.real_addr;
        if delta + n > block.len {
            None
        } else {
            let offset = block.mem_offset + delta;
            Some(&self.memory[offset..offset + n])
        }
    }

    pub fn get_block_idx(&self, addr: usize) -> usize {
        match self.blocks.binary_search_by_key(&addr, |b| b.real_addr) {
            Ok(index) => index,
            Err(index) => index - 1,
        }
    }

    // Iterate over (memory address, pointer value at said address).
    pub fn iter_addr(&self, from_addr: usize, base: bool) -> AddrIter {
        let block_idx = self.get_block_idx(from_addr);
        let block_map = self.block_idx_pointed_from[block_idx].as_slice();
        let block = block_map.get(0).map(|i| &self.blocks[*i]);
        AddrIter {
            block,
            memory: self.memory.as_slice(),
            block_offset: 0,
            blocks: self.blocks.as_slice(),
            block_map,
            block_map_idx: NonZeroUsize::new(1).unwrap(),
            base,
        }
    }

    pub fn iter_all_addr(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
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

pub struct AddrIter<'a> {
    // Current block.
    block: Option<&'a Block>,
    // All the memory.
    memory: &'a [u8],
    // Offset within a block.
    block_offset: usize,
    // All blocks.
    blocks: &'a [Block],
    // Map of indices for the block indices we'll check.
    block_map: &'a [usize],
    // Current index. Starts at one because `block` is pre-initialized to the zeroth element.
    block_map_idx: NonZeroUsize,
    // The `base` value of the block an address corresponds to for it to be yielded.
    base: bool,
}

impl<'a> Iterator for AddrIter<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let mut block = self.block?;
        if self.block_offset >= block.len {
            loop {
                // Roll over to the next block.
                self.block = self
                    .block_map
                    .get(self.block_map_idx.get())
                    .map(|i| &self.blocks[*i]);
                block = self.block?;
                self.block_map_idx = NonZeroUsize::new(self.block_map_idx.get() + 1).unwrap();

                if block.base == self.base {
                    break;
                } else {
                    continue;
                }
            }

            self.block_offset = 0;
        }

        // TODO very inefficient
        let chunk = &self.memory
            [block.mem_offset + self.block_offset..block.mem_offset + self.block_offset + 8];
        self.block_offset += 8;

        Some((
            block.real_addr + self.block_offset - 8,
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
    /// Used to lock on `new_work` when empty.
    work_cvar: Condvar,
    /// How many threads are working right now.
    /// Once there is no work and nobody is working, exit, as there won't ever be more work.
    working_now: AtomicU8,
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

        self.second_snap
            .iter_addr(future_node.second_addr, true)
            .filter(|(_sra, spv)| {
                if let Some(offset) = future_node.second_addr.checked_sub(*spv) {
                    offset <= MAX_OFFSET
                } else {
                    false
                }
            })
            .for_each(|(sra, _spv)| {
                let mut nodes_walked = self.nodes_walked.lock().unwrap();
                self.good_finds.lock().unwrap().push(nodes_walked.len());
                nodes_walked.push(CandidateNode {
                    parent: future_node.node_idx,
                    addr: sra,
                });
            });

        if future_node.depth != 0 {
            self.second_snap
                .iter_addr(future_node.second_addr, false)
                .filter(|(_sra, spv)| {
                    if let Some(offset) = future_node.second_addr.checked_sub(*spv) {
                        offset <= MAX_OFFSET
                    } else {
                        false
                    }
                })
                .for_each(|(sra, spv)| {
                    let offset = future_node.second_addr - spv;
                    let first_addr = future_node.first_addr - offset;
                    for (fra, fpv) in self.first_snap.iter_addr(future_node.first_addr, false) {
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
                        self.work_cvar.notify_one();
                        nodes_walked.push(CandidateNode {
                            parent: future_node.node_idx,
                            addr: sra,
                        });
                    }
                })
        }

        if self.working_now.fetch_sub(1, Ordering::SeqCst) == 1 {
            // We were the last thread working, and now nobody is, so wake everyone up.
            // There's probably no more work left to do, so we're done.
            self.work_cvar.notify_all();
        }

        true
    }
}
