use crate::Snapshot;

use std::collections::BinaryHeap;
use std::convert::TryInto;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

#[derive(Debug)]
pub struct PointerPathFinder {
    pub snap_a: Snapshot,
    pub addr_a: usize,
    pub snap_b: Snapshot,
    pub addr_b: usize,
    /// The maximum offset value allowed in a path.
    pub max_offset: usize,
    /// The maximum path length.
    pub max_length: u8,
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

/// A "path finder worker", implemented based on a queue.
///
/// You can obtain an instance of this structure through [`PointerPathFinder::init`],
/// and are free to `Arc`-wrap it in order to perform concurrent work (recommended).
#[derive(Debug)]
pub struct QueuePathFinder {
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
    /// How far off a pointer-value can be from the address being searched before not being valid.
    /// Essentially, the maximum delta allowed between an address and scanned pointer-values.
    max_offset: usize,
    /// How long can a path be.
    max_depth: u8,
    /// Stored in order to reconstruct [`PointerPathFinder::addr_a`] even if no paths are found.
    first_addr: usize,
}

impl PointerPathFinder {
    /// Initialize a worker structure which can carry the path finding process.
    pub fn init(self) -> QueuePathFinder {
        QueuePathFinder {
            first_snap: self.snap_a,
            second_snap: self.snap_b,
            good_finds: Mutex::new(Vec::new()),
            nodes_walked: Mutex::new(vec![CandidateNode {
                parent: 0,
                addr: self.addr_b,
            }]),
            new_work: {
                let mut new_work = BinaryHeap::new();
                new_work.push(FutureNode {
                    node_idx: 0,
                    first_addr: self.addr_a,
                    second_addr: self.addr_b,
                    depth: self.max_length,
                });
                Mutex::new(new_work)
            },
            work_cvar: Condvar::new(),
            working_now: AtomicU8::new(0),
            max_offset: self.max_offset,
            max_depth: self.max_length,
            first_addr: self.addr_a,
        }
    }

    /// Execute the path finding process.
    ///
    /// `extra_threads` will be spawned to help speed up the optimization process.
    pub fn execute_with_threads(self, extra_threads: usize) -> (Self, Vec<Vec<usize>>) {
        let worker = Arc::new(self.init());
        let threads = (0..extra_threads)
            .map(|_| {
                let dupe_worker = Arc::clone(&worker);
                thread::spawn(move || dupe_worker.work())
            })
            .collect::<Vec<_>>();

        worker.work();
        threads.into_iter().for_each(|t| t.join().unwrap());
        Arc::try_unwrap(worker).unwrap().finish()
    }
}

impl QueuePathFinder {
    /// Perform a single step in finding new paths.
    ///
    /// A single step may can find zero or more candidate path nodes to explore, and can also find
    /// zero or more good paths.
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
            .filter(|(_sra, spv)| future_node.second_addr.wrapping_sub(*spv) <= self.max_offset)
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
                .filter(|(_sra, spv)| future_node.second_addr.wrapping_sub(*spv) <= self.max_offset)
                .for_each(|(sra, spv)| {
                    let offset = future_node.second_addr - spv;
                    let first_addr = future_node.first_addr - offset;
                    self.first_snap
                        .iter_addr(future_node.first_addr, false)
                        .filter(|(_fra, fpv)| *fpv == first_addr)
                        .for_each(|(fra, _fpv)| {
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
                        });
                })
        }

        if self.working_now.fetch_sub(1, Ordering::SeqCst) == 1 {
            // We were the last thread working, and now nobody is, so wake everyone up.
            // There's probably no more work left to do, so we're done.
            self.work_cvar.notify_all();
        }

        true
    }

    /// Begin working on finding the pointer paths, until there's no more work left.
    pub fn work(&self) {
        while self.step() {}
    }

    /// Return how many paths have been found so far.
    pub fn paths_found(&self) -> usize {
        self.good_finds.lock().unwrap().len()
    }

    /// Return how many candidate path nodes have been found so far.
    pub fn scanned_node_count(&self) -> usize {
        self.nodes_walked.lock().unwrap().len()
    }

    /// Finish the finding job.
    ///
    /// The return value includes a vector with the vectors of valid offsets.
    pub fn finish(self) -> (PointerPathFinder, Vec<Vec<usize>>) {
        let QueuePathFinder {
            first_snap,
            second_snap,
            good_finds,
            nodes_walked,
            max_offset,
            max_depth,
            first_addr,
            ..
        } = self;

        let good_finds = good_finds.into_inner().unwrap();
        let nodes_walked = nodes_walked.into_inner().unwrap();

        let paths = good_finds
            .into_iter()
            .map(|mut node_idx| {
                let mut addresses = Vec::with_capacity((max_depth + 1) as usize);
                // Walk the linked list.
                loop {
                    let node = &nodes_walked[node_idx];
                    addresses.push(node.addr);
                    // A node whose parent is itself represents the end.
                    // This is similar to trying to `cd ..` when already at `/`.
                    if node_idx == node.parent {
                        break;
                    } else {
                        node_idx = node.parent;
                    }
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
            .collect();

        (
            PointerPathFinder {
                snap_a: first_snap,
                addr_a: first_addr,
                snap_b: second_snap,
                addr_b: nodes_walked[0].addr,
                max_offset: max_offset,
                max_length: max_depth,
            },
            paths,
        )
    }
}
