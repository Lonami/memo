use crate::ffi::{Process, Region};

use crate::SerDes;
use std::collections::HashSet;
use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::mem;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::thread;

/// How many bits to be used to index into the optimizer's memory map.
///
/// A megabyte worth seems to be a good amount.
const OPT_MEM_MAP_BITCOUNT: usize = 20;

/// How many of the low-order bits of a pointer-value to skip when indexing into the memory map.
///
/// A bit under half the bits used by an address (3 instead of all 8) seems to be a good amount.
const OPT_MEM_MAP_SHIFT: usize = 3 * mem::size_of::<usize>();

/// Mask used when indexing into the memory map.
const OPT_MEM_MAP_MASK: usize = (1 << OPT_MEM_MAP_BITCOUNT) - 1;

#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub real_addr: usize,
    pub mem_offset: usize,
    pub len: usize,
    pub base: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub memory: Vec<u8>,
    pub blocks: Vec<Block>,
    // A given key represents that the block at this key (very likely) is pointed-to from
    // pointer-values in the blocks in the child indices.
    //
    // For example, if `map[4] = [1, 4, 7]`, then all of `blocks[1]`, `blocks[4]` and
    // `blocks[7]` have aligned pointer-values in their corresponding memory that point into
    // `blocks[4]`.
    //
    // If an index is not present here as a key, it is considered to not be interesting.
    pub block_idx_pointed_from: Vec<Vec<usize>>,
}

#[derive(Debug)]
pub struct OptimizerWorker {
    snapshot: Snapshot,
    /// Memory map of every address condensed into a much smaller space.
    ///
    /// Used to quickly check whether a certain pointer-value may fall within a block.
    /// If it's definitely not within a block, finding the matching block can be skipped.
    mem_map: Vec<bool>,
    /// The memory region associated with block X is yet to be scanned.
    pending: Mutex<Vec<usize>>,
    /// The block at X.0 points to the blocks in X.1.
    done: Mutex<Vec<(usize, HashSet<usize>)>>,
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

/// Take a memory snapshot of the given regions of the process.
pub fn take_memory_snapshot<I>(process: &Process, regions: I) -> io::Result<Snapshot>
where
    I: IntoIterator<Item = Region>,
{
    let modules = process.list_modules()?;
    let mut blocks = regions
        .into_iter()
        .map(|r| Block {
            real_addr: r.addr(),
            mem_offset: 0,
            len: r.size(),
            base: modules.iter().any(|m| m.addr() == r.addr()),
        })
        .collect::<Vec<_>>();
    blocks.sort_by_key(|b| b.real_addr);

    let mut mem_offset = 0;
    let mut memory = vec![0; blocks.iter().map(|b| b.len).sum()];
    for block in blocks.iter_mut() {
        process.read_memory_exact(
            block.real_addr,
            &mut memory[mem_offset..mem_offset + block.len],
        )?;
        block.mem_offset = mem_offset;
        mem_offset += block.len;
    }

    // Without running the "optimization", we have to assume every block
    // can point to any other block (such `block_map` is cloned for every
    // block index).
    let block_map = (0..blocks.len()).collect::<Vec<_>>();
    let block_idx_pointed_from = (0..blocks.len()).map(|_| block_map.clone()).collect();

    Ok(Snapshot {
        memory,
        blocks,
        block_idx_pointed_from,
    })
}

impl Snapshot {
    /// Convert the snapshot into an [`OptimizerWorker`].
    ///
    /// After the optimizer runs, searching paths within this snapshot will be considerably faster.
    ///
    /// The optimizer can be cloned and executed from multiple threads at the same time.
    pub fn into_optimizer(self) -> OptimizerWorker {
        // This "bitmap" answers: should we bother looking for a possible block at this address?
        let mut should_bother = vec![false; 1 << OPT_MEM_MAP_BITCOUNT];
        for block in self.blocks.iter() {
            let start = block.real_addr >> OPT_MEM_MAP_SHIFT;
            // Add +1 to the count to also include this block's end,
            // and another +1 to account for "may be within, may not".
            let count = (block.len >> OPT_MEM_MAP_SHIFT) + 2;
            for addr in start..start + count {
                should_bother[addr & OPT_MEM_MAP_MASK] = true;
            }
        }

        OptimizerWorker {
            mem_map: should_bother,
            pending: Mutex::new((0..self.blocks.len()).collect::<Vec<_>>()),
            done: Mutex::new(Vec::new()),
            snapshot: self,
        }
    }

    /// Return an optimized version of self.
    ///
    /// `extra_threads` will be spawned to help speed up the optimization process.
    pub fn optimized_with_threads(self, extra_threads: usize) -> Self {
        let worker = Arc::new(self.into_optimizer());
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

    /// Iterate over `(memory address, pointer value at said address)`.
    ///
    /// Will not yield results if the address belongs to a block which was optimized away.
    pub fn iter_addr(&self, from_addr: usize, base: bool) -> AddrIter<'_> {
        let block_idx = self.get_block_idx(from_addr);
        let block_map = &self.block_idx_pointed_from[block_idx];

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

    fn iter_pointer_values(&self, block: usize) -> impl Iterator<Item = usize> + '_ {
        let block = &self.blocks[block];
        self.memory[block.mem_offset..block.mem_offset + block.len]
            .chunks_exact(8)
            .map(|chunk| usize::from_ne_bytes(chunk.try_into().unwrap()))
    }

    /// Serialize this snapshot into the given writer.
    ///
    /// Useful to save a snapshot for later analysis via [`Self::deserialize_from`].
    pub fn serialize_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.blocks.len().save(writer)?;
        for (i, block) in self.blocks.iter().enumerate() {
            block.real_addr.save(writer)?;
            block.mem_offset.save(writer)?;
            block.len.save(writer)?;
            block.base.save(writer)?;

            let vec = &self.block_idx_pointed_from[i];
            vec.len().save(writer)?;
            for item in vec {
                item.save(writer)?;
            }
        }

        self.memory.len().save(writer)?;
        writer.write_all(&self.memory)?;
        Ok(())
    }

    /// Deserailize a snapshot instance from a given reader.
    ///
    /// If the data is malformed, this method may allocate an absurd amount of memory and fail.
    pub fn deserialize_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut blocks = Vec::with_capacity(usize::load(reader)?);
        let mut block_idx_pointed_from = Vec::with_capacity(blocks.capacity());
        for _ in 0..blocks.capacity() {
            blocks.push(Block {
                real_addr: usize::load(reader)?,
                mem_offset: usize::load(reader)?,
                len: usize::load(reader)?,
                base: bool::load(reader)?,
            });
            let mut vec = Vec::with_capacity(usize::load(reader)?);
            for _ in 0..vec.capacity() {
                vec.push(usize::load(reader)?);
            }
            block_idx_pointed_from.push(vec);
        }

        let mut memory = vec![0; usize::load(reader)?];
        reader.read_exact(&mut memory)?;

        Ok(Self {
            memory,
            blocks,
            block_idx_pointed_from,
        })
    }
}

impl OptimizerWorker {
    /// Begin working on the optimization.
    pub fn work(&self) {
        // For each block...
        while let Some(block_idx) = {
            let val = { self.pending.lock().unwrap().pop() };
            val
        } {
            let mut points_to = vec![false; self.snapshot.blocks.len()];

            // ...scan all the pointer-values...
            for pv in self
                .snapshot
                .iter_pointer_values(block_idx)
                .filter(|pv| self.mem_map[(pv >> OPT_MEM_MAP_SHIFT) & OPT_MEM_MAP_MASK])
            {
                // ...and if any of the pointer-values points into a block...
                match self
                    .snapshot
                    .blocks
                    .binary_search_by_key(&pv, |b| b.real_addr)
                {
                    // ...then we know that the block with this pointer-value points to our original block.
                    Ok(idx) => {
                        points_to[idx] = true;
                    }
                    Err(0) => {}
                    Err(idx) => {
                        let block = &self.snapshot.blocks[idx - 1];
                        if (pv - block.real_addr) < block.len {
                            points_to[idx - 1] = true;
                        }
                    }
                }
            }

            self.done.lock().unwrap().push((
                block_idx,
                points_to
                    .into_iter()
                    .enumerate()
                    .flat_map(|(i, b)| b.then(|| i))
                    .collect::<HashSet<_>>(),
            ));
        }
    }

    /// Finish the optimization job.
    pub fn finish(self) -> Snapshot {
        let mut snap = self.snapshot;
        let done = self.done.into_inner().unwrap();

        snap.block_idx_pointed_from = (0..snap.blocks.len())
            .map(|_| Vec::new())
            .collect::<Vec<_>>();

        for (block_idx, points_to) in done {
            for target_idx in points_to {
                snap.block_idx_pointed_from[target_idx].push(block_idx);
            }
        }

        snap
    }
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

        let ret = Some((
            block.real_addr + self.block_offset,
            usize::from_ne_bytes(
                self.memory[block.mem_offset + self.block_offset
                    ..block.mem_offset + self.block_offset + 8]
                    .try_into()
                    .unwrap(),
            ),
        ));
        self.block_offset += 8;
        ret
    }
}
