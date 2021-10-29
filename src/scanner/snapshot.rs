use crate::ffi::{Process, Region};

use crate::SerDes;
use std::collections::HashSet;
use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::thread;

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
    pending: Mutex<Vec<usize>>,
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
    ///
    /// Only blocks for which the predicate returns `true` will be kept.
    pub fn into_optimizer<F>(self, mut predicate: F) -> OptimizerWorker
    where
        F: FnMut(&Block) -> bool,
    {
        OptimizerWorker {
            pending: Mutex::new(
                self.blocks
                    .iter()
                    .enumerate()
                    .filter_map(|(i, block)| predicate(block).then(|| i))
                    .collect::<Vec<_>>(),
            ),
            done: Mutex::new(Vec::new()),
            snapshot: self,
        }
    }

    /// Return an optimized version of self.
    ///
    /// `extra_threads` will be spawned to help speed up the optimization process.
    ///
    /// Only blocks for which the predicate returns `true` will be kept.
    pub fn optimized_with_threads<F>(self, extra_threads: usize, predicate: F) -> Self
    where
        F: FnMut(&Block) -> bool,
    {
        let worker = Arc::new(self.into_optimizer(predicate));
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
            let block = &self.snapshot.blocks[block_idx];
            let mut block_map = HashSet::new();

            // ...scan all the pointer-values...
            for (ra, pv) in self.snapshot.iter_all_addr() {
                // ...and if any of the pointer-values points inside this block...
                if let Some(delta) = pv.checked_sub(block.real_addr) {
                    if delta < block.len {
                        // ...then we know that the block with this pointer-value points to our original block.
                        block_map.insert(self.snapshot.get_block_idx(ra));
                    }
                }
            }

            self.done.lock().unwrap().push((block_idx, block_map));
        }
    }

    /// Finish the optimization job.
    pub fn finish(self) -> Snapshot {
        let mut snap = self.snapshot;
        let mut done = self.done.into_inner().unwrap();
        if !done.is_empty() {
            done.sort_by_key(|t| t.0);
            snap.block_idx_pointed_from = done
                .into_iter()
                .map(|(_, set)| {
                    let mut vec = set.into_iter().collect::<Vec<_>>();
                    // TODO would it help to sort by "closest block" first?
                    // and stop scanning after a match in any block is found?
                    vec.sort();
                    vec
                })
                .collect();
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
