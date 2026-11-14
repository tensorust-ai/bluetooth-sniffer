//! Sample sources: HackRF One (via libhackrf), IQ files and memory buffers.

pub mod dynlib;
pub mod file;
pub mod hackrf;

use crossbeam_channel::Sender;
use num_complex::Complex32;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// A block of complex baseband samples.
pub enum IqBlock {
    /// Interleaved signed 8-bit I/Q (HackRF native).
    Ci8(Vec<u8>),
    /// Complex float samples.
    Cf32(Vec<Complex32>),
    /// `n` samples were lost (buffer overflow); keeps the time base correct.
    Gap(u64),
}

impl IqBlock {
    pub fn num_samples(&self) -> u64 {
        match self {
            IqBlock::Ci8(v) => v.len() as u64 / 2,
            IqBlock::Cf32(v) => v.len() as u64,
            IqBlock::Gap(n) => *n,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct SourceStats {
    pub samples: u64,
    pub dropped: u64,
}

pub trait IqSource: Send {
    /// Stream blocks into `tx` until the source is exhausted or `stop` is set.
    fn run(
        self: Box<Self>,
        tx: Sender<IqBlock>,
        stop: Arc<AtomicBool>,
    ) -> anyhow::Result<SourceStats>;
}

/// In-memory ci8 source (tests, synthetic data).
pub struct MemorySource {
    data: Vec<u8>,
    block: usize,
}

impl MemorySource {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            block: 262_144,
        }
    }
}

impl IqSource for MemorySource {
    fn run(
        self: Box<Self>,
        tx: Sender<IqBlock>,
        stop: Arc<AtomicBool>,
    ) -> anyhow::Result<SourceStats> {
        let mut st = SourceStats::default();
        for chunk in self.data.chunks(self.block) {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            st.samples += chunk.len() as u64 / 2;
            if tx.send(IqBlock::Ci8(chunk.to_vec())).is_err() {
                break;
            }
        }
        Ok(st)
    }
}
