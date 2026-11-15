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
    /// The receiver was retuned to `center_mhz`. The samples that follow are
    /// from the new frequency, except the first `settle` ones: they may still
    /// be from the old frequency (buffered in the USB pipeline) or from the
    /// synthesizer settling, and must be discarded.
    Retune { center_mhz: u32, settle: u64 },
}

impl IqBlock {
    pub fn num_samples(&self) -> u64 {
        match self {
            IqBlock::Ci8(v) => v.len() as u64 / 2,
            IqBlock::Cf32(v) => v.len() as u64,
            IqBlock::Gap(n) => *n,
            IqBlock::Retune { .. } => 0,
        }
    }
}

/// Retuning schedule for a source that supports it (HackRF).
#[derive(Clone, Debug, PartialEq)]
pub struct Sweep {
    /// Centre frequencies in MHz, visited in order and then repeated.
    pub centers_mhz: Vec<u32>,
    /// Time on each centre frequency in seconds, including the settling time.
    pub dwell: f64,
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
    /// (sample index, marker): markers inserted before that sample.
    markers: Vec<(u64, IqBlock)>,
}

impl MemorySource {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            block: 262_144,
            markers: Vec::new(),
        }
    }

    /// Insert a [`IqBlock::Retune`] marker before sample `at`, as a sweeping
    /// receiver would.
    pub fn retune_at(mut self, at: u64, center_mhz: u32, settle: u64) -> Self {
        self.markers
            .push((at, IqBlock::Retune { center_mhz, settle }));
        self.markers.sort_by_key(|m| m.0);
        self
    }
}

impl IqSource for MemorySource {
    fn run(
        self: Box<Self>,
        tx: Sender<IqBlock>,
        stop: Arc<AtomicBool>,
    ) -> anyhow::Result<SourceStats> {
        let mut st = SourceStats::default();
        let mut markers = self.markers.into_iter().peekable();
        let total = self.data.len() as u64 / 2;
        let mut pos = 0u64; // in samples
        while pos < total {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            while let Some((_, m)) = markers.next_if(|m| m.0 <= pos) {
                if tx.send(m).is_err() {
                    return Ok(st);
                }
            }
            let next_marker = markers.peek().map_or(total, |m| m.0.min(total));
            let end = (pos + self.block as u64 / 2).min(next_marker).max(pos + 1);
            let chunk = &self.data[2 * pos as usize..2 * end as usize];
            st.samples += end - pos;
            if tx.send(IqBlock::Ci8(chunk.to_vec())).is_err() {
                break;
            }
            pos = end;
        }
        Ok(st)
    }
}
