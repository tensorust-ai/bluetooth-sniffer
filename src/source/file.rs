//! Raw IQ file input.

use super::{IqBlock, IqSource, SourceStats};
use anyhow::{Context, bail};
use crossbeam_channel::Sender;
use num_complex::Complex32;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum IqFormat {
    /// Guess from the file extension (.ci8/.cs8/.iq, .cu8, .ci16/.cs16, .cf32/.cfile)
    Auto,
    /// Signed 8-bit interleaved I/Q (hackrf_transfer -r)
    Ci8,
    /// Unsigned 8-bit interleaved I/Q (rtl_sdr)
    Cu8,
    /// Signed 16-bit little-endian interleaved I/Q
    Ci16,
    /// 32-bit float interleaved I/Q (GNU Radio gr_complex)
    Cf32,
}

impl IqFormat {
    pub fn resolve(self, path: &Path) -> anyhow::Result<IqFormat> {
        if self != IqFormat::Auto {
            return Ok(self);
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        Ok(match ext.as_str() {
            "ci8" | "cs8" | "iq" | "raw" | "bin" => IqFormat::Ci8,
            "cu8" => IqFormat::Cu8,
            "ci16" | "cs16" | "sc16" => IqFormat::Ci16,
            "cf32" | "fc32" | "cfile" | "complex" => IqFormat::Cf32,
            _ => bail!(
                "cannot guess the sample format of {}; use --format",
                path.display()
            ),
        })
    }

    fn bytes_per_sample(self) -> usize {
        match self {
            IqFormat::Ci8 | IqFormat::Cu8 | IqFormat::Auto => 2,
            IqFormat::Ci16 => 4,
            IqFormat::Cf32 => 8,
        }
    }
}

pub struct FileSource {
    path: PathBuf,
    format: IqFormat,
}

impl FileSource {
    pub fn new(path: &Path, format: IqFormat) -> anyhow::Result<Self> {
        let format = format.resolve(path)?;
        if !path.exists() {
            bail!("input file {} does not exist", path.display());
        }
        Ok(Self {
            path: path.to_path_buf(),
            format,
        })
    }
}

impl IqSource for FileSource {
    fn run(
        self: Box<Self>,
        tx: Sender<IqBlock>,
        stop: Arc<AtomicBool>,
    ) -> anyhow::Result<SourceStats> {
        let f =
            File::open(&self.path).with_context(|| format!("opening {}", self.path.display()))?;
        let mut r = BufReader::with_capacity(1 << 20, f);
        let bps = self.format.bytes_per_sample();
        let mut buf = vec![0u8; 131_072 * bps];
        let mut st = SourceStats::default();
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let mut filled = 0;
            while filled < buf.len() {
                let n = r.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            let usable = filled - filled % bps;
            if usable == 0 {
                break;
            }
            let data = &buf[..usable];
            let block = match self.format {
                IqFormat::Ci8 | IqFormat::Auto => IqBlock::Ci8(data.to_vec()),
                IqFormat::Cu8 => IqBlock::Ci8(data.iter().map(|b| b ^ 0x80).collect()),
                IqFormat::Ci16 => IqBlock::Cf32(
                    data.chunks_exact(4)
                        .map(|c| {
                            Complex32::new(
                                i16::from_le_bytes([c[0], c[1]]) as f32 / 32768.0,
                                i16::from_le_bytes([c[2], c[3]]) as f32 / 32768.0,
                            )
                        })
                        .collect(),
                ),
                IqFormat::Cf32 => IqBlock::Cf32(
                    data.chunks_exact(8)
                        .map(|c| {
                            Complex32::new(
                                f32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                                f32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                            )
                        })
                        .collect(),
                ),
            };
            st.samples += block.num_samples();
            if tx.send(block).is_err() {
                break;
            }
            if filled < buf.len() {
                break;
            }
        }
        Ok(st)
    }
}
