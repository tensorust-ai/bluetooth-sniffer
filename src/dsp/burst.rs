//! Energy-based burst (packet) detector operating on one channelizer output.

use num_complex::Complex32;

/// A contiguous block of channel samples containing (probably) one packet.
#[derive(Clone, Debug)]
pub struct Burst {
    /// Channel centre frequency in MHz.
    pub freq_mhz: u32,
    /// Channel sample rate (Hz).
    pub sample_rate: f64,
    /// Absolute channel-rate index of `samples[0]`.
    pub start_index: u64,
    pub samples: Vec<Complex32>,
    /// Range within `samples` where the power was above the threshold.
    pub core_start: usize,
    pub core_end: usize,
    /// Mean power of the core in dBFS.
    pub signal_db: f32,
    /// Noise floor estimate in dBFS.
    pub noise_db: f32,
}

#[derive(Clone, Copy, Debug)]
pub struct BurstParams {
    /// Detection threshold above the noise floor (dB).
    pub squelch_db: f32,
    /// Samples kept before the threshold crossing.
    pub pre: usize,
    /// Samples below threshold that end a burst (also kept as post-padding).
    pub post: usize,
    /// Minimum burst core length (samples).
    pub min_len: usize,
    /// Maximum burst length (samples); longer signals are treated as
    /// continuous interference and raise the noise floor.
    pub max_len: usize,
}

impl BurstParams {
    /// Sensible defaults for Bluetooth at `fs` samples/s per channel.
    pub fn for_rate(fs: f64, squelch_db: f32) -> Self {
        let us = |x: f64| (x * fs / 1e6).round() as usize;
        Self {
            squelch_db,
            pre: us(10.0),
            post: us(6.0),
            min_len: us(50.0),
            max_len: us(3200.0),
        }
    }
}

pub struct BurstDetector {
    freq_mhz: u32,
    fs: f64,
    p: BurstParams,
    thresh: f32,
    noise: f32,
    warmup_acc: f64,
    warmup_n: usize,
    avg: f32,
    /// Ring of the last `pre` samples.
    hist: Vec<Complex32>,
    hist_pos: usize,
    in_burst: bool,
    buf: Vec<Complex32>,
    buf_start: u64,
    core_start: usize,
    last_above: usize,
    below: usize,
    sig_acc: f64,
    sig_n: usize,
    index: u64,
}

const WARMUP: usize = 4000;

impl BurstDetector {
    pub fn new(freq_mhz: u32, fs: f64, p: BurstParams) -> Self {
        Self {
            freq_mhz,
            fs,
            p,
            thresh: 10f32.powf(p.squelch_db / 10.0),
            noise: 0.0,
            warmup_acc: 0.0,
            warmup_n: 0,
            avg: 0.0,
            hist: vec![Complex32::new(0.0, 0.0); p.pre.max(1)],
            hist_pos: 0,
            in_burst: false,
            buf: Vec::new(),
            buf_start: 0,
            core_start: 0,
            last_above: 0,
            below: 0,
            sig_acc: 0.0,
            sig_n: 0,
            index: 0,
        }
    }

    pub fn noise_db(&self) -> f32 {
        10.0 * self.noise.max(1e-20).log10()
    }

    /// Set the absolute index of the next sample (after a gap).
    pub fn resync(&mut self, index: u64) {
        if self.in_burst {
            self.in_burst = false;
            self.buf.clear();
        }
        self.index = index;
    }

    pub fn process(&mut self, samples: &[Complex32], out: &mut Vec<Burst>) {
        for &s in samples {
            let pw = s.norm_sqr();
            self.avg += 0.3 * (pw - self.avg);
            if self.warmup_n < WARMUP {
                self.warmup_acc += pw as f64;
                self.warmup_n += 1;
                if self.warmup_n == WARMUP {
                    self.noise = (self.warmup_acc / WARMUP as f64) as f32;
                }
                self.push_hist(s);
                self.index += 1;
                continue;
            }
            let level = self.noise * self.thresh;
            if !self.in_burst {
                if self.avg > level {
                    self.in_burst = true;
                    self.buf.clear();
                    // pre-padding from the history ring, oldest first
                    let n = self.hist.len();
                    for i in 0..n {
                        self.buf.push(self.hist[(self.hist_pos + i) % n]);
                    }
                    self.buf_start = self.index - n as u64;
                    // The smoothed power lags the signal; walk back to the
                    // first sample whose instantaneous power is above level.
                    let mut cs = self.buf.len();
                    while cs > 0 && self.buf.len() - cs < 4 && self.buf[cs - 1].norm_sqr() > level {
                        cs -= 1;
                    }
                    self.core_start = cs;
                    self.last_above = self.buf.len();
                    self.below = 0;
                    self.sig_acc = pw as f64;
                    self.sig_n = 1;
                    self.buf.push(s);
                } else {
                    // track the noise floor with quiet samples only
                    self.noise += 0.002 * (self.avg - self.noise);
                    self.push_hist(s);
                }
            } else {
                self.buf.push(s);
                // Instantaneous power marks the end precisely (GFSK has a
                // constant envelope); the smoothed power provides hysteresis.
                if pw > level {
                    self.last_above = self.buf.len() - 1;
                }
                if self.avg > level * 0.5 {
                    self.below = 0;
                    self.sig_acc += pw as f64;
                    self.sig_n += 1;
                } else {
                    self.below += 1;
                }
                if self.below >= self.p.post {
                    self.finish(out);
                } else if self.buf.len() >= self.p.max_len {
                    // Continuous signal: treat as raised noise floor.
                    let mean = (self.sig_acc / self.sig_n.max(1) as f64) as f32;
                    self.noise = self.noise.max(mean * 0.7);
                    self.in_burst = false;
                    self.buf.clear();
                }
            }
            self.index += 1;
        }
    }

    fn push_hist(&mut self, s: Complex32) {
        let n = self.hist.len();
        self.hist[self.hist_pos] = s;
        self.hist_pos = (self.hist_pos + 1) % n;
    }

    fn finish(&mut self, out: &mut Vec<Burst>) {
        self.in_burst = false;
        let core_end = self.last_above + 1;
        let core_len = core_end.saturating_sub(self.core_start);
        let samples = std::mem::take(&mut self.buf);
        // refill the history with the tail so a following burst has context
        for &s in samples.iter().rev().take(self.hist.len()).rev() {
            self.push_hist(s);
        }
        if core_len < self.p.min_len {
            return;
        }
        let sig = (self.sig_acc / self.sig_n.max(1) as f64) as f32;
        out.push(Burst {
            freq_mhz: self.freq_mhz,
            sample_rate: self.fs,
            start_index: self.buf_start,
            samples,
            core_start: self.core_start,
            core_end,
            signal_db: 10.0 * sig.max(1e-20).log10(),
            noise_db: self.noise_db(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(n: usize, sigma: f32, seed: &mut u64) -> Vec<Complex32> {
        let mut rnd = || {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            (*seed >> 11) as f32 / (1u64 << 53) as f32 - 0.5
        };
        (0..n)
            .map(|_| Complex32::new(rnd(), rnd()) * sigma)
            .collect()
    }

    #[test]
    fn detects_single_burst() {
        let fs = 2e6;
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut x = noise(20_000, 0.01, &mut seed);
        for s in &mut x[10_000..10_400] {
            *s += Complex32::new(0.3, 0.1);
        }
        let mut d = BurstDetector::new(2426, fs, BurstParams::for_rate(fs, 8.0));
        let mut out = Vec::new();
        d.process(&x, &mut out);
        assert_eq!(out.len(), 1);
        let b = &out[0];
        let abs_core = b.start_index + b.core_start as u64;
        assert!(
            (abs_core as i64 - 10_000).abs() <= 2,
            "core start {abs_core}"
        );
        assert!(((b.core_end - b.core_start) as i64 - 400).abs() <= 4);
    }
}
