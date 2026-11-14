//! Oversampled polyphase filter bank (PFB) channelizer.
//!
//! The wideband input (sample rate `fs`) is split into `M = fs / spacing`
//! channels spaced `spacing` Hz apart. Each channel is delivered at
//! `spacing * os` samples/s (os = oversampling factor, 2 by default), which
//! gives the 1 MHz Bluetooth channels 2 samples per symbol and enough
//! bandwidth for the wider LE signals.
//!
//! For output time `t` (index of the newest input sample in the window):
//!
//! ```text
//! y_k[t] = sum_l h[l] x[t-l] e^{-j 2 pi k (t-l) / M}
//!        = e^{-j 2 pi k t / M} * IDFT_M{ u_m },  u_m = sum_p h[pM+m] x[t-pM-m]
//! ```
//!
//! i.e. one length-L dot product folded into M partial sums, one M-point
//! inverse FFT and a per-channel phase rotation every `M / os` inputs.

use super::filter;
use num_complex::Complex32;
use rustfft::{Fft, FftPlanner};
use std::sync::Arc;

pub struct Channelizer {
    m: usize,
    decim: usize,
    taps_rev: Vec<f32>,
    re: Vec<f32>,
    im: Vec<f32>,
    /// Absolute index of `re[0]`.
    base: u64,
    /// Absolute index of the newest sample of the next output window.
    next_t: u64,
    fft: Arc<dyn Fft<f32>>,
    fft_buf: Vec<Complex32>,
    fft_scratch: Vec<Complex32>,
    acc_re: Vec<f32>,
    acc_im: Vec<f32>,
    /// twiddle[k * m + r] = e^{-j 2 pi k r / M}
    twiddle: Vec<Complex32>,
    /// PFB bins (0..M) to output, in output order.
    selected: Vec<usize>,
    dc_re: f32,
    dc_im: f32,
    dc_init: bool,
}

impl Channelizer {
    /// * `m` - number of channels (input rate / channel spacing)
    /// * `os` - oversampling factor; must divide `m`
    /// * `taps_per_branch` - prototype filter length is `m * taps_per_branch`
    /// * `selected` - PFB bins to produce (bin k is centred at `+k * spacing`,
    ///   bins >= m/2 represent negative frequencies)
    pub fn new(m: usize, os: usize, taps_per_branch: usize, selected: Vec<usize>) -> Self {
        assert!(
            m >= 2 && os >= 1 && m % os == 0,
            "oversampling must divide M"
        );
        let l = m * taps_per_branch;
        // Pass +-0.75 channel spacings (LE signals are ~1.5 MHz wide), stop at
        // the output Nyquist frequency (os/2 spacings).
        let cutoff = 0.8 / m as f64;
        let proto = filter::lowpass(l, cutoff, filter::kaiser_beta(65.0));
        let taps_rev: Vec<f32> = proto.iter().rev().copied().collect();
        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_inverse(m);
        let scratch_len = fft.get_inplace_scratch_len();
        let mut twiddle = Vec::with_capacity(m * m);
        for k in 0..m {
            for r in 0..m {
                let ph = -2.0 * std::f64::consts::PI * (k * r) as f64 / m as f64;
                twiddle.push(Complex32::new(ph.cos() as f32, ph.sin() as f32));
            }
        }
        for &k in &selected {
            assert!(k < m);
        }
        Self {
            m,
            decim: m / os,
            taps_rev,
            re: Vec::new(),
            im: Vec::new(),
            base: 0,
            next_t: (l - 1) as u64,
            fft,
            fft_buf: vec![Complex32::new(0.0, 0.0); m],
            fft_scratch: vec![Complex32::new(0.0, 0.0); scratch_len],
            acc_re: vec![0.0; m],
            acc_im: vec![0.0; m],
            twiddle,
            selected,
            dc_re: 0.0,
            dc_im: 0.0,
            dc_init: false,
        }
    }

    pub fn num_outputs(&self) -> usize {
        self.selected.len()
    }

    /// Channel-rate index of the next output sample. Output `j` covers the
    /// input window ending at input sample `L - 1 + j * decimation`.
    pub fn next_output_index(&self) -> u64 {
        (self.next_t + 1 - self.taps_rev.len() as u64) / self.decim as u64
    }

    /// Filter group delay in input samples.
    pub fn delay_samples(&self) -> f64 {
        (self.taps_rev.len() as f64 - 1.0) / 2.0
    }

    fn remove_dc(&mut self, start: usize) {
        let n = self.re.len() - start;
        if n == 0 {
            return;
        }
        let (sr, si) = self.re[start..]
            .iter()
            .zip(&self.im[start..])
            .fold((0.0f64, 0.0f64), |(a, b), (&r, &i)| {
                (a + r as f64, b + i as f64)
            });
        let (mr, mi) = ((sr / n as f64) as f32, (si / n as f64) as f32);
        if !self.dc_init {
            self.dc_re = mr;
            self.dc_im = mi;
            self.dc_init = true;
        } else {
            self.dc_re += 0.2 * (mr - self.dc_re);
            self.dc_im += 0.2 * (mi - self.dc_im);
        }
        let (dr, di) = (self.dc_re, self.dc_im);
        for v in &mut self.re[start..] {
            *v -= dr;
        }
        for v in &mut self.im[start..] {
            *v -= di;
        }
    }

    /// Append interleaved signed 8-bit I/Q (HackRF native format).
    pub fn push_ci8(&mut self, raw: &[u8]) {
        let start = self.re.len();
        let n = raw.len() / 2;
        self.re.reserve(n);
        self.im.reserve(n);
        for c in raw.chunks_exact(2) {
            self.re.push((c[0] as i8) as f32 * (1.0 / 128.0));
            self.im.push((c[1] as i8) as f32 * (1.0 / 128.0));
        }
        self.remove_dc(start);
    }

    /// Append complex float samples.
    pub fn push_cf32(&mut self, samples: &[Complex32]) {
        let start = self.re.len();
        self.re.extend(samples.iter().map(|c| c.re));
        self.im.extend(samples.iter().map(|c| c.im));
        self.remove_dc(start);
    }

    /// Advance the absolute time by `n` missing input samples (e.g. after a
    /// dropped USB buffer). Filter history is discarded.
    pub fn skip(&mut self, n: u64) {
        let end = self.base + self.re.len() as u64 + n;
        self.re.clear();
        self.im.clear();
        self.base = end;
        let l = self.taps_rev.len() as u64;
        // realign so that outputs stay on the same decimation grid
        let first = end + l - 1;
        let d = self.decim as u64;
        self.next_t = first.div_ceil(d) * d + (self.next_t % d);
        if self.next_t < first {
            self.next_t += d;
        }
    }

    /// Run the filter bank over all buffered input. Output samples for the
    /// i-th selected channel are appended to `out[i]`. Returns the absolute
    /// output-sample index of the first sample produced (in channel-rate
    /// units, i.e. input index / decimation).
    pub fn process(&mut self, out: &mut [Vec<Complex32>]) -> u64 {
        assert_eq!(out.len(), self.selected.len());
        let m = self.m;
        let l = self.taps_rev.len();
        let first_out = self.next_t / self.decim as u64;
        let end = self.base + self.re.len() as u64;
        while self.next_t < end {
            let s = (self.next_t + 1 - l as u64 - self.base) as usize;
            let xr = &self.re[s..s + l];
            let xi = &self.im[s..s + l];
            self.acc_re.iter_mut().for_each(|v| *v = 0.0);
            self.acc_im.iter_mut().for_each(|v| *v = 0.0);
            for ((t, r), i) in self
                .taps_rev
                .chunks_exact(m)
                .zip(xr.chunks_exact(m))
                .zip(xi.chunks_exact(m))
            {
                for j in 0..m {
                    self.acc_re[j] += t[j] * r[j];
                    self.acc_im[j] += t[j] * i[j];
                }
            }
            // u_m = acc[M-1-m]
            for mm in 0..m {
                self.fft_buf[mm] = Complex32::new(self.acc_re[m - 1 - mm], self.acc_im[m - 1 - mm]);
            }
            self.fft
                .process_with_scratch(&mut self.fft_buf, &mut self.fft_scratch);
            let r = (self.next_t % m as u64) as usize;
            for (o, &k) in out.iter_mut().zip(&self.selected) {
                o.push(self.fft_buf[k] * self.twiddle[k * m + r]);
            }
            self.next_t += self.decim as u64;
        }
        // Drop samples no longer needed.
        let keep_from = self.next_t + 1 - l as u64;
        if keep_from > self.base {
            let drop = ((keep_from - self.base) as usize).min(self.re.len());
            self.re.drain(..drop);
            self.im.drain(..drop);
            self.base += drop as u64;
        }
        first_out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(fs: f64, f: f64, n: usize) -> Vec<Complex32> {
        (0..n)
            .map(|i| {
                let ph = 2.0 * std::f64::consts::PI * f * i as f64 / fs;
                Complex32::new(ph.cos() as f32, ph.sin() as f32) * 0.5
            })
            .collect()
    }

    /// A tone 3.2 MHz above centre must appear in bin 3 at +200 kHz and be
    /// strongly attenuated in its neighbours.
    #[test]
    fn tone_lands_in_right_channel() {
        let fs = 20e6;
        let m = 20;
        let sel = vec![2, 3, 4, 17];
        let mut ch = Channelizer::new(m, 2, 16, sel.clone());
        let x = tone(fs, 3.2e6, 40_000);
        ch.push_cf32(&x[..17_000]);
        let mut out = vec![Vec::new(); sel.len()];
        ch.process(&mut out);
        ch.push_cf32(&x[17_000..]);
        ch.process(&mut out);
        let power = |v: &Vec<Complex32>| {
            v[200..].iter().map(|c| c.norm_sqr()).sum::<f32>() / (v.len() - 200) as f32
        };
        let p: Vec<f32> = out.iter().map(power).collect();
        assert!((p[1] - 0.25).abs() < 0.02, "in-band power {}", p[1]);
        assert!(p[0] < 1e-4 && p[3] < 1e-6, "leakage {:?}", p);
        // the bin-3 output must be a +200 kHz tone at 2 Msps
        let o = &out[1];
        let mut acc = Complex32::new(0.0, 0.0);
        for i in 201..o.len() {
            acc += o[i] * o[i - 1].conj();
        }
        let f = acc.arg() as f64 / (2.0 * std::f64::consts::PI) * 2e6;
        assert!((f - 200e3).abs() < 1e3, "freq {f}");
    }
}
