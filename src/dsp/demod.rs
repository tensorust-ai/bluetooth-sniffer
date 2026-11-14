//! GFSK demodulation of a detected burst (1 Msym/s, BLE LE 1M and BR).
//!
//! The burst (2 samples/symbol) is interpolated by 4 to 8 samples/symbol,
//! FM-discriminated, smoothed with a one-symbol moving average, corrected for
//! carrier frequency offset and sliced at the sampling phase with the widest
//! eye opening.

use super::burst::Burst;
use super::filter;
use num_complex::Complex32;

pub const INTERP: usize = 4;
const INTERP_TAPS: usize = 12 * INTERP + 1;

#[derive(Clone, Debug)]
pub struct Demodulated {
    /// Hard decisions, one per symbol.
    pub bits: Vec<u8>,
    /// Frequency (Hz, CFO removed) at each decision point.
    pub soft: Vec<f32>,
    /// Time (seconds, capture-relative) of the centre of bit 0.
    pub t0: f64,
    /// Bit index range corresponding to the burst core.
    pub core_start_bit: usize,
    pub core_end_bit: usize,
    pub cfo_hz: f32,
    /// Estimated peak frequency deviation (Hz).
    pub deviation_hz: f32,
}

impl Demodulated {
    /// Capture time of the leading edge of bit `i`.
    pub fn bit_time(&self, i: usize) -> f64 {
        self.t0 + i as f64 * 1e-6 - 0.5e-6
    }
}

pub struct GfskDemod {
    /// Polyphase interpolation filter: phases[r][k]
    phases: Vec<Vec<f32>>,
    /// Extra capture-time delay to subtract (wideband filter delay), seconds.
    extra_delay: f64,
}

impl GfskDemod {
    /// `extra_delay` is the delay (s) introduced upstream, e.g. by the
    /// channelizer filter, so that timestamps refer to the antenna.
    pub fn new(extra_delay: f64) -> Self {
        // Interpolation filter designed at 4x the channel rate: pass the
        // channel (+-1 MHz of 8 MHz => 0.125), gain INTERP.
        let h = filter::lowpass(INTERP_TAPS, 0.125, filter::kaiser_beta(60.0));
        let mut phases = vec![Vec::new(); INTERP];
        for (i, &t) in h.iter().enumerate() {
            phases[i % INTERP].push(t * INTERP as f32);
        }
        Self {
            phases,
            extra_delay,
        }
    }

    pub fn demodulate(&self, b: &Burst) -> Option<Demodulated> {
        let n_in = b.samples.len();
        if n_in < 16 {
            return None;
        }
        let fs_hi = b.sample_rate * INTERP as f64;
        // 1. interpolate: y[4n + r] = sum_k phases[r][k] x[n - k]
        let n_out = n_in * INTERP;
        let mut z = Vec::with_capacity(n_out);
        for n in 0..n_in {
            for ph in &self.phases {
                let mut acc = Complex32::new(0.0, 0.0);
                for (k, &t) in ph.iter().enumerate() {
                    if n >= k {
                        acc += b.samples[n - k] * t;
                    }
                }
                z.push(acc);
            }
        }
        // 2. FM discriminator (Hz)
        let k_hz = (fs_hi / (2.0 * std::f64::consts::PI)) as f32;
        let mut f = vec![0f32; n_out];
        for i in 1..n_out {
            let d = z[i] * z[i - 1].conj();
            f[i] = d.im.atan2(d.re) * k_hz;
        }
        // 3. one-symbol moving average
        let sps = INTERP * (b.sample_rate / 1e6).round() as usize; // samples per symbol
        let mut g = vec![0f32; n_out];
        let mut acc = 0f32;
        for i in 0..n_out {
            acc += f[i];
            if i >= sps {
                acc -= f[i - sps];
            }
            g[i] = acc / sps as f32;
        }
        // Delay of g[i] relative to burst sample time i/fs_hi:
        // interpolator (taps-1)/2, discriminator 0.5, average (sps-1)/2.
        let delay = (INTERP_TAPS as f64 - 1.0) / 2.0 + 0.5 + (sps as f64 - 1.0) / 2.0;

        // core region in interpolated samples (shrink edges by 2 us)
        let margin = 2 * sps;
        let cs = (b.core_start * INTERP + delay as usize + margin).min(n_out);
        let ce = (b.core_end * INTERP + delay as usize)
            .saturating_sub(margin)
            .min(n_out);
        if ce <= cs + 8 * sps {
            return None;
        }
        // 4. CFO estimate: mean over the core (whitened data is balanced)
        let mut cfo = g[cs..ce].iter().sum::<f32>() / (ce - cs) as f32;
        // 5. timing: phase with the largest mean |g - cfo|
        let mut best = (0usize, -1f32);
        for ph in 0..sps {
            let mut m = 0f32;
            let mut cnt = 0;
            let mut i = cs + ph;
            while i < ce {
                m += (g[i] - cfo).abs();
                cnt += 1;
                i += sps;
            }
            let m = m / cnt.max(1) as f32;
            if m > best.1 {
                best = (ph, m);
            }
        }
        // align the chosen phase to the start of the buffer
        let phase = (cs + best.0) % sps;
        // 6. refine threshold from the two symbol clusters
        let (mut s1, mut n1, mut s0, mut n0) = (0f32, 0usize, 0f32, 0usize);
        let mut i = phase;
        while i < n_out {
            if i >= cs && i < ce {
                let v = g[i] - cfo;
                if v > 0.0 {
                    s1 += v;
                    n1 += 1;
                } else {
                    s0 += v;
                    n0 += 1;
                }
            }
            i += sps;
        }
        let mut dev = 0.0;
        if n1 > 0 && n0 > 0 {
            let (m1, m0) = (s1 / n1 as f32, s0 / n0 as f32);
            cfo += (m1 + m0) / 2.0;
            dev = (m1 - m0) / 2.0;
        }
        // 7. slice
        let nbits = (n_out - phase).div_ceil(sps);
        let mut bits = Vec::with_capacity(nbits);
        let mut soft = Vec::with_capacity(nbits);
        let mut i = phase;
        while i < n_out {
            let v = g[i] - cfo;
            bits.push((v > 0.0) as u8);
            soft.push(v);
            i += sps;
        }
        let t_start = b.start_index as f64 / b.sample_rate - self.extra_delay;
        let t0 = t_start + (phase as f64 - delay) / fs_hi;
        let to_bit = |i: usize| -> usize { if i <= phase { 0 } else { (i - phase) / sps } };
        let core_start_bit = to_bit(b.core_start * INTERP + delay as usize);
        let core_end_bit = to_bit(b.core_end * INTERP + delay as usize).min(bits.len());
        Some(Demodulated {
            bits,
            soft,
            t0,
            core_start_bit,
            core_end_bit,
            cfo_hz: cfo,
            deviation_hz: dev,
        })
    }
}
