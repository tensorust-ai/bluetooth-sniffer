//! Bluetooth EDR (Enhanced Data Rate) payload demodulation.
//!
//! An EDR packet carries its access code and header in GFSK, exactly like a
//! BR packet. After the header the transmitter keeps a guard time of
//! 4.75-5.25 us, then sends a DPSK synchronisation sequence (a reference
//! symbol followed by ten symbols with fixed phase changes), the payload and
//! a two-symbol trailer. The payload uses pi/4-DQPSK (2 Mbit/s) or 8DPSK
//! (3 Mbit/s) at 1 Msym/s with root-raised-cosine pulses (roll-off 0.4).
//!
//! The demodulator reuses the carrier offset estimated on the GFSK part of
//! the same packet, interpolates to 8 samples/symbol, applies the matched
//! RRC filter, finds the symbol timing by correlating with the known sync
//! sequence inside the guard-time window and detects each symbol
//! differentially while tracking the residual frequency error.

use super::filter;
use num_complex::Complex32;
use std::f32::consts::PI;

/// Phase changes of the synchronisation sequence, in units of pi/4.
pub const SYNC_STEPS: [i8; 10] = [3, -3, 3, -3, 3, -3, -3, 3, 3, 3];
/// Roll-off of the EDR root-raised-cosine pulse.
pub const ROLL_OFF: f64 = 0.4;

const INTERP: usize = 4;
const INTERP_TAPS: usize = 12 * INTERP + 1;
const RRC_SPAN: usize = 4;
/// Minimum mean cos(phase error) over the sync sequence to accept it.
const MIN_SYNC_QUALITY: f32 = 0.5;

/// Map bits (air order, first bit of a symbol first) to DPSK phase changes in
/// units of pi/4, using the Gray mappings of the core specification.
pub fn bits_to_steps(bits: &[u8], bits_per_symbol: usize) -> Vec<i8> {
    bits.chunks(bits_per_symbol)
        .map(|c| {
            let mut b = [0u8; 3];
            b[..c.len()].copy_from_slice(c);
            if bits_per_symbol == 2 {
                match (b[0], b[1]) {
                    (0, 0) => 1,
                    (0, 1) => 3,
                    (1, 1) => -3,
                    _ => -1,
                }
            } else {
                match (b[0], b[1], b[2]) {
                    (0, 0, 0) => 0,
                    (0, 0, 1) => 1,
                    (0, 1, 1) => 2,
                    (0, 1, 0) => 3,
                    (1, 1, 0) => 4,
                    (1, 1, 1) => -3,
                    (1, 0, 1) => -2,
                    _ => -1,
                }
            }
        })
        .collect()
}

/// Bits of a decided phase change `q` (units of pi/4).
pub fn step_to_bits(q: i32, bits_per_symbol: usize) -> [u8; 3] {
    let q = q.rem_euclid(8);
    if bits_per_symbol == 2 {
        match q {
            1 => [0, 0, 0],
            3 => [0, 1, 0],
            5 => [1, 1, 0],
            _ => [1, 0, 0],
        }
    } else {
        match q {
            0 => [0, 0, 0],
            1 => [0, 0, 1],
            2 => [0, 1, 1],
            3 => [0, 1, 0],
            4 => [1, 1, 0],
            5 => [1, 1, 1],
            6 => [1, 0, 1],
            _ => [1, 0, 0],
        }
    }
}

fn wrap(x: f32) -> f32 {
    (x + PI).rem_euclid(2.0 * PI) - PI
}

/// What the EDR demodulator needs to know about a packet.
#[derive(Clone, Debug)]
pub struct EdrContext {
    /// Channel samples of the burst.
    pub samples: Vec<Complex32>,
    pub sample_rate: f64,
    /// Fractional index in `samples` of the end of the last header bit.
    pub header_end: f64,
    /// Carrier offset measured on the GFSK part (Hz).
    pub cfo_hz: f32,
}

/// Demodulated EDR payload bits.
#[derive(Clone, Debug)]
pub struct DpskBits {
    /// Payload bits (air order), starting right after the sync sequence.
    pub bits: Vec<u8>,
    /// Mean cos(phase error) over the sync sequence (1.0 = perfect).
    pub sync_quality: f32,
    /// RMS phase error of the payload symbols (radians).
    pub rms_error: f32,
}

pub struct EdrDemod {
    phases: Vec<Vec<f32>>,
    rrc: Vec<f32>,
}

impl Default for EdrDemod {
    fn default() -> Self {
        Self::new()
    }
}

impl EdrDemod {
    pub fn new() -> Self {
        let h = filter::lowpass(INTERP_TAPS, 0.125, filter::kaiser_beta(60.0));
        let mut phases = vec![Vec::new(); INTERP];
        for (i, &t) in h.iter().enumerate() {
            phases[i % INTERP].push(t * INTERP as f32);
        }
        // matched filter at 8 samples/symbol (2 Msps channel rate x 4)
        let rrc = filter::root_raised_cosine(2 * INTERP, ROLL_OFF, RRC_SPAN);
        Self { phases, rrc }
    }

    /// Demodulate up to `max_symbols` payload symbols with
    /// `bits_per_symbol` = 2 (pi/4-DQPSK) or 3 (8DPSK). Returns `None` if no
    /// synchronisation sequence is found after the header.
    pub fn demodulate(
        &self,
        ctx: &EdrContext,
        bits_per_symbol: usize,
        max_symbols: usize,
    ) -> Option<DpskBits> {
        let ch_per_symbol = (ctx.sample_rate / 1e6).round(); // channel samples per symbol
        let sps = INTERP * ch_per_symbol as usize;
        if sps != self.rrc.len() / (2 * RRC_SPAN) {
            return None;
        }
        let start = (ctx.header_end.floor() as isize - 8).max(0) as usize;
        if start >= ctx.samples.len() {
            return None;
        }
        let x = &ctx.samples[start..];
        // 1. interpolate
        let n = x.len() * INTERP;
        let mut z = Vec::with_capacity(n);
        for i in 0..x.len() {
            for ph in &self.phases {
                let mut acc = Complex32::new(0.0, 0.0);
                for (k, &t) in ph.iter().enumerate().take(i + 1) {
                    acc += x[i - k] * t;
                }
                z.push(acc);
            }
        }
        // 2. remove the carrier offset measured on the GFSK part
        let w = -2.0 * std::f64::consts::PI * ctx.cfo_hz as f64 / (ctx.sample_rate * INTERP as f64);
        for (m, v) in z.iter_mut().enumerate() {
            let ph = w * (m + start * INTERP) as f64;
            *v *= Complex32::new(ph.cos() as f32, ph.sin() as f32);
        }
        // 3. matched filter
        let y: Vec<Complex32> = (0..n)
            .map(|m| {
                let mut acc = Complex32::new(0.0, 0.0);
                for (k, &t) in self.rrc.iter().enumerate().take(m + 1) {
                    acc += z[m - k] * t;
                }
                acc
            })
            .collect();
        let delay = (INTERP_TAPS - 1) as f64 / 2.0 + (RRC_SPAN * sps) as f64;
        let index = |tau: f64| -> Option<usize> {
            let m = (INTERP as f64 * (tau - start as f64) + delay).round();
            (m >= 0.0 && (m as usize) < y.len()).then_some(m as usize)
        };
        let symbol_at =
            |t_ref: f64, k: usize| index(t_ref + ch_per_symbol * k as f64).map(|m| y[m]);
        // 4. timing: correlate with the sync sequence over the guard window
        let mut best: Option<(f32, f64)> = None;
        for gi in 0..=8 {
            let guard_us = 4.5 + gi as f64 * 0.125;
            // centre of the reference symbol
            let t_ref = ctx.header_end + ch_per_symbol * (guard_us + 0.5);
            let Some(s) = (0..11)
                .map(|k| symbol_at(t_ref, k))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let q: f32 = (1..11)
                .map(|k| {
                    ((s[k] * s[k - 1].conj()).arg() - SYNC_STEPS[k - 1] as f32 * PI / 4.0).cos()
                })
                .sum::<f32>()
                / 10.0;
            if best.is_none_or(|(bq, _)| q > bq) {
                best = Some((q, t_ref));
            }
        }
        let (sync_quality, t_ref) = best?;
        if sync_quality < MIN_SYNC_QUALITY {
            return None;
        }
        // residual frequency error (phase drift per symbol) from the sync
        let s: Vec<Complex32> = (0..11).map(|k| symbol_at(t_ref, k).unwrap()).collect();
        let mut eps = (1..11)
            .map(|k| wrap((s[k] * s[k - 1].conj()).arg() - SYNC_STEPS[k - 1] as f32 * PI / 4.0))
            .sum::<f32>()
            / 10.0;
        // 5. differential detection of the payload
        let unit = PI / 4.0;
        let mut bits = Vec::with_capacity(max_symbols * bits_per_symbol);
        let mut prev = s[10];
        let (mut err2, mut count) = (0f32, 0usize);
        for k in 11..11 + max_symbols {
            let Some(cur) = symbol_at(t_ref, k) else {
                break;
            };
            let d = wrap((cur * prev.conj()).arg() - eps);
            let xq = d / unit;
            let q = if bits_per_symbol == 2 {
                2 * ((xq - 1.0) / 2.0).round() as i32 + 1
            } else {
                xq.round() as i32
            };
            let e = d - q as f32 * unit;
            eps += 0.05 * e;
            err2 += e * e;
            count += 1;
            bits.extend_from_slice(&step_to_bits(q, bits_per_symbol)[..bits_per_symbol]);
            prev = cur;
        }
        Some(DpskBits {
            bits,
            sync_quality,
            rms_error: (err2 / count.max(1) as f32).sqrt(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gray_mappings_roundtrip() {
        for bps in [2usize, 3] {
            let bits: Vec<u8> = (0..(bps * 64))
                .map(|i| ((i * 7 + i / 3) % 2) as u8)
                .collect();
            let steps = bits_to_steps(&bits, bps);
            let back: Vec<u8> = steps
                .iter()
                .flat_map(|&q| step_to_bits(q as i32, bps)[..bps].to_vec())
                .collect();
            assert_eq!(back, bits, "bps {bps}");
        }
        // the sync sequence written as Gray symbols (spec index notation)
        assert_eq!(bits_to_steps(&[0, 1, 1, 1], 2), vec![3, -3]);
        assert_eq!(bits_to_steps(&[0, 1, 0, 1, 1, 1], 3), vec![3, -3]);
    }

    #[test]
    fn neighbouring_8dpsk_symbols_differ_in_one_bit() {
        for q in 0..8 {
            let a = step_to_bits(q, 3);
            let b = step_to_bits(q + 1, 3);
            let diff = a.iter().zip(&b).filter(|(x, y)| x != y).count();
            assert_eq!(diff, 1, "q {q}");
        }
    }
}
