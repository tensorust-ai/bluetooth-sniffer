//! FIR filter design helpers (Kaiser-windowed sinc).

use std::f64::consts::PI;

/// Zeroth-order modified Bessel function of the first kind.
pub fn bessel_i0(x: f64) -> f64 {
    let mut sum = 1.0;
    let mut term = 1.0;
    let q = x * x / 4.0;
    for k in 1..64 {
        term *= q / (k as f64 * k as f64);
        sum += term;
        if term < sum * 1e-12 {
            break;
        }
    }
    sum
}

/// Kaiser window beta for a desired stop-band attenuation in dB.
pub fn kaiser_beta(atten_db: f64) -> f64 {
    if atten_db > 50.0 {
        0.1102 * (atten_db - 8.7)
    } else if atten_db >= 21.0 {
        0.5842 * (atten_db - 21.0).powf(0.4) + 0.07886 * (atten_db - 21.0)
    } else {
        0.0
    }
}

/// Windowed-sinc low-pass prototype.
///
/// * `num_taps` - filter length
/// * `cutoff` - -6 dB cutoff frequency as a fraction of the sample rate (0..0.5)
/// * `beta` - Kaiser window parameter
///
/// The taps are normalised to unity DC gain.
pub fn lowpass(num_taps: usize, cutoff: f64, beta: f64) -> Vec<f32> {
    let mid = (num_taps as f64 - 1.0) / 2.0;
    let i0b = bessel_i0(beta);
    let mut taps: Vec<f64> = (0..num_taps)
        .map(|n| {
            let x = n as f64 - mid;
            let sinc = if x.abs() < 1e-12 {
                2.0 * cutoff
            } else {
                (2.0 * PI * cutoff * x).sin() / (PI * x)
            };
            let r = if mid > 0.0 { x / mid } else { 0.0 };
            let w = bessel_i0(beta * (1.0 - r * r).max(0.0).sqrt()) / i0b;
            sinc * w
        })
        .collect();
    let sum: f64 = taps.iter().sum();
    for t in taps.iter_mut() {
        *t /= sum;
    }
    taps.into_iter().map(|t| t as f32).collect()
}

/// Magnitude response (linear) of a real FIR at a normalised frequency.
pub fn response(taps: &[f32], freq: f64) -> f64 {
    let (mut re, mut im) = (0.0f64, 0.0f64);
    for (n, &t) in taps.iter().enumerate() {
        let ph = -2.0 * PI * freq * n as f64;
        re += t as f64 * ph.cos();
        im += t as f64 * ph.sin();
    }
    (re * re + im * im).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowpass_shape() {
        let h = lowpass(321, 0.04, kaiser_beta(70.0));
        assert!((response(&h, 0.0) - 1.0).abs() < 1e-6);
        assert!((response(&h, 0.04) - 0.5).abs() < 0.05);
        assert!(response(&h, 0.06) < 1e-3);
    }
}
