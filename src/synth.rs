//! Synthetic signal generation: packet encoders for LE and BR, a GFSK
//! modulator and a demo scenario. Used by the test-suite and by the
//! `btsdr synth` command to produce IQ files for trying the decoder without
//! hardware.

use crate::bits;
use crate::ble::{self, crc_init_to_air, crc24};
use crate::bredr;
use num_complex::Complex32;
use std::f64::consts::PI;

// ------------------------------------------------------------------ LE

/// Air bits of an LE 1M packet: preamble, access address, whitened PDU + CRC.
pub fn ble_packet_bits(aa: u32, crc_init: u32, pdu: &[u8], channel_index: u8) -> Vec<u8> {
    let mut v = Vec::new();
    let first = if aa & 1 == 1 { 1u8 } else { 0u8 };
    for i in 0..8 {
        // alternating, last preamble bit differs from the first AA bit
        v.push(if i % 2 == 0 { first } else { 1 - first });
    }
    bits::push_bits(&mut v, aa as u64, 32);
    let mut body = bits::unpack_lsb(pdu);
    let crc = crc24(crc_init_to_air(crc_init), &body);
    bits::push_bits(&mut body, crc as u64, 24);
    ble::whiten(&mut body, channel_index);
    v.extend_from_slice(&body);
    v
}

/// Legacy advertising PDU (header + payload).
pub fn adv_pdu(pdu_type: u8, tx_random: bool, rx_random: bool, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![
        (pdu_type & 0x0F) | ((tx_random as u8) << 6) | ((rx_random as u8) << 7),
        payload.len() as u8,
    ];
    v.extend_from_slice(payload);
    v
}

pub fn adv_ind(adv_addr: [u8; 6], name: &str) -> Vec<u8> {
    let mut p = adv_addr.to_vec();
    p.extend_from_slice(&[0x02, 0x01, 0x06]); // flags
    p.push(name.len() as u8 + 1);
    p.push(0x09);
    p.extend_from_slice(name.as_bytes());
    adv_pdu(0x0, true, false, &p)
}

#[allow(clippy::too_many_arguments)]
pub fn connect_ind(
    init_addr: [u8; 6],
    adv_addr: [u8; 6],
    aa: u32,
    crc_init: u32,
    interval: u16,
    timeout: u16,
    hop: u8,
) -> Vec<u8> {
    let mut p = init_addr.to_vec();
    p.extend_from_slice(&adv_addr);
    p.extend_from_slice(&aa.to_le_bytes());
    p.extend_from_slice(&crc_init.to_le_bytes()[..3]);
    p.push(2); // WinSize
    p.extend_from_slice(&0u16.to_le_bytes()); // WinOffset
    p.extend_from_slice(&interval.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes()); // latency
    p.extend_from_slice(&timeout.to_le_bytes());
    p.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]); // all 37 channels
    p.push((hop & 0x1F) | (1 << 5));
    adv_pdu(0x5, true, true, &p)
}

pub fn data_pdu(llid: u8, nesn: bool, sn: bool, md: bool, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![
        (llid & 3) | ((nesn as u8) << 2) | ((sn as u8) << 3) | ((md as u8) << 4),
        payload.len() as u8,
    ];
    v.extend_from_slice(payload);
    v
}

// ------------------------------------------------------------------ BR

/// Air bits of a BR packet with header (and payload, if any).
///
/// `body` is the user payload for ACL types (the payload header and CRC are
/// added here) or the 18 FHS bytes for an FHS packet.
#[allow(clippy::too_many_arguments)]
pub fn br_packet_bits(
    lap: u32,
    uap: u8,
    clk6: u8,
    ptype: u8,
    lt_addr: u8,
    seqn: bool,
    llid: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut v = bredr::access_code_bits(lap, true);
    let hdr = bredr::build_header(lt_addr, ptype, true, false, seqn, uap);
    let mut hb = bits::from_u64(hdr as u64, 18);
    bredr::whiten(&mut hb, clk6, 0);
    v.extend(bredr::fec13_encode(&hb));
    let ti = bredr::type_info(ptype);
    if ptype <= 1 {
        return v;
    }
    let mut payload = Vec::new();
    match ti.header_bytes {
        1 => payload.push((llid & 3) | (1 << 2) | ((body.len() as u8 & 0x1F) << 3)),
        2 => {
            let h = (llid as u16 & 3) | (1 << 2) | ((body.len() as u16 & 0x3FF) << 3);
            payload.extend_from_slice(&h.to_le_bytes());
        }
        _ => {}
    }
    payload.extend_from_slice(body);
    if ti.has_crc {
        let crc = bredr::crc16(uap, &payload);
        payload.extend_from_slice(&crc);
    }
    let mut pb = bits::unpack_lsb(&payload);
    bredr::whiten(&mut pb, clk6, 18);
    match ti.fec {
        bredr::Fec::None => v.extend(pb),
        bredr::Fec::Rate23 => v.extend(bredr::fec23_encode(&pb)),
        bredr::Fec::Rate13 => v.extend(bredr::fec13_encode(&pb)),
    }
    v
}

/// ID packet (access code only).
pub fn br_id_bits(lap: u32) -> Vec<u8> {
    bredr::access_code_bits(lap, false)
}

/// The 18-byte FHS payload announcing a device.
pub fn fhs_payload(lap: u32, uap: u8, nap: u16, cod: u32, lt_addr: u8, clk27_2: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(144);
    let parity = bredr::syncword(lap) & ((1u64 << 34) - 1);
    bits::push_bits(&mut b, parity, 34);
    bits::push_bits(&mut b, lap as u64, 24);
    bits::push_bits(&mut b, 0, 1); // EIR
    bits::push_bits(&mut b, 0, 1); // undefined
    bits::push_bits(&mut b, 1, 2); // SR
    bits::push_bits(&mut b, 2, 2); // reserved
    bits::push_bits(&mut b, uap as u64, 8);
    bits::push_bits(&mut b, nap as u64, 16);
    bits::push_bits(&mut b, cod as u64, 24);
    bits::push_bits(&mut b, lt_addr as u64, 3);
    bits::push_bits(&mut b, clk27_2 as u64, 26);
    bits::push_bits(&mut b, 0, 3); // page scan mode
    bits::pack_lsb(&b)
}

// ------------------------------------------------------------ modulator

/// Continuous-phase GFSK modulator (1 Msym/s).
pub struct Gfsk {
    fs: f64,
    sps: usize,
    pulse: Vec<f64>,
}

impl Gfsk {
    pub fn new(fs: f64, bt: f64) -> Self {
        let sps = (fs / 1e6).round() as usize;
        // Gaussian frequency pulse spanning 4 symbols, unit area per symbol
        let span = 4 * sps + 1;
        let sigma = (2f64.ln()).sqrt() / (2.0 * PI * bt) * sps as f64;
        let mid = (span / 2) as f64;
        let mut g: Vec<f64> = (0..span)
            .map(|i| (-((i as f64 - mid).powi(2)) / (2.0 * sigma * sigma)).exp())
            .collect();
        let s: f64 = g.iter().sum();
        g.iter_mut().for_each(|x| *x /= s);
        Self { fs, sps, pulse: g }
    }

    /// Baseband waveform for `bits` with peak deviation `dev_hz`, including a
    /// short power ramp before and after the packet.
    pub fn modulate(&self, bits: &[u8], dev_hz: f64) -> Vec<Complex32> {
        let ramp = 2 * self.sps;
        let n = bits.len() * self.sps;
        let pad = self.pulse.len();
        let mut nrz = vec![0f64; n + 2 * pad];
        for (i, &b) in bits.iter().enumerate() {
            let v = if b == 1 { 1.0 } else { -1.0 };
            for k in 0..self.sps {
                nrz[pad + i * self.sps + k] = v;
            }
        }
        let half = self.pulse.len() / 2;
        let mut out = Vec::with_capacity(n + 2 * ramp);
        let mut phase = 0f64;
        for i in 0..n + 2 * ramp {
            // frequency at output sample i (bits start at `ramp`)
            let center = pad as i64 + i as i64 - ramp as i64;
            let mut f = 0.0;
            for (k, &g) in self.pulse.iter().enumerate() {
                let idx = center + k as i64 - half as i64;
                if idx >= 0 && (idx as usize) < nrz.len() {
                    f += g * nrz[idx as usize];
                }
            }
            phase += 2.0 * PI * dev_hz * f / self.fs;
            let amp = if i < ramp {
                i as f64 / ramp as f64
            } else if i >= n + ramp {
                (n + 2 * ramp - i) as f64 / ramp as f64
            } else {
                1.0
            };
            out.push(Complex32::new(
                (amp * phase.cos()) as f32,
                (amp * phase.sin()) as f32,
            ));
        }
        out
    }

    pub fn ramp_samples(&self) -> usize {
        2 * self.sps
    }
}

/// Radio impairments applied to every synthesised packet.
#[derive(Clone, Copy, Debug)]
pub struct Impairments {
    /// Initial carrier offset, uniform in +-`cfo_hz`.
    pub cfo_hz: f64,
    /// Linear frequency drift during the packet, uniform in +- Hz/us.
    pub drift_hz_per_us: f64,
    /// Modulation index spread, uniform in +- this fraction of nominal.
    pub h_spread: f64,
    /// Random-walk phase noise, rad per sqrt(us).
    pub phase_noise: f64,
}

impl Impairments {
    /// Small carrier offset only.
    pub const IDEAL: Self = Self {
        cfo_hz: 30e3,
        drift_hz_per_us: 0.0,
        h_spread: 0.0,
        phase_noise: 0.0,
    };
    /// Within the core specification limits: +-100 kHz offset, up to
    /// 20 Hz/us drift (40 kHz over a 2 ms packet), +-10 % modulation index
    /// (LE 0.45-0.55, BR 0.29-0.35) and mild phase noise.
    pub const REALISTIC: Self = Self {
        cfo_hz: 100e3,
        drift_hz_per_us: 20.0,
        h_spread: 0.1,
        phase_noise: 0.05,
    };
}

/// Wideband IQ buffer into which packets are mixed.
pub struct Scene {
    pub fs: f64,
    pub center_mhz: u32,
    pub buf: Vec<Complex32>,
    gfsk: Gfsk,
    imp: Impairments,
    rng: XorShift,
}

/// Modulation index presets.
pub const BLE_DEV: f64 = 250e3;
pub const BR_DEV: f64 = 160e3;

impl Scene {
    pub fn new(fs: f64, center_mhz: u32, duration: f64) -> Self {
        Self::with_impairments(fs, center_mhz, duration, Impairments::IDEAL, 1)
    }

    pub fn with_impairments(
        fs: f64,
        center_mhz: u32,
        duration: f64,
        imp: Impairments,
        seed: u64,
    ) -> Self {
        Self {
            fs,
            center_mhz,
            buf: vec![Complex32::new(0.0, 0.0); (duration * fs) as usize],
            gfsk: Gfsk::new(fs, 0.5),
            imp,
            rng: XorShift(seed.wrapping_mul(0xD1B5_4A32_D192_ED03).max(1)),
        }
    }

    /// Add a packet whose first bit starts at time `t` (s) on `freq_mhz`.
    pub fn add(&mut self, t: f64, freq_mhz: u32, bits: &[u8], dev_hz: f64, amp: f32, cfo_hz: f64) {
        let sym = |r: &mut XorShift| 2.0 * r.uniform() - 1.0;
        let dev = dev_hz * (1.0 + sym(&mut self.rng) * self.imp.h_spread);
        let drift = sym(&mut self.rng) * self.imp.drift_hz_per_us * 1e6; // Hz/s
        let pn_step = self.imp.phase_noise * (1e6 / self.fs).sqrt();
        let wave = self.gfsk.modulate(bits, dev);
        let start = (t * self.fs).round() as i64 - self.gfsk.ramp_samples() as i64;
        let f_off = (freq_mhz as f64 - self.center_mhz as f64) * 1e6 + cfo_hz;
        let mut pn = 0.0f64;
        for (n, w) in wave.iter().enumerate() {
            let i = start + n as i64;
            if pn_step > 0.0 {
                pn += pn_step * self.rng.gauss_pair().0 as f64;
            }
            if i < 0 || i as usize >= self.buf.len() {
                continue;
            }
            let tt = n as f64 / self.fs;
            let ph = 2.0 * PI * (f_off * i as f64 / self.fs + 0.5 * drift * tt * tt) + pn;
            let lo = Complex32::new(ph.cos() as f32, ph.sin() as f32);
            self.buf[i as usize] += w * lo * amp;
        }
    }

    /// Add white Gaussian noise with the given RMS amplitude and quantise to
    /// interleaved signed 8-bit samples.
    pub fn to_ci8(&self, noise_rms: f32, seed: u64) -> Vec<u8> {
        let mut rng = XorShift(seed.max(1));
        let mut out = Vec::with_capacity(self.buf.len() * 2);
        for s in &self.buf {
            let (a, b) = rng.gauss_pair();
            let v = *s + Complex32::new(a, b) * (noise_rms / std::f32::consts::SQRT_2);
            out.push((v.re * 127.0).round().clamp(-127.0, 127.0) as i8 as u8);
            out.push((v.im * 127.0).round().clamp(-127.0, 127.0) as i8 as u8);
        }
        out
    }
}

pub struct XorShift(pub u64);

impl XorShift {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn gauss_pair(&mut self) -> (f32, f32) {
        let u1 = self.uniform().max(1e-12);
        let u2 = self.uniform();
        let r = (-2.0 * u1.ln()).sqrt();
        (
            (r * (2.0 * PI * u2).cos()) as f32,
            (r * (2.0 * PI * u2).sin()) as f32,
        )
    }
}

// ------------------------------------------------------------- scenario

/// Description of what the demo scenario contains (for tests).
#[derive(Clone, Debug)]
pub struct ScenarioInfo {
    pub adv_packets: usize,
    pub conn_aa: u32,
    pub conn_crc_init: u32,
    pub conn_packets: usize,
    pub hidden_aa: u32,
    pub hidden_crc_init: u32,
    pub hidden_packets: usize,
    pub br_lap: u32,
    pub br_uap: u8,
    pub br_packets: usize,
    pub br_crc_packets: usize,
    pub inquiry_ids: usize,
    pub fhs_bd_addr: String,
}

pub const DEMO_ADV_ADDR: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0xC1];

/// Generate a demo capture centred at `center_mhz` (must cover 2426 MHz,
/// i.e. advertising channel 38, for the LE part).
pub fn demo_scenario(
    center_mhz: u32,
    rate_mhz: u32,
    duration: f64,
    snr_db: f64,
    seed: u64,
    imp: Impairments,
) -> (Vec<u8>, ScenarioInfo) {
    let fs = rate_mhz as f64 * 1e6;
    let mut sc = Scene::with_impairments(fs, center_mhz, duration, imp, seed);
    let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1));
    let half = rate_mhz as i64 / 2 - 2;
    let lo = (center_mhz as i64 - half).max(2402) as u32;
    let hi = (center_mhz as i64 + half).min(2480) as u32;
    let amp = 0.25f32;
    // noise RMS for the requested SNR in a 1 MHz channel
    let noise_rms = amp / 10f32.powf(snr_db as f32 / 20.0) * (fs as f32 / 1e6).sqrt();
    let cfo = |r: &mut XorShift| (2.0 * r.uniform() - 1.0) * imp.cfo_hz;

    let le_data_freqs: Vec<u32> = (lo..=hi)
        .filter(|&f| ble::rf_channel_from_mhz(f).is_some_and(|rf| !ble::is_primary_adv(rf)))
        .collect();
    let br_freqs: Vec<u32> = (lo..=hi).collect();
    let mut info = ScenarioInfo {
        adv_packets: 0,
        conn_aa: 0x5065_4A3C,
        conn_crc_init: 0x7A3B5C,
        conn_packets: 0,
        hidden_aa: 0x6A7C_4F31,
        hidden_crc_init: 0x13579B,
        hidden_packets: 0,
        br_lap: 0xA1B2C3,
        br_uap: 0x5D,
        br_packets: 0,
        br_crc_packets: 0,
        inquiry_ids: 0,
        fhs_bd_addr: "00:1a:7d:da:71:13".into(),
    };
    let ch38 = 2426u32;
    let adv_ok = (lo..=hi).contains(&ch38);

    // --- LE advertising every 20 ms on channel 38, plus a CONNECT_IND
    if adv_ok {
        let mut t = 0.002;
        let pdu = adv_ind(DEMO_ADV_ADDR, "btsdr-demo");
        let bits = ble_packet_bits(ble::ADV_AA, ble::ADV_CRC_INIT, &pdu, 38);
        while t < duration - 0.003 {
            sc.add(t, ch38, &bits, BLE_DEV, amp, cfo(&mut rng));
            info.adv_packets += 1;
            t += 0.020;
        }
        let ci = connect_ind(
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x46],
            DEMO_ADV_ADDR,
            info.conn_aa,
            info.conn_crc_init,
            6,
            100,
            7,
        );
        let t_conn = 0.0125;
        let bits = ble_packet_bits(ble::ADV_AA, ble::ADV_CRC_INIT, &ci, 38);
        sc.add(t_conn, ch38, &bits, BLE_DEV, amp, cfo(&mut rng));
        info.adv_packets += 1;

        // --- the announced connection: event every 7.5 ms on in-band data channels
        if !le_data_freqs.is_empty() {
            let mut t = t_conn + 0.002;
            let mut k = 0usize;
            let mut sn = false;
            while t < duration - 0.003 {
                let f = le_data_freqs[k % le_data_freqs.len()];
                let ci = ble::channel_index(ble::rf_channel_from_mhz(f).unwrap());
                let m_pdu = if k % 4 == 1 {
                    data_pdu(3, sn, sn, false, &[0x0C, 0x0D, 0x59, 0x00, 0x34, 0x12]) // LL_VERSION_IND
                } else {
                    data_pdu(1, sn, sn, false, &[])
                };
                let s_pdu = data_pdu(
                    2,
                    !sn,
                    sn,
                    false,
                    &[0x03, 0x00, 0x04, 0x00, 0x0A, 0x03, 0x00],
                ); // ATT read
                let m_bits = ble_packet_bits(info.conn_aa, info.conn_crc_init, &m_pdu, ci);
                let c = cfo(&mut rng);
                sc.add(t, f, &m_bits, BLE_DEV, amp, c);
                let t2 = t + m_bits.len() as f64 * 1e-6 + 150e-6;
                let s_bits = ble_packet_bits(info.conn_aa, info.conn_crc_init, &s_pdu, ci);
                sc.add(t2, f, &s_bits, BLE_DEV, amp, c + 5e3);
                info.conn_packets += 2;
                sn = !sn;
                k += 1;
                t += 0.0075;
            }
        }
    }

    // --- a connection that started before the capture (promiscuous discovery)
    if !le_data_freqs.is_empty() {
        let mut t = 0.004;
        let mut k = 3usize;
        while t < duration - 0.003 {
            let f = le_data_freqs[k % le_data_freqs.len()];
            let ci = ble::channel_index(ble::rf_channel_from_mhz(f).unwrap());
            let m_bits = ble_packet_bits(
                info.hidden_aa,
                info.hidden_crc_init,
                &data_pdu(1, false, false, false, &[]),
                ci,
            );
            let s_bits = ble_packet_bits(
                info.hidden_aa,
                info.hidden_crc_init,
                &data_pdu(1, true, false, false, &[]),
                ci,
            );
            let c = cfo(&mut rng);
            sc.add(t, f, &m_bits, BLE_DEV, amp, c);
            sc.add(
                t + m_bits.len() as f64 * 1e-6 + 150e-6,
                f,
                &s_bits,
                BLE_DEV,
                amp,
                c,
            );
            info.hidden_packets += 2;
            k += 5;
            t += 0.010;
        }
    }

    // --- BR piconet: POLL/NULL with occasional DM1/DH1, on a slot grid
    {
        let slot = 625e-6;
        let clk0: u32 = 0x1234; // master clock (CLK) at t = 0, 312.5 us ticks
        let mut slot_idx = 3i64; // even slots: master
        // the master transmits in slots with CLK1 = 0
        if (clk0.wrapping_add((slot_idx * 2) as u32) >> 1) & 1 == 1 {
            slot_idx += 1;
        }
        let mut seq = false;
        let mut n = 0usize;
        loop {
            let t = slot_idx as f64 * slot + 0.0001;
            if t > duration - 0.004 {
                break;
            }
            let clk = clk0.wrapping_add((slot_idx * 2) as u32);
            let clk6 = ((clk >> 1) & 0x3F) as u8;
            let f = br_freqs[(rng.next_u64() % br_freqs.len() as u64) as usize];
            let (ptype, body): (u8, Vec<u8>) = match n % 6 {
                // DM1: L2CAP signalling Echo Request
                1 => (3, vec![0x04, 0x00, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00]),
                // DH1: start of a longer L2CAP frame
                4 => (4, (0..20u8).collect()),
                _ => (1, Vec::new()), // POLL
            };
            let bits = br_packet_bits(info.br_lap, info.br_uap, clk6, ptype, 1, seq, 2, &body);
            sc.add(t, f, &bits, BR_DEV, amp, cfo(&mut rng));
            info.br_packets += 1;
            if ptype != 1 {
                info.br_crc_packets += 1;
            }
            // slave answers with NULL in the next slot
            let clk_s = clk.wrapping_add(2);
            let f2 = br_freqs[(rng.next_u64() % br_freqs.len() as u64) as usize];
            let bits = br_packet_bits(
                info.br_lap,
                info.br_uap,
                ((clk_s >> 1) & 0x3F) as u8,
                0,
                1,
                seq,
                0,
                &[],
            );
            sc.add(t + slot, f2, &bits, BR_DEV, amp, cfo(&mut rng));
            info.br_packets += 1;
            seq = !seq;
            n += 1;
            slot_idx += 6;
        }
    }

    // --- inquiry: GIAC ID packets and one FHS inquiry response
    {
        let mut t = 0.0031;
        let mut i = 0;
        while t < duration - 0.002 && i < 40 {
            let f = br_freqs[(rng.next_u64() % br_freqs.len() as u64) as usize];
            sc.add(t, f, &br_id_bits(bredr::GIAC), BR_DEV, amp, cfo(&mut rng));
            info.inquiry_ids += 1;
            i += 1;
            t += 0.0043;
        }
        let fhs = fhs_payload(0xDA7113, 0x7D, 0x001A, 0x5A020C, 0, 0x0ABCDEF);
        let f = br_freqs[br_freqs.len() / 2];
        let bits = br_packet_bits(bredr::GIAC, 0x00, 0x2B, 2, 0, false, 0, &fhs);
        sc.add(duration * 0.6, f, &bits, BR_DEV, amp, cfo(&mut rng));
    }

    (sc.to_ci8(noise_rms, seed), info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_bits_roundtrip() {
        let pdu = adv_ind(DEMO_ADV_ADDR, "x");
        let b = ble_packet_bits(ble::ADV_AA, ble::ADV_CRC_INIT, &pdu, 37);
        assert_eq!(b.len(), 8 + 32 + pdu.len() * 8 + 24);
        assert_eq!(bits::to_u32(&b[8..40]), ble::ADV_AA);
        let mut rest = b[40..].to_vec();
        ble::whiten(&mut rest, 37);
        assert_eq!(bits::pack_lsb(&rest[..pdu.len() * 8]), pdu);
    }

    #[test]
    fn br_dm1_roundtrip() {
        use crate::bredr::decoder::decode_payload;
        let body = b"hello world";
        let bits = br_packet_bits(0x123456, 0x47, 21, 3, 2, true, 2, body);
        let sw = bits::to_u64(&bits[4..68]);
        assert_eq!(bredr::check_syncword(sw, 0), Some((0x123456, 0)));
        let (h, _) = bredr::fec13_decode(&bits[72..126]);
        let mut h = h;
        bredr::whiten(&mut h, 21, 0);
        let hdr = bits::to_u32(&h);
        assert!(bredr::header_valid(0x47, hdr));
        assert_eq!(bredr::uap_from_header(hdr), 0x47);
        let pl = decode_payload(&bits[126..], &[], 3, 0x47, 21).unwrap();
        assert_eq!(pl.crc_valid, Some(true));
        assert_eq!(&pl.bytes[1..1 + body.len()], body);
    }
}
