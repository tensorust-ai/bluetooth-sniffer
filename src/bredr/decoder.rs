//! BR packet recovery from demodulated bursts, with per-piconet UAP and
//! clock (CLK6-1) discovery.
//!
//! A BR packet starts with a 72-bit access code whose 64-bit sync word is a
//! BCH code word derived from the LAP, so the LAP can be read directly from
//! the air. The header and payload, however, are whitened with the master's
//! clock (CLK6-1) and protected with HEC/CRC initialised with the UAP:
//!
//! * For each of the 64 possible clock values a header yields exactly one
//!   UAP that makes the HEC valid. Packets of one piconet are on a 625 us
//!   slot grid, so the true (UAP, clock offset) pair collects a vote from
//!   every packet while wrong pairs collect votes only by chance.
//! * Packets with a CRC give much stronger evidence: for a guessed
//!   (UAP, clock) the payload CRC only passes for the right pair.
//!
//! Once a piconet is locked, every packet is de-whitened with the predicted
//! clock (re-anchored on each packet to absorb clock drift), its HEC/CRC are
//! verified and the payload is extracted.

use super::*;
use crate::bits;
use crate::ble::decoder::{BurstInfo, clamp_i8};
use crate::ble::parse_ad;
use crate::dsp::burst::Burst;
use crate::dsp::demod::Demodulated;
use crate::dsp::edr::{DpskBits, EdrContext, EdrDemod};
use std::cell::OnceCell;
use std::collections::HashMap;

pub const SLOT: f64 = 625e-6;

/// How far (bits) after the energy onset a packet may start.
pub const SEARCH_AFTER_ONSET: usize = 80;

/// Wireshark "payload transport" values (upper nibble already shifted).
pub const TRANSPORT_ANY: u8 = 0x00;
pub const TRANSPORT_ACL: u8 = 0x30;
pub const TRANSPORT_IGNORED: u8 = 0xFF;

#[derive(Clone, Debug)]
pub struct BrConfig {
    pub max_ac_errors: u32,
    pub rssi_offset: f32,
    /// LAPs whose UAP is known in advance.
    pub known_uaps: HashMap<u32, u8>,
    /// Use soft decisions for the header (1/3) and payload (2/3) FEC.
    pub soft_decisions: bool,
}

impl Default for BrConfig {
    fn default() -> Self {
        Self {
            max_ac_errors: 2,
            rssi_offset: 0.0,
            known_uaps: HashMap::new(),
            soft_decisions: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrKind {
    /// Access code only (inquiry / page / ID packet).
    Id,
    /// Access code + header (+ payload).
    Full,
}

#[derive(Clone, Debug)]
pub struct BrPacket {
    pub time: f64,
    pub rf_channel: u8,
    pub lap: u32,
    pub uap: Option<u8>,
    pub clk6: Option<u8>,
    pub kind: BrKind,
    pub ac_errors: u8,
    /// 18-bit header after FEC decoding; de-whitened if `clk6` is known.
    pub header: u32,
    pub header_corrected: u8,
    pub hec_valid: bool,
    /// De-whitened payload (payload header + body + CRC), air order bytes.
    pub payload: Option<Vec<u8>>,
    pub crc_valid: Option<bool>,
    pub payload_corrected: i16,
    pub transport: u8,
    pub signal_dbm: i8,
    pub noise_dbm: i8,
    /// Observed packet duration in bits (from the preamble to the end of energy).
    pub air_bits: usize,
    /// Payload modulation: 0 = basic rate, 1 = EDR 2 Mbit/s, 2 = EDR 3 Mbit/s.
    pub rate: u8,
    /// EDR sync-sequence quality (1.0 = perfect) when an EDR payload was found.
    pub edr_quality: Option<f32>,
}

/// Fields of an FHS payload.
#[derive(Clone, Debug)]
pub struct Fhs {
    pub lap: u32,
    pub uap: u8,
    pub nap: u16,
    pub class_of_device: u32,
    pub lt_addr: u8,
    pub clk27_2: u32,
    pub eir: bool,
}

impl Fhs {
    pub fn bd_addr(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.nap >> 8,
            self.nap & 0xFF,
            self.uap,
            (self.lap >> 16) & 0xFF,
            (self.lap >> 8) & 0xFF,
            self.lap & 0xFF
        )
    }
}

impl BrPacket {
    pub fn ptype(&self) -> Option<u8> {
        (self.kind == BrKind::Full && self.clk6.is_some())
            .then_some(((self.header >> 3) & 0xF) as u8)
    }

    pub fn lt_addr(&self) -> u8 {
        (self.header & 7) as u8
    }

    pub fn fhs(&self) -> Option<Fhs> {
        if self.ptype()? != 2 || self.crc_valid != Some(true) {
            return None;
        }
        let b = bits::unpack_lsb(self.payload.as_ref()?);
        if b.len() < 144 {
            return None;
        }
        let f = |s: usize, n: usize| bits::to_u64(&b[s..s + n]);
        Some(Fhs {
            lap: f(34, 24) as u32,
            eir: f(58, 1) == 1,
            uap: f(64, 8) as u8,
            nap: f(72, 16) as u16,
            class_of_device: f(88, 24) as u32,
            lt_addr: f(112, 3) as u8,
            clk27_2: f(115, 26) as u32,
        })
    }

    pub fn describe(&self) -> String {
        let mut s = format!("LAP={:06x}", self.lap);
        match self.uap {
            Some(u) => s += &format!(" UAP={u:02x}"),
            None if !is_inquiry_lap(self.lap) => s += " UAP=??",
            None => {}
        }
        if self.kind == BrKind::Id {
            if self.lap == GIAC {
                s += " ID (GIAC inquiry)";
            } else if is_inquiry_lap(self.lap) {
                s += " ID (DIAC inquiry)";
            } else {
                s += " ID (page / poll)";
            }
            return s;
        }
        let Some(pt) = self.ptype() else {
            s += " header (clock unknown)";
            return s;
        };
        let ti = type_info(pt);
        let name = if self.rate > 0 {
            format!(
                "{} (EDR {}M)",
                edr_type_name(pt).unwrap_or(ti.name),
                self.rate + 1
            )
        } else if self.crc_valid == Some(true) || self.payload.is_none() && pt <= 1 {
            ti.name.to_string()
        } else {
            // without a payload CRC we cannot tell BR from EDR
            match pt {
                4 => "DH1/2-DH1".into(),
                6 => "HV2/2-EV3".into(),
                7 => "HV3/EV3/3-EV3".into(),
                8 => "DV/3-DH1".into(),
                10 => "DM3/2-DH3".into(),
                11 => "DH3/3-DH3".into(),
                12 => "EV4/2-EV5".into(),
                13 => "EV5/3-EV5".into(),
                14 => "DM5/2-DH5".into(),
                15 => "DH5/3-DH5".into(),
                _ => ti.name.to_string(),
            }
        };
        s += &format!(
            " clk6={:02} LT_ADDR={} {} {}{}{}",
            self.clk6.unwrap_or(0),
            self.lt_addr(),
            name,
            if self.header & (1 << 7) != 0 {
                "F"
            } else {
                "-"
            },
            if self.header & (1 << 8) != 0 {
                "A"
            } else {
                "-"
            },
            if self.header & (1 << 9) != 0 {
                "S"
            } else {
                "-"
            },
        );
        if let Some(f) = self.fhs() {
            s += &format!(
                " BD_ADDR={} CoD=0x{:06x} LT_ADDR={} CLK27-2=0x{:07x}{}",
                f.bd_addr(),
                f.class_of_device,
                f.lt_addr,
                f.clk27_2,
                if f.eir { " EIR" } else { "" }
            );
        } else if let (Some(p), Some(true)) = (&self.payload, self.crc_valid) {
            let header_bytes = if self.rate > 0 { 2 } else { ti.header_bytes };
            if header_bytes > 0 && p.len() >= header_bytes + 2 {
                let llid = p[0] & 3;
                let body = &p[header_bytes..p.len() - 2];
                let what = match llid {
                    3 => format!("LMP opcode={}", body.first().map(|b| b >> 1).unwrap_or(0)),
                    2 => "L2CAP start".into(),
                    1 if body.is_empty() => "empty".into(),
                    1 => "L2CAP cont".into(),
                    _ => "LLID0".into(),
                };
                s += &format!(" len={} {}", body.len(), what);
                if is_inquiry_lap(self.lap) {
                    if let Some(n) = parse_ad(body).name {
                        s += &format!(" EIR name=\"{n}\"");
                    }
                }
            }
            s += " CRC ok";
        } else if self.rate > 0 {
            s += " payload CRC mismatch (encrypted or bit errors)";
        } else if self.payload.is_none() && type_info(pt).has_crc {
            s += " (payload not decoded)";
        }
        if let Some(q) = self.edr_quality {
            s += &format!(" sync={q:.2}");
        }
        s
    }
}

/// Decoded payload of a BR packet.
#[derive(Clone, Debug)]
pub struct Payload {
    pub bytes: Vec<u8>,
    pub crc_valid: Option<bool>,
    pub corrected: u32,
    /// 0 = basic rate, 1 = EDR 2 Mbit/s, 2 = EDR 3 Mbit/s.
    pub rate: u8,
    pub edr_quality: Option<f32>,
}

fn dewhitened(coded_info: &[u8], clk6: u8) -> Vec<u8> {
    let mut b = coded_info.to_vec();
    whiten(&mut b, clk6, 18);
    b
}

/// Decode the payload of a basic-rate ACL packet (or FHS). Returns `None`
/// if the type carries no verifiable payload or the bits do not decode.
pub fn decode_payload(coded: &[u8], soft: &[f32], ptype: u8, uap: u8, clk6: u8) -> Option<Payload> {
    let fec23 = |n: usize| {
        if soft.len() >= n {
            fec23_decode_soft(&coded[..n], &soft[..n])
        } else {
            fec23_decode(&coded[..n])
        }
    };
    let ti = type_info(ptype);
    if ptype <= 1 {
        return Some(Payload {
            bytes: Vec::new(),
            crc_valid: None,
            corrected: 0,
            rate: 0,
            edr_quality: None,
        });
    }
    if !ti.has_crc || matches!(ptype, 12 | 13) {
        return None;
    }
    // number of information bits for the whole payload
    let total_bits = if ti.header_bytes == 0 {
        (ti.max_payload + 2) * 8
    } else {
        let hdr_bits = ti.header_bytes * 8;
        let hdr = match ti.fec {
            Fec::Rate23 => {
                let need = hdr_bits.div_ceil(10) * 15;
                if coded.len() < need {
                    return None;
                }
                fec23(need)?.0
            }
            _ => {
                if coded.len() < hdr_bits {
                    return None;
                }
                coded[..hdr_bits].to_vec()
            }
        };
        let hdr = dewhitened(&hdr[..hdr_bits], clk6);
        let len = if ti.header_bytes == 1 {
            bits::to_u64(&hdr[3..8]) as usize
        } else {
            bits::to_u64(&hdr[3..13]) as usize
        };
        if len > ti.max_payload {
            return None;
        }
        (ti.header_bytes + len + 2) * 8
    };
    let (info, corrected) = match ti.fec {
        Fec::Rate23 => {
            let need = total_bits.div_ceil(10) * 15;
            if coded.len() < need {
                return None;
            }
            fec23(need)?
        }
        Fec::None => {
            if coded.len() < total_bits {
                return None;
            }
            (coded[..total_bits].to_vec(), 0)
        }
        Fec::Rate13 => return None,
    };
    let info = dewhitened(&info[..total_bits], clk6);
    let bytes = bits::pack_lsb(&info);
    let n = bytes.len();
    let crc_ok = crc16(uap, &bytes[..n - 2]) == bytes[n - 2..];
    Some(Payload {
        bytes,
        crc_valid: Some(crc_ok),
        corrected,
        rate: 0,
        edr_quality: None,
    })
}

/// Maximum EDR payload symbols (3-DH5 / 2-DH5 plus margin).
const MAX_EDR_SYMBOLS: usize = 2750;

/// Bits per symbol and maximum user payload of the EDR ACL packet types.
pub fn edr_acl_type(ptype: u8) -> Option<(usize, usize)> {
    match ptype {
        4 => Some((2, 54)),
        8 => Some((3, 83)),
        10 => Some((2, 367)),
        11 => Some((3, 552)),
        14 => Some((2, 679)),
        15 => Some((3, 1021)),
        _ => None,
    }
}

pub fn edr_type_name(ptype: u8) -> Option<&'static str> {
    Some(match ptype {
        4 => "2-DH1",
        8 => "3-DH1",
        10 => "2-DH3",
        11 => "3-DH3",
        14 => "2-DH5",
        15 => "3-DH5",
        _ => return None,
    })
}

/// Interpret demodulated DPSK bits as an EDR ACL payload (2-byte payload
/// header, body, CRC) for a guessed (UAP, clock).
pub fn decode_edr_payload(dp: &DpskBits, ptype: u8, uap: u8, clk6: u8) -> Option<Payload> {
    let (bps, max_len) = edr_acl_type(ptype)?;
    if dp.bits.len() < 16 {
        return None;
    }
    let hdr = dewhitened(&dp.bits[..16], clk6);
    let len = bits::to_u64(&hdr[3..13]) as usize;
    if len > max_len {
        return None;
    }
    let total = (2 + len + 2) * 8;
    if dp.bits.len() < total {
        return None;
    }
    let bytes = bits::pack_lsb(&dewhitened(&dp.bits[..total], clk6));
    let n = bytes.len();
    let crc_ok = crc16(uap, &bytes[..n - 2]) == bytes[n - 2..];
    Some(Payload {
        bytes,
        crc_valid: Some(crc_ok),
        corrected: 0,
        rate: (bps - 1) as u8,
        edr_quality: Some(dp.sync_quality),
    })
}

/// IQ samples of a packet and its lazily demodulated DPSK payloads.
#[derive(Clone, Debug)]
struct EdrCache {
    ctx: EdrContext,
    dqpsk: OnceCell<Option<DpskBits>>,
    d8psk: OnceCell<Option<DpskBits>>,
}

impl EdrCache {
    fn bits(&self, demod: &EdrDemod, bps: usize) -> Option<&DpskBits> {
        let cell = if bps == 2 { &self.dqpsk } else { &self.d8psk };
        cell.get_or_init(|| demod.demodulate(&self.ctx, bps, MAX_EDR_SYMBOLS))
            .as_ref()
    }
}

/// Can a packet of this TYPE, sent in the slot whose master clock is
/// `clk6`, plausibly last `air_bits` microseconds? Besides the length this
/// uses one protocol rule: POLL is only sent by the master, and the master
/// only transmits in slots with CLK1 = 0.
fn type_plausible(ptype: u8, air_bits: usize, clk6: u8) -> bool {
    if ptype == 1 && clk6 & 1 == 1 {
        return false;
    }
    // The measured length runs from the preamble to the end of the energy,
    // so it includes the transmitter's power ramp-down: real radios add up
    // to ~20 us to the nominal packet length.
    // Minimum lengths: DM1 >= 171 us (126 + 45), DH1 >= 150, 2-DH1 >= 160,
    // AUX1 >= 134. Keeping NULL/POLL and DM1 apart matters: the clock aliases
    // created by the linear whitening turn POLL into DM1 and NULL into FHS.
    let n = air_bits as i64;
    match ptype {
        0 | 1 => (116..=152).contains(&n), // nominal 126 us
        2 => (352..=395).contains(&n),     // nominal 366 us
        3 => (165..=400).contains(&n),
        9 => (130..=400).contains(&n),
        4..=8 => (145..=400).contains(&n),
        10..=13 => (145..=1660).contains(&n),
        _ => (145..=2910).contains(&n),
    }
}

fn header_mask(clk6: u8) -> u32 {
    let mut b = [0u8; 18];
    whiten(&mut b, clk6, 0);
    bits::to_u32(&b)
}

/// A packet waiting for its piconet's UAP/clock to be discovered.
#[derive(Clone, Debug)]
struct RawPacket {
    time: f64,
    rf_channel: u8,
    lap: u32,
    ac_errors: u8,
    header_w: u32,
    header_corrected: u8,
    payload_coded: Vec<u8>,
    payload_soft: Vec<f32>,
    air_bits: usize,
    signal_dbm: i8,
    noise_dbm: i8,
    /// Samples for EDR demodulation (packets longer than POLL/NULL).
    edr: Option<Box<EdrCache>>,
}

pub struct Piconet {
    pub lap: u32,
    pub uap: Option<u8>,
    clk: Option<(f64, u8)>,
    votes: Vec<u16>,
    /// Packets that cast at least one vote since the last reset.
    voters: u16,
    t_first: f64,
    buffer: Vec<RawPacket>,
    pub first_seen: f64,
    pub last_seen: f64,
    pub packets: u64,
    pub decoded: u64,
    pub channels: std::collections::BTreeSet<u8>,
}

impl Piconet {
    fn new(lap: u32, t: f64) -> Self {
        Self {
            lap,
            uap: None,
            clk: None,
            votes: vec![0; 256 * 64],
            voters: 0,
            t_first: t,
            buffer: Vec::new(),
            first_seen: t,
            last_seen: t,
            packets: 0,
            decoded: 0,
            channels: Default::default(),
        }
    }

    pub fn clock_known(&self) -> bool {
        self.clk.is_some()
    }
}

#[derive(Default, Debug, Clone)]
pub struct BrStats {
    pub id_packets: u64,
    pub header_packets: u64,
    pub decoded_headers: u64,
    pub crc_ok: u64,
    /// Packets with an EDR (DPSK) payload detected.
    pub edr_detected: u64,
    /// EDR packets whose payload CRC is valid.
    pub edr_crc_ok: u64,
}

pub struct BrDecoder {
    cfg: BrConfig,
    masks: [u32; 64],
    piconets: HashMap<u32, Piconet>,
    notes: Vec<String>,
    edr: EdrDemod,
    pub stats: BrStats,
}

impl BrDecoder {
    pub fn new(cfg: BrConfig) -> Self {
        let mut masks = [0u32; 64];
        for (c, m) in masks.iter_mut().enumerate() {
            *m = header_mask(c as u8);
        }
        Self {
            cfg,
            masks,
            piconets: HashMap::new(),
            notes: Vec::new(),
            edr: EdrDemod::new(),
            stats: BrStats::default(),
        }
    }

    pub fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    pub fn piconets(&self) -> impl Iterator<Item = &Piconet> {
        self.piconets.values()
    }

    /// Search a demodulated burst for a BR access code; returns true if one
    /// was found (decoded packets may be delivered later, once the piconet's
    /// UAP is known).
    pub fn process(
        &mut self,
        d: &Demodulated,
        burst: &Burst,
        info: &BurstInfo,
        out: &mut Vec<BrPacket>,
    ) -> bool {
        let Some(rf) = rf_channel_from_mhz(info.freq_mhz) else {
            return false;
        };
        let bits = &d.bits;
        if bits.len() < 72 {
            return false;
        }
        // Many radios transmit tens of microseconds of unmodulated carrier
        // before the access code, so search well past the energy onset.
        let lo = (d.core_start_bit + 4).saturating_sub(8);
        let hi = (d.core_start_bit + SEARCH_AFTER_ONSET).min(bits.len() - 64);
        let mut found = None;
        for p in lo..=hi {
            let sw = bits::to_u64(&bits[p..p + 64]);
            if let Some((lap, errs)) = check_syncword(sw, self.cfg.max_ac_errors) {
                found = Some((p, lap, errs));
                break;
            }
        }
        let Some((p, lap, errs)) = found else {
            return false;
        };
        let start = p.saturating_sub(4);
        let air_bits = d.core_end_bit.saturating_sub(start);
        let time = d.bit_time(start);
        let signal_dbm = clamp_i8(info.signal_db + self.cfg.rssi_offset);
        let noise_dbm = clamp_i8(info.noise_db + self.cfg.rssi_offset);

        let hdr_start = p + 64 + 4;
        if air_bits < 100 || hdr_start + 54 > bits.len() {
            self.stats.id_packets += 1;
            let pn = self
                .piconets
                .entry(lap)
                .or_insert_with(|| Piconet::new(lap, time));
            pn.last_seen = time;
            pn.packets += 1;
            pn.channels.insert(rf);
            out.push(BrPacket {
                time,
                rf_channel: rf,
                lap,
                uap: if is_inquiry_lap(lap) { None } else { pn.uap },
                clk6: None,
                kind: BrKind::Id,
                ac_errors: errs as u8,
                header: 0,
                header_corrected: 0,
                hec_valid: false,
                payload: None,
                crc_valid: None,
                payload_corrected: 0,
                transport: TRANSPORT_IGNORED,
                signal_dbm,
                noise_dbm,
                air_bits,
                rate: 0,
                edr_quality: None,
            });
            return true;
        }
        self.stats.header_packets += 1;
        let (hdr, corrected) = if self.cfg.soft_decisions {
            fec13_decode_soft(&d.soft[hdr_start..hdr_start + 54])
        } else {
            fec13_decode(&bits[hdr_start..hdr_start + 54])
        };
        let end = (d.core_end_bit + 6).min(bits.len());
        let raw = RawPacket {
            time,
            rf_channel: rf,
            lap,
            ac_errors: errs as u8,
            header_w: bits::to_u32(&hdr),
            header_corrected: corrected as u8,
            payload_coded: bits[(hdr_start + 54).min(end)..end].to_vec(),
            payload_soft: if self.cfg.soft_decisions {
                d.soft[(hdr_start + 54).min(end)..end].to_vec()
            } else {
                Vec::new()
            },
            air_bits,
            signal_dbm,
            noise_dbm,
            // An EDR packet is at least 126 + 5 + 11 + 16 + 2 us long.
            edr: (air_bits >= 150).then(|| {
                let per_bit = burst.sample_rate / 1e6;
                Box::new(EdrCache {
                    ctx: EdrContext {
                        samples: burst.samples.clone(),
                        sample_rate: burst.sample_rate,
                        header_end: d.sample_of_bit0 + per_bit * (hdr_start + 54) as f64
                            - per_bit / 2.0,
                        cfo_hz: d.cfo_hz,
                    },
                    dqpsk: OnceCell::new(),
                    d8psk: OnceCell::new(),
                })
            }),
        };
        if is_inquiry_lap(lap) {
            let pkt = self.decode_brute(&raw, 0, true);
            out.push(pkt);
            return true;
        }
        self.handle_piconet_packet(raw, out);
        true
    }

    fn base_packet(raw: &RawPacket) -> BrPacket {
        BrPacket {
            time: raw.time,
            rf_channel: raw.rf_channel,
            lap: raw.lap,
            uap: None,
            clk6: None,
            kind: BrKind::Full,
            ac_errors: raw.ac_errors,
            header: raw.header_w,
            header_corrected: raw.header_corrected,
            hec_valid: false,
            payload: None,
            crc_valid: None,
            payload_corrected: 0,
            transport: TRANSPORT_ANY,
            signal_dbm: raw.signal_dbm,
            noise_dbm: raw.noise_dbm,
            air_bits: raw.air_bits,
            rate: 0,
            edr_quality: None,
        }
    }

    /// Fill in header/payload for a known (UAP, clock).
    fn finish_packet(
        &mut self,
        raw: &RawPacket,
        uap: u8,
        clk6: u8,
        payload: Option<Payload>,
    ) -> BrPacket {
        let mut pkt = Self::base_packet(raw);
        let h = raw.header_w ^ self.masks[clk6 as usize];
        pkt.uap = Some(uap);
        pkt.clk6 = Some(clk6);
        pkt.header = h;
        pkt.hec_valid = header_valid(uap, h);
        self.stats.decoded_headers += 1;
        if let Some(pl) = payload {
            pkt.rate = pl.rate;
            pkt.edr_quality = pl.edr_quality;
            if pl.rate > 0 {
                self.stats.edr_detected += 1;
            }
            if pl.crc_valid == Some(true) {
                self.stats.crc_ok += 1;
                if pl.rate > 0 {
                    self.stats.edr_crc_ok += 1;
                }
                pkt.transport = TRANSPORT_ACL | pl.rate;
                pkt.payload_corrected = pl.corrected as i16;
                pkt.crc_valid = Some(true);
                pkt.payload = Some(pl.bytes);
            } else if pl.crc_valid.is_none() {
                pkt.payload = (!pl.bytes.is_empty()).then_some(pl.bytes);
            } else if pl.rate > 0 {
                // EDR modulation found but the payload CRC does not match
                // (encrypted or bit errors): report the rate only.
                pkt.transport = TRANSPORT_ANY | pl.rate;
            }
        }
        pkt
    }

    /// Decode a payload as basic rate and, failing that, as EDR.
    fn decode_any(&self, raw: &RawPacket, ptype: u8, uap: u8, clk6: u8) -> Option<Payload> {
        let br = decode_payload(&raw.payload_coded, &raw.payload_soft, ptype, uap, clk6);
        if br.as_ref().is_some_and(|p| p.crc_valid == Some(true)) {
            return br;
        }
        let (Some((bps, _)), Some(cache)) = (edr_acl_type(ptype), raw.edr.as_ref()) else {
            return br;
        };
        let Some(dp) = cache.bits(&self.edr, bps) else {
            return br;
        };
        match decode_edr_payload(dp, ptype, uap, clk6) {
            Some(p) if p.crc_valid == Some(true) => Some(p),
            _ => Some(Payload {
                bytes: Vec::new(),
                crc_valid: Some(false),
                corrected: 0,
                rate: (bps - 1) as u8,
                edr_quality: Some(dp.sync_quality),
            }),
        }
    }

    /// Try all 64 clocks with a fixed UAP (inquiry: DCI = 0). With
    /// `require_crc`, only accept a clock confirmed by a payload CRC.
    fn decode_brute(&mut self, raw: &RawPacket, uap: u8, require_crc: bool) -> BrPacket {
        let mut hec_only = None;
        for c in 0..64u8 {
            let h = raw.header_w ^ self.masks[c as usize];
            if !header_valid(uap, h) {
                continue;
            }
            let pt = ((h >> 3) & 0xF) as u8;
            if !type_plausible(pt, raw.air_bits, c) {
                continue;
            }
            if let Some(pl) = self.decode_any(raw, pt, uap, c) {
                if pl.crc_valid == Some(true) {
                    return self.finish_packet(raw, uap, c, Some(pl));
                }
            }
            if hec_only.is_none() {
                hec_only = Some(c);
            }
        }
        let mut pkt = Self::base_packet(raw);
        if !is_inquiry_lap(raw.lap) {
            pkt.uap = Some(uap);
        }
        if !require_crc {
            if let Some(c) = hec_only {
                return self.finish_packet(raw, uap, c, None);
            }
        }
        pkt
    }

    fn handle_piconet_packet(&mut self, raw: RawPacket, out: &mut Vec<BrPacket>) {
        let lap = raw.lap;
        let known_uap = self.cfg.known_uaps.get(&lap).copied();
        let pn = self.piconets.entry(lap).or_insert_with(|| {
            let mut p = Piconet::new(lap, raw.time);
            p.uap = known_uap;
            p
        });
        pn.last_seen = raw.time;
        pn.packets += 1;
        pn.channels.insert(raw.rf_channel);
        if pn.clk.is_some() {
            let pkt = self.decode_locked(&raw);
            out.push(pkt);
            return;
        }
        // Discovery: vote, buffer, and see whether a pair stands out.
        if raw.time - pn.t_first > 8.0 {
            // slot grid drift makes old votes useless; start over
            pn.votes.iter_mut().for_each(|v| *v = 0);
            pn.voters = 0;
            pn.t_first = raw.time;
        }
        let fixed_uap = pn.uap;
        let s = ((raw.time - pn.t_first) / SLOT).round() as i64;
        let mut new_votes: Vec<(usize, u16)> = Vec::new();
        for c in 0..64u8 {
            let h = raw.header_w ^ self.masks[c as usize];
            let pt = ((h >> 3) & 0xF) as u8;
            if !type_plausible(pt, raw.air_bits, c) {
                continue;
            }
            let u = uap_from_header(h);
            if fixed_uap.is_some_and(|f| f != u) {
                continue;
            }
            let mut w = 1u16;
            if type_info(pt).has_crc {
                if let Some(pl) = self.decode_any(&raw, pt, u, c) {
                    if pl.crc_valid == Some(true) {
                        w = 5;
                    }
                }
            }
            let c0 = (c as i64 - s).rem_euclid(64) as usize;
            new_votes.push((u as usize * 64 + c0, w));
        }
        let pn = self.piconets.get_mut(&lap).unwrap();
        if !new_votes.is_empty() {
            pn.voters = pn.voters.saturating_add(1);
        }
        for (idx, w) in new_votes {
            pn.votes[idx] = pn.votes[idx].saturating_add(w);
        }
        pn.buffer.push(raw);
        let (mut best, mut best_i, mut second) = (0u16, 0usize, 0u16);
        for (i, &v) in pn.votes.iter().enumerate() {
            if v > best {
                second = best;
                best = v;
                best_i = i;
            } else if v > second {
                second = v;
            }
        }
        // The true (UAP, clock) pair collects a vote from nearly every packet.
        // Because whitening is linear, a few other pairs collect votes from a
        // fixed fraction of the packets (partial aliases, up to ~40 %), so a
        // pair that clearly dominates the packet count is accepted as well.
        let dominant = best >= 8
            && best as u32 * 10 >= pn.voters as u32 * 6
            && best as u32 * 2 >= second as u32 * 3;
        if (best >= 6 && best >= 3 * second) || dominant {
            let uap = (best_i / 64) as u8;
            let c0 = (best_i % 64) as u8;
            pn.uap = Some(uap);
            pn.clk = Some((pn.t_first, c0));
            let buffered = std::mem::take(&mut pn.buffer);
            self.notes.push(format!(
                "BR piconet LAP={lap:06x}: UAP={uap:02x} and clock discovered after {} packets",
                buffered.len()
            ));
            for r in buffered {
                let pkt = self.decode_locked(&r);
                out.push(pkt);
            }
            return;
        }
        // Flush packets that waited too long (emitted undecoded).
        let now = pn.last_seen;
        let mut keep = Vec::new();
        for r in std::mem::take(&mut pn.buffer) {
            if now - r.time > 4.0 || keep.len() > 400 {
                let mut pkt = Self::base_packet(&r);
                pkt.uap = pn.uap;
                out.push(pkt);
            } else {
                keep.push(r);
            }
        }
        pn.buffer = keep;
    }

    /// Decode a packet of a piconet whose UAP and clock are known.
    fn decode_locked(&mut self, raw: &RawPacket) -> BrPacket {
        let pn = &self.piconets[&raw.lap];
        let uap = pn.uap.unwrap();
        let (t_ref, c_ref) = pn.clk.unwrap();
        let dt = raw.time - t_ref;
        let s = (dt / SLOT).round() as i64;
        let pred = (c_ref as i64 + s).rem_euclid(64) as u8;
        let window = (2.0 + dt.abs() * 0.1).min(31.0) as i64;
        let mut best: Option<(u8, Option<Payload>, bool)> = None; // (clk, payload, crc_ok)
        for k in 0..=(2 * window) {
            let delta = if k % 2 == 0 { k / 2 } else { -(k + 1) / 2 };
            let c = (pred as i64 + delta).rem_euclid(64) as u8;
            let h = raw.header_w ^ self.masks[c as usize];
            if !header_valid(uap, h) {
                continue;
            }
            let pt = ((h >> 3) & 0xF) as u8;
            let pl = self.decode_any(raw, pt, uap, c);
            let crc_ok = pl.as_ref().is_some_and(|p| p.crc_valid == Some(true));
            if crc_ok {
                best = Some((c, pl, true));
                break;
            }
            if best.is_none() && delta.abs() <= 1 && type_plausible(pt, raw.air_bits, c) {
                best = Some((c, pl, false));
            }
        }
        if best.is_none() {
            // Clock lost (long gap) or FHS with special whitening: brute force,
            // accepting only CRC-confirmed results.
            let pkt = self.decode_brute(raw, uap, true);
            if let Some(c) = pkt.clk6 {
                let pn = self.piconets.get_mut(&raw.lap).unwrap();
                pn.clk = Some((raw.time, c));
                pn.decoded += 1;
            }
            return pkt;
        }
        let (c, pl, _) = best.unwrap();
        let pn = self.piconets.get_mut(&raw.lap).unwrap();
        pn.clk = Some((raw.time, c));
        pn.decoded += 1;
        self.finish_packet(raw, uap, c, pl)
    }

    /// Emit everything still waiting for discovery (end of capture).
    pub fn flush(&mut self, out: &mut Vec<BrPacket>) {
        for pn in self.piconets.values_mut() {
            for r in std::mem::take(&mut pn.buffer) {
                let mut pkt = Self::base_packet(&r);
                pkt.uap = pn.uap;
                out.push(pkt);
            }
        }
    }
}
