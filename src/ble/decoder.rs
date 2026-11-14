//! LE packet recovery from demodulated bursts, with connection tracking.
//!
//! * Advertising-channel PDUs are found by correlating with the advertising
//!   access address and validated with CRC init 0x555555.
//! * Connections announced by a CONNECT_IND are followed on every observed
//!   data channel by their access address and CRCInit.
//! * Connections established before the capture started are discovered
//!   promiscuously: a burst whose preamble/AA/length are consistent with its
//!   duration yields a candidate (AA, CRCInit) pair by running the CRC
//!   backwards; a pair seen repeatedly is promoted to a tracked connection.

use super::*;
use crate::bits::{self, Lfsr7};
use crate::dsp::demod::Demodulated;
use std::collections::HashMap;

/// Burst metadata needed by the link-layer decoders.
#[derive(Clone, Copy, Debug)]
pub struct BurstInfo {
    pub freq_mhz: u32,
    pub signal_db: f32,
    pub noise_db: f32,
}

#[derive(Clone, Debug)]
pub struct BleConfig {
    pub promiscuous: bool,
    pub keep_bad_crc: bool,
    pub max_aa_errors: u32,
    pub rssi_offset: f32,
    /// Repeated (AA, CRCInit) observations needed to accept a discovered connection.
    pub discovery_hits: u32,
    /// Repair packets with up to two bit errors using soft decisions.
    pub crc_repair: bool,
}

impl Default for BleConfig {
    fn default() -> Self {
        Self {
            promiscuous: true,
            keep_bad_crc: false,
            max_aa_errors: 2,
            rssi_offset: 0.0,
            discovery_hits: 3,
            crc_repair: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnSource {
    ConnectInd,
    Discovered,
}

#[derive(Clone, Debug)]
pub struct Connection {
    pub access_address: u32,
    pub crc_init: u32,
    crc_init_air: u32,
    pub source: ConnSource,
    pub first_seen: f64,
    pub last_seen: f64,
    pub packets: u64,
    pub interval_ms: Option<f64>,
    pub central: Option<[u8; 6]>,
    pub peripheral: Option<[u8; 6]>,
    expiry: f64,
    last_end: f64,
    last_rf: u8,
    last_dir: Direction,
}

struct Candidate {
    crc_init_air: u32,
    hits: u32,
    last_seen: f64,
    pending: Vec<BlePacket>,
}

/// Packet decoded at a specific bit offset.
struct Decoded {
    pdu: Vec<u8>,
    pdu_bits: Vec<u8>,
    crc: [u8; 3],
    crc_rx: u32,
    end_bit: usize,
}

#[derive(Default, Debug, Clone)]
pub struct BleStats {
    pub adv_packets: u64,
    pub data_packets: u64,
    pub bad_crc: u64,
    /// Packets whose CRC was made valid by flipping unreliable bits.
    pub crc_repaired: u64,
    pub connections_seen: u64,
}

/// Number of least reliable bits considered by the CRC repair.
const REPAIR_CANDIDATES: usize = 12;

pub struct BleDecoder {
    cfg: BleConfig,
    connections: HashMap<u32, Connection>,
    candidates: HashMap<u32, Candidate>,
    notes: Vec<String>,
    last_gc: f64,
    pub stats: BleStats,
}

impl BleDecoder {
    pub fn new(cfg: BleConfig) -> Self {
        Self {
            cfg,
            connections: HashMap::new(),
            candidates: HashMap::new(),
            notes: Vec::new(),
            last_gc: 0.0,
            stats: BleStats::default(),
        }
    }

    /// Informational messages (new connections etc.) since the last call.
    pub fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    pub fn connections(&self) -> impl Iterator<Item = &Connection> {
        self.connections.values()
    }

    /// Track a connection explicitly (e.g. from the command line).
    pub fn add_connection(&mut self, aa: u32, crc_init: u32, now: f64) {
        self.insert_connection(
            aa,
            crc_init,
            ConnSource::Discovered,
            now,
            None,
            None,
            None,
            1e9,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_connection(
        &mut self,
        aa: u32,
        crc_init: u32,
        source: ConnSource,
        now: f64,
        interval_ms: Option<f64>,
        central: Option<[u8; 6]>,
        peripheral: Option<[u8; 6]>,
        expiry: f64,
    ) {
        self.candidates.remove(&aa);
        if !self.connections.contains_key(&aa) {
            self.stats.connections_seen += 1;
        }
        self.connections.insert(
            aa,
            Connection {
                access_address: aa,
                crc_init,
                crc_init_air: crc_init_to_air(crc_init),
                source,
                first_seen: now,
                last_seen: now,
                packets: 0,
                interval_ms,
                central,
                peripheral,
                expiry,
                last_end: f64::NEG_INFINITY,
                last_rf: 255,
                last_dir: Direction::Unknown,
            },
        );
    }

    fn gc(&mut self, now: f64) {
        if now - self.last_gc < 1.0 {
            return;
        }
        self.last_gc = now;
        self.candidates.retain(|_, c| now - c.last_seen < 5.0);
        let mut gone = Vec::new();
        self.connections.retain(|aa, c| {
            let keep = now - c.last_seen < c.expiry;
            if !keep {
                gone.push(*aa);
            }
            keep
        });
        for aa in gone {
            self.notes
                .push(format!("BLE connection AA={aa:08x} timed out"));
        }
    }

    fn crc_init_for(&self, aa: u32) -> u32 {
        if aa == ADV_AA {
            crc_init_to_air(ADV_CRC_INIT)
        } else {
            self.connections[&aa].crc_init_air
        }
    }

    /// Soft-decision CRC repair: flip the `REPAIR_CANDIDATES` least reliable
    /// bits of the packet one and two at a time until the CRC passes.
    /// With 78 trials the chance of accepting a wrong packet is ~5e-6.
    fn repair(
        bits: &[u8],
        soft: &[f32],
        p: usize,
        ci: u8,
        is_adv: bool,
        init: u32,
    ) -> Option<(Decoded, u8)> {
        let (dec0, _) = Self::decode_at(bits, p, ci, is_adv, init)?;
        let start = p + 40;
        let end = dec0.end_bit.min(bits.len()).min(soft.len());
        let mut idx: Vec<usize> = (start..end).collect();
        idx.sort_by(|&a, &b| soft[a].abs().total_cmp(&soft[b].abs()));
        idx.truncate(REPAIR_CANDIDATES);
        let mut work = bits.to_vec();
        let check = |w: &[u8]| {
            Self::decode_at(w, p, ci, is_adv, init)
                .and_then(|(d, calc)| (calc == d.crc_rx).then_some(d))
        };
        for &i in &idx {
            work[i] ^= 1;
            if let Some(d) = check(&work) {
                return Some((d, 1));
            }
            work[i] ^= 1;
        }
        for (k, &i) in idx.iter().enumerate() {
            work[i] ^= 1;
            for &j in &idx[k + 1..] {
                work[j] ^= 1;
                if let Some(d) = check(&work) {
                    return Some((d, 2));
                }
                work[j] ^= 1;
            }
            work[i] ^= 1;
        }
        None
    }

    /// De-whiten and parse a packet whose preamble starts at bit `p`.
    fn decode_at(
        bits: &[u8],
        p: usize,
        ci: u8,
        is_adv: bool,
        crc_init_air: u32,
    ) -> Option<(Decoded, u32)> {
        let start = p + 40;
        if start + 16 > bits.len() {
            return None;
        }
        let mut lfsr = Lfsr7::ble(ci);
        let mut pdu_bits = bits[start..start + 16].to_vec();
        lfsr.apply(&mut pdu_bits);
        let len = bits::to_u32(&pdu_bits[8..16]) as usize;
        let cp = !is_adv && pdu_bits[5] == 1;
        if !is_adv && len > 251 {
            return None;
        }
        let body = if cp { 8 } else { 0 } + len * 8;
        let total = 16 + body;
        if start + total + 24 > bits.len() {
            return None;
        }
        let mut rest = bits[start + 16..start + total + 24].to_vec();
        lfsr.apply(&mut rest);
        pdu_bits.extend_from_slice(&rest[..body]);
        let crc_bits = &rest[body..];
        let crc_rx = bits::to_u32(crc_bits);
        let calc = crc24(crc_init_air, &pdu_bits);
        let mut crc = [0u8; 3];
        crc.copy_from_slice(&bits::pack_lsb(crc_bits));
        Some((
            Decoded {
                pdu: bits::pack_lsb(&pdu_bits),
                pdu_bits,
                crc,
                crc_rx,
                end_bit: start + total + 24,
            },
            calc,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn make_packet(
        &self,
        d: &Demodulated,
        info: &BurstInfo,
        rf: u8,
        p: usize,
        aa: u32,
        dec: &Decoded,
        crc_ok: bool,
        aa_errors: u32,
    ) -> BlePacket {
        BlePacket {
            time: d.bit_time(p),
            rf_channel: rf,
            access_address: aa,
            pdu: dec.pdu.clone(),
            crc: dec.crc,
            crc_checked: true,
            crc_valid: crc_ok,
            aa_errors: aa_errors as u8,
            signal_dbm: clamp_i8(info.signal_db + self.cfg.rssi_offset),
            noise_dbm: clamp_i8(info.noise_db + self.cfg.rssi_offset),
            direction: Direction::Unknown,
            cfo_hz: d.cfo_hz,
            bits_corrected: 0,
        }
    }

    fn assign_direction(conn: &mut Connection, pkt: &mut BlePacket, end_time: f64) {
        let dir = if conn.last_rf == pkt.rf_channel
            && (pkt.time - conn.last_end - 150e-6).abs() < 10e-6
        {
            match conn.last_dir {
                Direction::CentralToPeripheral => Direction::PeripheralToCentral,
                _ => Direction::CentralToPeripheral,
            }
        } else {
            Direction::CentralToPeripheral
        };
        pkt.direction = dir;
        conn.last_dir = dir;
        conn.last_end = end_time;
        conn.last_rf = pkt.rf_channel;
        conn.last_seen = pkt.time;
        conn.packets += 1;
    }

    /// Try to recover LE packets from one demodulated burst.
    pub fn process(&mut self, d: &Demodulated, info: &BurstInfo, out: &mut Vec<BlePacket>) -> bool {
        let Some(rf) = rf_channel_from_mhz(info.freq_mhz) else {
            return false;
        };
        let ci = channel_index(rf);
        let bits = &d.bits;
        if bits.len() < 80 {
            return false;
        }
        let now = d.t0;
        self.gc(now);
        // The preamble may follow the energy onset by tens of microseconds
        // (transmitter ramp-up with unmodulated carrier).
        let lo = d.core_start_bit.saturating_sub(6);
        let hi =
            (d.core_start_bit + crate::bredr::decoder::SEARCH_AFTER_ONSET).min(bits.len() - 80);
        if lo > hi {
            return false;
        }

        // --- known access addresses (advertising + tracked connections)
        let mut matches: Vec<(u32, usize, u32)> = Vec::new(); // (errors, p, aa)
        for p in lo..=hi {
            let w = bits::to_u32(&bits[p + 8..p + 40]);
            let e = (w ^ ADV_AA).count_ones();
            if e <= self.cfg.max_aa_errors {
                matches.push((e, p, ADV_AA));
            }
            for &aa in self.connections.keys() {
                let e = (w ^ aa).count_ones();
                if e <= self.cfg.max_aa_errors {
                    matches.push((e, p, aa));
                }
            }
        }
        matches.sort_by_key(|&(e, p, _)| (e, p));
        let mut bad: Option<BlePacket> = None;
        let mut chosen = None;
        for &(e, p, aa) in &matches {
            let is_adv = aa == ADV_AA;
            let init = self.crc_init_for(aa);
            let Some((dec, calc)) = Self::decode_at(bits, p, ci, is_adv, init) else {
                continue;
            };
            if calc == dec.crc_rx {
                chosen = Some((e, p, aa, dec, 0u8));
                break;
            }
            if bad.is_none() {
                bad = Some(self.make_packet(d, info, rf, p, aa, &dec, false, e));
            }
        }
        if chosen.is_none() && self.cfg.crc_repair {
            // Second pass: flip the least reliable bits of the best candidates.
            for &(e, p, aa) in matches.iter().take(2) {
                let init = self.crc_init_for(aa);
                if let Some((dec, fixed)) = Self::repair(bits, &d.soft, p, ci, aa == ADV_AA, init) {
                    self.stats.crc_repaired += 1;
                    chosen = Some((e, p, aa, dec, fixed));
                    break;
                }
            }
        }
        if let Some((e, p, aa, dec, fixed)) = chosen {
            let is_adv = aa == ADV_AA;
            let mut pkt = self.make_packet(d, info, rf, p, aa, &dec, true, e);
            pkt.bits_corrected = fixed;
            let end_time = d.bit_time(dec.end_bit);
            if is_adv {
                self.stats.adv_packets += 1;
                if let Some(c) = parse_connect_ind(&pkt.pdu) {
                    let interval_ms = c.interval as f64 * 1.25;
                    let expiry = (c.timeout as f64 * 0.01 * 4.0).max(30.0);
                    self.notes.push(format!(
                        "BLE new connection AA={:08x} CRCInit={:06x} central={} peripheral={} interval={:.2}ms",
                        c.access_address,
                        c.crc_init,
                        fmt_addr(&c.initiator),
                        fmt_addr(&c.advertiser),
                        interval_ms
                    ));
                    self.insert_connection(
                        c.access_address,
                        c.crc_init,
                        ConnSource::ConnectInd,
                        pkt.time,
                        Some(interval_ms),
                        Some(c.initiator),
                        Some(c.advertiser),
                        expiry,
                    );
                }
            } else {
                self.stats.data_packets += 1;
                let conn = self.connections.get_mut(&aa).unwrap();
                Self::assign_direction(conn, &mut pkt, end_time);
                if pkt.pdu.len() >= 3 && pkt.pdu[0] & 3 == 3 && pkt.pdu[2] == 0x02 {
                    self.notes.push(format!(
                        "BLE connection AA={aa:08x} terminated (LL_TERMINATE_IND)"
                    ));
                    conn.expiry = conn.expiry.min(2.0);
                }
            }
            out.push(pkt);
            return true;
        }

        // --- promiscuous discovery of unknown connections
        if self.cfg.promiscuous
            && !is_primary_adv(rf)
            && self.promiscuous(d, info, rf, ci, lo, hi, out)
        {
            return true;
        }

        if let Some(p) = bad {
            self.stats.bad_crc += 1;
            if self.cfg.keep_bad_crc {
                out.push(p);
                return true;
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn promiscuous(
        &mut self,
        d: &Demodulated,
        info: &BurstInfo,
        rf: u8,
        ci: u8,
        lo: usize,
        hi: usize,
        out: &mut Vec<BlePacket>,
    ) -> bool {
        let bits = &d.bits;
        for p in lo..=hi {
            if !(0..8).all(|i| bits[p + i] != bits[p + i + 1]) {
                continue;
            }
            let aa = bits::to_u32(&bits[p + 8..p + 40]);
            if !access_address_plausible(aa) || self.connections.contains_key(&aa) {
                continue;
            }
            let Some((dec, _)) = Self::decode_at(bits, p, ci, false, 0) else {
                continue;
            };
            // The packet must end where the energy ends.
            if (dec.end_bit as i64 - d.core_end_bit as i64).abs() > 5 {
                continue;
            }
            let init_air = crc24_reverse(dec.crc_rx, &dec.pdu_bits);
            let pkt = self.make_packet(d, info, rf, p, aa, &dec, true, 0);
            let end_time = d.bit_time(dec.end_bit);
            let c = self.candidates.entry(aa).or_insert(Candidate {
                crc_init_air: init_air,
                hits: 0,
                last_seen: pkt.time,
                pending: Vec::new(),
            });
            if c.crc_init_air != init_air {
                c.crc_init_air = init_air;
                c.hits = 0;
                c.pending.clear();
            }
            c.hits += 1;
            c.last_seen = pkt.time;
            c.pending.push(pkt);
            if c.hits >= self.cfg.discovery_hits {
                let pending = std::mem::take(&mut c.pending);
                let crc_init = crc_init_from_air(init_air);
                self.notes.push(format!(
                    "BLE discovered connection AA={aa:08x} CRCInit={crc_init:06x} (promiscuous)"
                ));
                let t = pending.first().map(|p| p.time).unwrap_or(d.t0);
                self.insert_connection(
                    aa,
                    crc_init,
                    ConnSource::Discovered,
                    t,
                    None,
                    None,
                    None,
                    30.0,
                );
                let conn = self.connections.get_mut(&aa).unwrap();
                let n = pending.len();
                for (i, mut pp) in pending.into_iter().enumerate() {
                    // only the last packet's end time is known precisely
                    let end = if i + 1 == n {
                        end_time
                    } else {
                        pp.time + (pp.pdu.len() + 8) as f64 * 8e-6
                    };
                    Self::assign_direction(conn, &mut pp, end);
                    self.stats.data_packets += 1;
                    out.push(pp);
                }
            }
            return true;
        }
        false
    }
}

pub fn clamp_i8(v: f32) -> i8 {
    v.round().clamp(-127.0, 127.0) as i8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth;

    fn demod_of(bits: Vec<u8>, soft: Vec<f32>, core: (usize, usize)) -> Demodulated {
        Demodulated {
            bits,
            soft,
            t0: 0.0,
            core_start_bit: core.0,
            core_end_bit: core.1,
            cfo_hz: 0.0,
            deviation_hz: 200e3,
        }
    }

    #[test]
    fn soft_repair_fixes_two_weak_bit_errors() {
        let pdu = synth::adv_ind(synth::DEMO_ADV_ADDR, "repair");
        let pkt = synth::ble_packet_bits(ADV_AA, ADV_CRC_INIT, &pdu, 38);
        let mut bits = vec![0u8; 20];
        bits.extend(&pkt);
        bits.extend(vec![0u8; 20]);
        let mut soft: Vec<f32> = bits
            .iter()
            .map(|&b| if b == 1 { 200e3 } else { -200e3 })
            .collect();
        // two errors inside the PDU, both with low confidence
        for i in [100usize, 180] {
            bits[i] ^= 1;
            soft[i] = if bits[i] == 1 { 10e3 } else { -10e3 };
        }
        let core = (20, 20 + pkt.len());
        let info = BurstInfo {
            freq_mhz: 2426,
            signal_db: -30.0,
            noise_db: -60.0,
        };

        let mut dec = BleDecoder::new(BleConfig::default());
        let mut out = Vec::new();
        assert!(dec.process(&demod_of(bits.clone(), soft.clone(), core), &info, &mut out));
        assert_eq!(out[0].pdu, pdu);
        assert!(out[0].crc_valid);
        assert_eq!(out[0].bits_corrected, 2);
        assert_eq!(dec.stats.crc_repaired, 1);

        let mut dec = BleDecoder::new(BleConfig {
            crc_repair: false,
            ..Default::default()
        });
        let mut out = Vec::new();
        assert!(!dec.process(&demod_of(bits, soft, core), &info, &mut out));
        assert_eq!(dec.stats.bad_crc, 1);
    }
}
