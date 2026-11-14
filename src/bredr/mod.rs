//! Bluetooth BR/EDR baseband (Basic Rate, GFSK): access codes, FEC, HEC,
//! CRC, whitening and packet-type tables.

pub mod decoder;

use crate::bits::{self, Lfsr7};
use std::collections::HashMap;
use std::sync::OnceLock;

/// 64-bit pseudo-random sequence XOR-ed onto the sync word, air order.
pub const PN: u64 = 0x8384_8D96_BBCC_54FC;
/// BCH(64,30) generator polynomial, octal 260534236651 (degree 34).
pub const BCH_G: u64 = 0o260534236651;

/// General / Dedicated Inquiry Access Codes occupy LAPs 0x9E8B00..=0x9E8B3F.
pub const GIAC: u32 = 0x9E8B33;

pub fn is_inquiry_lap(lap: u32) -> bool {
    (0x9E8B00..=0x9E8B3F).contains(&lap)
}

/// RF channel (0..=78) for a centre frequency in MHz.
pub fn rf_channel_from_mhz(mhz: u32) -> Option<u8> {
    if (2402..=2480).contains(&mhz) {
        Some((mhz - 2402) as u8)
    } else {
        None
    }
}

#[inline]
fn poly_mod(mut v: u64) -> u64 {
    for i in (34..64).rev() {
        if (v >> i) & 1 == 1 {
            v ^= BCH_G << (i - 34);
        }
    }
    v
}

/// The six "barker" bits appended to the LAP (a24..a29, air order).
#[inline]
pub fn barker_bits(lap: u32) -> u64 {
    if (lap >> 23) & 1 == 0 { 0x2C } else { 0x13 }
}

/// Sync word for a LAP (air order: bit 0 is transmitted first).
pub fn syncword(lap: u32) -> u64 {
    let info = (lap as u64 & 0xFF_FFFF) | (barker_bits(lap) << 24);
    let x = info ^ (PN >> 34);
    let parity = poly_mod(x << 34);
    ((x << 34) | parity) ^ PN
}

/// BCH syndrome of a received sync word; zero for a valid code word.
#[inline]
pub fn syndrome(sync: u64) -> u64 {
    poly_mod(sync ^ PN)
}

fn syndrome_table() -> &'static HashMap<u64, u64> {
    static TABLE: OnceLock<HashMap<u64, u64>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut m = HashMap::new();
        for i in 0..64 {
            let e = 1u64 << i;
            m.insert(poly_mod(e), e);
        }
        for i in 0..64 {
            for j in (i + 1)..64 {
                let e = (1u64 << i) | (1u64 << j);
                m.entry(poly_mod(e)).or_insert(e);
            }
        }
        m
    })
}

/// Check a 64-bit candidate sync word. On success returns the LAP and the
/// number of corrected bit errors (at most `max_errors`, which is capped at 2).
pub fn check_syncword(sync: u64, max_errors: u32) -> Option<(u32, u32)> {
    let s = syndrome(sync);
    let (corrected, errors) = if s == 0 {
        (sync, 0)
    } else if max_errors == 0 {
        return None;
    } else {
        let e = *syndrome_table().get(&s)?;
        let n = e.count_ones();
        if n > max_errors {
            return None;
        }
        (sync ^ e, n)
    };
    let lap = ((corrected >> 34) & 0xFF_FFFF) as u32;
    if (corrected >> 58) != barker_bits(lap) {
        return None;
    }
    Some((lap, errors))
}

/// Full 72-bit access code (preamble + sync word + trailer), air order.
pub fn access_code_bits(lap: u32, with_trailer: bool) -> Vec<u8> {
    let sw = syncword(lap);
    let mut v = Vec::with_capacity(72);
    // Preamble 0101 or 1010: its last bit differs from the first sync bit.
    let first = (sw & 1) as u8;
    for i in 0..4 {
        v.push(if (i % 2 == 0) == (first == 1) { 1 } else { 0 });
    }
    bits::push_bits(&mut v, sw, 64);
    if with_trailer {
        // Trailer 1010 or 0101: its first bit differs from the last sync bit.
        let last = ((sw >> 63) & 1) as u8;
        for i in 0..4 {
            v.push(if (i % 2 == 0) == (last == 0) { 1 } else { 0 });
        }
    }
    v
}

/// Rate 1/3 repetition code.
pub fn fec13_encode(bits: &[u8]) -> Vec<u8> {
    bits.iter().flat_map(|&b| [b, b, b]).collect()
}

/// Majority-vote decoding of the rate 1/3 code. Returns the decoded bits and
/// the number of triplets that contained a disagreement.
pub fn fec13_decode(coded: &[u8]) -> (Vec<u8>, u32) {
    let mut errors = 0;
    let out = coded
        .chunks_exact(3)
        .map(|c| {
            let s = c[0] + c[1] + c[2];
            if s == 1 || s == 2 {
                errors += 1;
            }
            (s >= 2) as u8
        })
        .collect();
    (out, errors)
}

/// Soft majority decoding of the rate 1/3 code: each bit is the sign of the
/// sum of its three soft values. Returns the bits and the number of triplets
/// whose hard decisions disagreed.
pub fn fec13_decode_soft(soft: &[f32]) -> (Vec<u8>, u32) {
    let mut errors = 0;
    let out = soft
        .chunks_exact(3)
        .map(|c| {
            let hard = c.iter().filter(|&&v| v > 0.0).count();
            if hard == 1 || hard == 2 {
                errors += 1;
            }
            (c[0] + c[1] + c[2] > 0.0) as u8
        })
        .collect();
    (out, errors)
}

/// (15,10) shortened Hamming code, g(D) = D^5 + D^4 + D^2 + 1.
const FEC23_G: u16 = 0b110101;

fn fec23_parity(data10: u16) -> u16 {
    // Systematic encoding: parity = data(D) * D^5 mod g(D), air order.
    // In air order bit 0 is transmitted first, which corresponds to the
    // highest-degree coefficient of the information polynomial.
    let mut reg: u16 = 0;
    for i in 0..10 {
        let b = (data10 >> i) & 1;
        let fb = ((reg >> 4) & 1) ^ b;
        reg = (reg << 1) & 0x1F;
        if fb == 1 {
            reg ^= FEC23_G & 0x1F;
        }
    }
    // reg bit 4 is transmitted first after the data
    bits::reverse_bits(reg as u64, 5) as u16
}

/// Encode with the rate 2/3 FEC. The input is zero-padded to a multiple of 10.
pub fn fec23_encode(bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len() * 3 / 2 + 15);
    for chunk in bits.chunks(10) {
        let mut block = [0u8; 10];
        block[..chunk.len()].copy_from_slice(chunk);
        let d = bits::to_u64(&block) as u16;
        out.extend_from_slice(&block);
        bits::push_bits(&mut out, fec23_parity(d) as u64, 5);
    }
    out
}

fn fec23_syndrome_table() -> &'static [Option<u16>; 32] {
    static TABLE: OnceLock<[Option<u16>; 32]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [None; 32];
        t[0] = Some(0);
        for pos in 0..15 {
            let e: u16 = 1 << pos;
            let data = e & 0x3FF;
            let par = (e >> 10) & 0x1F;
            let s = fec23_parity(data) ^ par;
            t[s as usize] = Some(e);
        }
        t
    })
}

/// Soft-decision (Chase-2) decoding of the rate 2/3 FEC. Blocks the
/// algebraic decoder cannot correct are retried with every combination of
/// their three least reliable bits flipped; the candidate code word closest
/// to the received soft values wins. Falls back to hard decoding when no
/// soft values are available.
pub fn fec23_decode_soft(coded: &[u8], soft: &[f32]) -> Option<(Vec<u8>, u32)> {
    if soft.len() < coded.len() {
        return fec23_decode(coded);
    }
    let table = fec23_syndrome_table();
    let syndrome = |w: u16| fec23_parity(w & 0x3FF) ^ ((w >> 10) & 0x1F);
    let mut out = Vec::with_capacity(coded.len() * 2 / 3);
    let mut corrected = 0;
    for (block, sb) in coded.chunks_exact(15).zip(soft.chunks_exact(15)) {
        let hard = bits::to_u64(block) as u16;
        let fixed = if let Some(e) = table[syndrome(hard) as usize] {
            hard ^ e
        } else {
            let mut order: Vec<usize> = (0..15).collect();
            order.sort_by(|&a, &b| sb[a].abs().total_cmp(&sb[b].abs()));
            let mut best: Option<(f32, u16)> = None;
            for pattern in 1u16..8 {
                let mut w = hard;
                for (k, &pos) in order.iter().take(3).enumerate() {
                    if pattern & (1 << k) != 0 {
                        w ^= 1 << pos;
                    }
                }
                let Some(e) = table[syndrome(w) as usize] else {
                    continue;
                };
                let cand = w ^ e;
                let diff = cand ^ hard;
                let metric: f32 = (0..15)
                    .filter(|i| diff & (1 << i) != 0)
                    .map(|i| sb[i].abs())
                    .sum();
                if best.is_none_or(|(m, _)| metric < m) {
                    best = Some((metric, cand));
                }
            }
            best?.1
        };
        corrected += (fixed ^ hard).count_ones();
        bits::push_bits(&mut out, (fixed & 0x3FF) as u64, 10);
    }
    Some((out, corrected))
}

/// Decode the rate 2/3 FEC, correcting single-bit errors per 15-bit block.
/// Returns `None` if a block has an uncorrectable error pattern, otherwise
/// the decoded bits (a multiple of 10) and the number of corrected bits.
pub fn fec23_decode(coded: &[u8]) -> Option<(Vec<u8>, u32)> {
    let table = fec23_syndrome_table();
    let mut out = Vec::with_capacity(coded.len() * 2 / 3);
    let mut corrected = 0;
    for block in coded.chunks_exact(15) {
        let word = bits::to_u64(block) as u16;
        let data = word & 0x3FF;
        let par = (word >> 10) & 0x1F;
        let s = fec23_parity(data) ^ par;
        let e = table[s as usize]?;
        if e != 0 {
            corrected += 1;
        }
        bits::push_bits(&mut out, ((word ^ e) & 0x3FF) as u64, 10);
    }
    Some((out, corrected))
}

/// 8-bit header error check over the 10 header bits (air order, LT_ADDR in
/// bits 0..2). Matches the definition used by Wireshark's btbredr_rf.
pub fn hec(uap: u8, header10: u16) -> u8 {
    let mut h: u32 = (header10 as u32 & 0x3FF) ^ (uap.reverse_bits() as u32);
    for _ in 0..10 {
        if h & 1 != 0 {
            h ^= 0xE5 << 1;
        }
        h >>= 1;
    }
    h as u8
}

/// Build the 18-bit header (air order) from its fields, computing the HEC.
pub fn build_header(lt_addr: u8, ptype: u8, flow: bool, arqn: bool, seqn: bool, uap: u8) -> u32 {
    let h10 = (lt_addr as u16 & 7)
        | ((ptype as u16 & 0xF) << 3)
        | ((flow as u16) << 7)
        | ((arqn as u16) << 8)
        | ((seqn as u16) << 9);
    h10 as u32 | ((hec(uap, h10) as u32) << 10)
}

fn uap_from_hec_table() -> &'static [u8; 256] {
    // hec(uap, h) = R(h) ^ R(rev(uap)) is linear; tabulate the inverse of
    // u -> hec(u, 0).
    static TABLE: OnceLock<[u8; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u8; 256];
        for u in 0..=255u8 {
            t[hec(u, 0) as usize] = u;
        }
        t
    })
}

/// Recover the UAP that makes a de-whitened 18-bit header's HEC valid.
pub fn uap_from_header(header18: u32) -> u8 {
    let h10 = (header18 & 0x3FF) as u16;
    let hec_rx = ((header18 >> 10) & 0xFF) as u8;
    uap_from_hec_table()[(hec_rx ^ hec(0, h10)) as usize]
}

pub fn header_valid(uap: u8, header18: u32) -> bool {
    hec(uap, (header18 & 0x3FF) as u16) == ((header18 >> 10) & 0xFF) as u8
}

/// CRC-CCITT as used on BR/EDR payloads, computed over air-order bytes
/// (Wireshark-compatible). Returns the two CRC bytes as transmitted.
pub fn crc16(uap: u8, data: &[u8]) -> [u8; 2] {
    let mut crc: u16 = (uap.reverse_bits() as u16) << 8;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            let x = crc & 1;
            crc >>= 1;
            if x != 0 {
                crc ^= 0x8408;
            }
        }
    }
    crc.to_le_bytes()
}

/// CRC over a bit stream that may not be byte aligned (bit-serial form).
pub fn crc16_bits(uap: u8, data_bits: &[u8]) -> u16 {
    let mut crc: u16 = (uap.reverse_bits() as u16) << 8;
    for &b in data_bits {
        let x = (crc ^ b as u16) & 1;
        crc >>= 1;
        if x != 0 {
            crc ^= 0x8408;
        }
    }
    crc
}

/// De-whiten (or whiten) bits in place starting `skip` bits into the
/// whitening sequence for the given CLK6-1 value.
pub fn whiten(bits: &mut [u8], clk6: u8, skip: usize) {
    let mut l = Lfsr7::bredr(clk6);
    l.skip(skip);
    l.apply(bits);
}

/// Payload FEC scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fec {
    None,
    Rate13,
    Rate23,
}

/// Static description of a BR (basic rate) ACL/SCO packet type.
#[derive(Clone, Copy, Debug)]
pub struct TypeInfo {
    pub name: &'static str,
    pub fec: Fec,
    /// Payload header bytes (0 = none, fixed-size payload).
    pub header_bytes: usize,
    /// Maximum user payload bytes (excluding payload header and CRC), or the
    /// fixed payload size for header-less types.
    pub max_payload: usize,
    pub has_crc: bool,
    pub slots: u8,
}

/// Interpretation of the 4-bit TYPE field for the BR ACL logical transport
/// (plus SCO HV types, which share code points 5..7).
pub fn type_info(ptype: u8) -> TypeInfo {
    let t = |name, fec, header_bytes, max_payload, has_crc, slots| TypeInfo {
        name,
        fec,
        header_bytes,
        max_payload,
        has_crc,
        slots,
    };
    match ptype & 0xF {
        0 => t("NULL", Fec::None, 0, 0, false, 1),
        1 => t("POLL", Fec::None, 0, 0, false, 1),
        2 => t("FHS", Fec::Rate23, 0, 18, true, 1),
        3 => t("DM1", Fec::Rate23, 1, 17, true, 1),
        4 => t("DH1", Fec::None, 1, 27, true, 1),
        5 => t("HV1", Fec::Rate13, 0, 10, false, 1),
        6 => t("HV2", Fec::Rate23, 0, 20, false, 1),
        7 => t("HV3", Fec::None, 0, 30, false, 1),
        8 => t("DV", Fec::None, 0, 0, false, 1),
        9 => t("AUX1", Fec::None, 1, 29, false, 1),
        10 => t("DM3", Fec::Rate23, 2, 121, true, 3),
        11 => t("DH3", Fec::None, 2, 183, true, 3),
        12 => t("EV4", Fec::Rate23, 0, 120, true, 3),
        13 => t("EV5", Fec::None, 0, 180, true, 3),
        14 => t("DM5", Fec::Rate23, 2, 224, true, 5),
        _ => t("DH5", Fec::None, 2, 339, true, 5),
    }
}

/// Number of air bits of a whole BR packet: access code (72), header (54)
/// and the FEC-encoded payload of `payload_info_bits` bits.
pub fn packet_air_bits(fec: Fec, payload_info_bits: usize) -> usize {
    let coded = match fec {
        Fec::None => payload_info_bits,
        Fec::Rate13 => payload_info_bits * 3,
        Fec::Rate23 => payload_info_bits.div_ceil(10) * 15,
    };
    72 + 54 + coded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syncword_matches_known_value() {
        // Sync word for LAP 0x000000 as tabulated by libbtbb (host/air order).
        assert_eq!(syncword(0), 0xb000_0002_c782_0e7e);
    }

    /// The generator-matrix formulation used by libbtbb must agree with our
    /// polynomial encoder for every LAP bit.
    #[test]
    fn syncword_matches_generator_matrix() {
        const DEFAULT_CODEWORD: u64 = 0xb000_0002_c782_0e7e;
        const SW_MATRIX: [u64; 24] = [
            0xfe000002a0d1c014,
            0x01000003f0b9201f,
            0x008000033ae40edb,
            0x004000035fca99b9,
            0x002000036d5dd208,
            0x00100001b6aee904,
            0x00080000db577482,
            0x000400006dabba41,
            0x00020002f46d43f4,
            0x000100017a36a1fa,
            0x00008000bd1b50fd,
            0x000040029c3536aa,
            0x000020014e1a9b55,
            0x0000100265b5d37e,
            0x0000080132dae9bf,
            0x000004025bd5ea0b,
            0x00000203ef526bd1,
            0x000001033511ab3c,
            0x000000819a88d59e,
            0x00000040cd446acf,
            0x00000022a41aabb3,
            0x0000001390b5cb0d,
            0x0000000b0ae27b52,
            0x0000000585713da9,
        ];
        for lap in [
            0x000001u32,
            0x9E8B33,
            0x123456,
            0xABCDEF,
            0x800000,
            0xFFFFFF,
        ] {
            let mut cw = DEFAULT_CODEWORD;
            for (i, row) in SW_MATRIX.iter().enumerate() {
                if lap & (0x800000 >> i) != 0 {
                    cw ^= row;
                }
            }
            assert_eq!(syncword(lap), cw, "LAP {lap:06x}");
        }
    }

    #[test]
    fn syncword_check_and_correct() {
        for lap in [0x9E8B33u32, 0x123456, 0xC0FFEE] {
            let sw = syncword(lap);
            assert_eq!(syndrome(sw), 0);
            assert_eq!(check_syncword(sw, 0), Some((lap, 0)));
            assert_eq!(check_syncword(sw ^ (1 << 17), 2), Some((lap, 1)));
            assert_eq!(check_syncword(sw ^ (1 << 3) ^ (1 << 40), 2), Some((lap, 2)));
            assert_eq!(check_syncword(sw ^ (1 << 3), 0), None);
        }
    }

    #[test]
    fn fec23_matches_generator_matrix() {
        // Generator matrix rows (air order) as used by libbtbb.
        const M: [u16; 10] = [
            0x2c01, 0x5802, 0x1c04, 0x3808, 0x7010, 0x4c20, 0x3440, 0x6880, 0x7d00, 0x5600,
        ];
        for d in 0..1024u16 {
            let mut cw = 0u16;
            for (i, row) in M.iter().enumerate() {
                if d & (1 << i) != 0 {
                    cw ^= row;
                }
            }
            assert_eq!(fec23_parity(d), cw >> 10, "data {d:03x}");
        }
    }

    #[test]
    fn fec23_soft_corrects_double_errors() {
        let data: Vec<u8> = (0..30).map(|i| ((i * 5 + 1) % 3 == 0) as u8).collect();
        let coded = fec23_encode(&data);
        // soft values: confident everywhere except the two flipped bits
        let mut soft: Vec<f32> = coded
            .iter()
            .map(|&b| if b == 1 { 1.0 } else { -1.0 })
            .collect();
        let mut rx = coded.clone();
        for &i in &[2usize, 9, 17, 20] {
            rx[i] ^= 1;
            soft[i] = if rx[i] == 1 { 0.1 } else { -0.1 };
        }
        assert!(fec23_decode(&rx).is_none_or(|(d, _)| d != data));
        let (dec, corrected) = fec23_decode_soft(&rx, &soft).unwrap();
        assert_eq!(dec, data);
        assert_eq!(corrected, 4);
    }

    #[test]
    fn fec13_soft_majority() {
        // two weak wrong votes are outvoted by one strong correct one
        let (b, e) = fec13_decode_soft(&[0.1, 0.2, -2.0, 1.0, 1.0, 1.0]);
        assert_eq!(b, vec![0, 1]);
        assert_eq!(e, 1);
    }

    #[test]
    fn fec23_roundtrip_with_errors() {
        let data: Vec<u8> = (0..40).map(|i| ((i * 7 + 3) % 5 == 0) as u8).collect();
        let mut coded = fec23_encode(&data);
        coded[3] ^= 1;
        coded[15 + 12] ^= 1;
        let (dec, corrected) = fec23_decode(&coded).unwrap();
        assert_eq!(dec, data);
        assert_eq!(corrected, 2);
    }

    /// Wireshark's check: XOR rev(UAP) into the header and divide.
    fn wireshark_check_hec(uap: u8, header: u32) -> bool {
        let mut h = header & 0x3ffff;
        h ^= uap.reverse_bits() as u32;
        for _ in 0..10 {
            if h & 1 != 0 {
                h ^= 0xe5 << 1;
            }
            h >>= 1;
        }
        h == 0
    }

    #[test]
    fn hec_and_uap_recovery() {
        for uap in [0x00u8, 0x47, 0xA5, 0xFF] {
            for h10 in [0u16, 0x1FF, 0x2A5, 0x3FF] {
                let hdr = h10 as u32 | ((hec(uap, h10) as u32) << 10);
                assert!(wireshark_check_hec(uap, hdr));
                assert!(header_valid(uap, hdr));
                assert_eq!(uap_from_header(hdr), uap);
            }
        }
    }

    #[test]
    fn crc_residue_is_zero() {
        let data = [0x12u8, 0x34, 0x56, 0x78, 0x9A];
        let uap = 0x47;
        let crc = crc16(uap, &data);
        let mut all = data.to_vec();
        all.extend_from_slice(&crc);
        assert_eq!(crc16(uap, &all), [0, 0]);
        let bits = crate::bits::unpack_lsb(&data);
        assert_eq!(crc16_bits(uap, &bits).to_le_bytes(), crc);
    }

    /// libbtbb whitening table (127-bit m-sequence) and per-clock offsets.
    /// Checks that our LFSR initialisation maps CLK6-1 exactly like the
    /// field-proven implementation.
    #[test]
    fn whitening_matches_libbtbb_tables() {
        const INDICES: [usize; 64] = [
            99, 85, 17, 50, 102, 58, 108, 45, 92, 62, 32, 118, 88, 11, 80, 2, 37, 69, 55, 8, 20,
            40, 74, 114, 15, 106, 30, 78, 53, 72, 28, 26, 68, 7, 39, 113, 105, 77, 71, 25, 84, 49,
            57, 44, 61, 117, 10, 1, 123, 124, 22, 125, 111, 23, 42, 126, 6, 112, 76, 24, 48, 43,
            116, 0,
        ];
        const WD: [u8; 127] = [
            1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1,
            0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1,
            1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0,
            0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0,
            1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
        ];
        for clk in 0..64u8 {
            let mut bits = vec![0u8; 200];
            whiten(&mut bits, clk, 0);
            let idx = INDICES[clk as usize];
            let expected: Vec<u8> = (0..200).map(|i| WD[(idx + i) % 127]).collect();
            assert_eq!(bits, expected, "clk {clk}");
        }
    }
}
