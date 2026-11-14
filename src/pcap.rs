//! PCAP and PCAPNG writers with the Bluetooth RF link types understood by
//! Wireshark:
//!
//! * `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` (256): LE link-layer packets with a
//!   10-byte RF pseudo-header.
//! * `LINKTYPE_BLUETOOTH_BREDR_BB` (255): BR/EDR baseband packets with a
//!   22-byte RF pseudo-header.

use crate::ble::{ADV_AA, BlePacket, Direction};
use crate::bredr::decoder::{BrKind, BrPacket};
use std::io::{self, Write};

pub const LINKTYPE_BLUETOOTH_BREDR_BB: u16 = 255;
pub const LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: u16 = 256;

// LE pseudo-header flags
const LE_DEWHITENED: u16 = 0x0001;
const LE_SIGPOWER_VALID: u16 = 0x0002;
const LE_NOISEPOWER_VALID: u16 = 0x0004;
const LE_REF_AA_VALID: u16 = 0x0010;
const LE_AA_OFFENSES_VALID: u16 = 0x0020;
const LE_CRC_CHECKED: u16 = 0x0400;
const LE_CRC_VALID: u16 = 0x0800;

// BR/EDR pseudo-header flags
const BREDR_DEWHITENED: u16 = 0x0001;
const BREDR_SIGPOWER_VALID: u16 = 0x0002;
const BREDR_NOISEPOWER_VALID: u16 = 0x0004;
const BREDR_PAYLOAD_DECRYPTED: u16 = 0x0008;
const BREDR_REFLAP_VALID: u16 = 0x0010;
const BREDR_PAYLOAD_PRESENT: u16 = 0x0020;
const BREDR_REFUAP_VALID: u16 = 0x0080;
const BREDR_HEC_CHECKED: u16 = 0x0100;
const BREDR_HEC_VALID: u16 = 0x0200;
const BREDR_CRC_CHECKED: u16 = 0x0400;
const BREDR_CRC_VALID: u16 = 0x0800;

/// Serialise an LE packet as a LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR record.
pub fn le_record(p: &BlePacket) -> Vec<u8> {
    let mut flags = LE_DEWHITENED
        | LE_SIGPOWER_VALID
        | LE_NOISEPOWER_VALID
        | LE_REF_AA_VALID
        | LE_AA_OFFENSES_VALID;
    if p.crc_checked {
        flags |= LE_CRC_CHECKED;
        if p.crc_valid {
            flags |= LE_CRC_VALID;
        }
    }
    let pdu_type: u16 = match (p.access_address == ADV_AA, p.direction) {
        (true, _) => 0,
        (false, Direction::CentralToPeripheral) => 2,
        (false, Direction::PeripheralToCentral) => 3,
        (false, Direction::Unknown) => 0,
    };
    flags |= pdu_type << 7; // PHY bits (14..15) stay 0 = LE 1M
    let ll = p.ll_bytes();
    let mut v = Vec::with_capacity(10 + ll.len());
    v.push(p.rf_channel);
    v.push(p.signal_dbm as u8);
    v.push(p.noise_dbm as u8);
    v.push(p.aa_errors);
    v.extend_from_slice(&p.access_address.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&ll);
    v
}

/// Serialise a BR packet as a LINKTYPE_BLUETOOTH_BREDR_BB record.
pub fn bredr_record(p: &BrPacket) -> Vec<u8> {
    let mut flags = BREDR_SIGPOWER_VALID | BREDR_NOISEPOWER_VALID | BREDR_REFLAP_VALID;
    let mut ref_lap_uap = p.lap & 0xFF_FFFF;
    if let Some(u) = p.uap {
        flags |= BREDR_REFUAP_VALID;
        ref_lap_uap |= (u as u32) << 24;
    }
    let mut header = 0u32;
    if p.kind == BrKind::Full {
        header = p.header & 0x3FFFF;
        if p.clk6.is_some() {
            flags |= BREDR_DEWHITENED | BREDR_HEC_CHECKED;
            if p.hec_valid {
                flags |= BREDR_HEC_VALID;
            }
        }
    }
    let payload: &[u8] = match &p.payload {
        Some(b) if p.clk6.is_some() => {
            flags |= BREDR_PAYLOAD_PRESENT;
            if let Some(ok) = p.crc_valid {
                flags |= BREDR_CRC_CHECKED;
                if ok {
                    // A valid CRC over the de-whitened payload means the
                    // payload is readable (not E0-encrypted).
                    flags |= BREDR_CRC_VALID | BREDR_PAYLOAD_DECRYPTED;
                }
            }
            b
        }
        _ => &[],
    };
    let mut v = Vec::with_capacity(22 + payload.len());
    v.push(p.rf_channel);
    v.push(p.signal_dbm as u8);
    v.push(p.noise_dbm as u8);
    v.push(p.ac_errors);
    v.push(p.transport);
    v.push(p.header_corrected);
    v.extend_from_slice(&p.payload_corrected.to_le_bytes());
    v.extend_from_slice(&(p.lap & 0xFF_FFFF).to_le_bytes());
    v.extend_from_slice(&ref_lap_uap.to_le_bytes());
    v.extend_from_slice(&header.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// Something that accepts captured packets.
pub trait PacketSink: Send {
    fn write_ble(&mut self, ts_ns: u64, p: &BlePacket) -> io::Result<()>;
    fn write_bredr(&mut self, ts_ns: u64, p: &BrPacket) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
    /// Called about once per second; may write a harmless block so that a
    /// closed pipe is detected even when no packets are captured.
    fn keepalive(&mut self, _ts_ns: u64) -> io::Result<()> {
        Ok(())
    }
}

/// Classic libpcap file (nanosecond timestamps) with a single link type.
pub struct PcapWriter<W: Write + Send> {
    w: W,
    linktype: u16,
    flush_each: bool,
}

impl<W: Write + Send> PcapWriter<W> {
    pub fn new(mut w: W, linktype: u16, flush_each: bool) -> io::Result<Self> {
        w.write_all(&0xA1B2_3C4Du32.to_le_bytes())?; // nanosecond-resolution magic
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&65535u32.to_le_bytes())?;
        w.write_all(&(linktype as u32).to_le_bytes())?;
        if flush_each {
            w.flush()?;
        }
        Ok(Self {
            w,
            linktype,
            flush_each,
        })
    }

    pub fn write_record(&mut self, ts_ns: u64, data: &[u8]) -> io::Result<()> {
        let sec = (ts_ns / 1_000_000_000) as u32;
        let nsec = (ts_ns % 1_000_000_000) as u32;
        self.w.write_all(&sec.to_le_bytes())?;
        self.w.write_all(&nsec.to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w.write_all(data)?;
        if self.flush_each {
            self.w.flush()?;
        }
        Ok(())
    }
}

impl<W: Write + Send> PacketSink for PcapWriter<W> {
    fn write_ble(&mut self, ts_ns: u64, p: &BlePacket) -> io::Result<()> {
        if self.linktype == LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR {
            self.write_record(ts_ns, &le_record(p))?;
        }
        Ok(())
    }
    fn write_bredr(&mut self, ts_ns: u64, p: &BrPacket) -> io::Result<()> {
        if self.linktype == LINKTYPE_BLUETOOTH_BREDR_BB {
            self.write_record(ts_ns, &bredr_record(p))?;
        }
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// PCAPNG file with two interfaces: 0 = LE, 1 = BR/EDR.
pub struct PcapNgWriter<W: Write + Send> {
    w: W,
    flush_each: bool,
    keepalive: bool,
    interfaces: Vec<u16>,
}

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

impl<W: Write + Send> PcapNgWriter<W> {
    /// PCAPNG with both interfaces (0 = LE, 1 = BR/EDR).
    pub fn new(w: W, flush_each: bool) -> io::Result<Self> {
        Self::with_interfaces(
            w,
            flush_each,
            &[
                LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR,
                LINKTYPE_BLUETOOTH_BREDR_BB,
            ],
        )
    }

    /// PCAPNG with the given link types as interfaces 0, 1, ...; packets of
    /// a link type that has no interface are skipped.
    pub fn with_interfaces(mut w: W, flush_each: bool, linktypes: &[u16]) -> io::Result<Self> {
        // Section Header Block
        let app = format!("btsdr {}", env!("CARGO_PKG_VERSION"));
        let mut opts = Vec::new();
        push_option(&mut opts, 4, app.as_bytes()); // shb_userappl
        push_option(&mut opts, 0, &[]);
        let len = 28 + opts.len() as u32;
        w.write_all(&0x0A0D_0D0Au32.to_le_bytes())?;
        w.write_all(&len.to_le_bytes())?;
        w.write_all(&0x1A2B_3C4Du32.to_le_bytes())?;
        w.write_all(&1u16.to_le_bytes())?;
        w.write_all(&0u16.to_le_bytes())?;
        w.write_all(&(-1i64).to_le_bytes())?;
        w.write_all(&opts)?;
        w.write_all(&len.to_le_bytes())?;
        let mut s = Self {
            w,
            flush_each,
            keepalive: false,
            interfaces: linktypes.to_vec(),
        };
        for &lt in linktypes {
            let name = match lt {
                LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR => "bluetooth-le",
                LINKTYPE_BLUETOOTH_BREDR_BB => "bluetooth-bredr",
                _ => "bluetooth",
            };
            s.write_idb(lt, name)?;
        }
        if flush_each {
            s.w.flush()?;
        }
        Ok(s)
    }

    /// Write an (empty) Interface Statistics Block from [`PacketSink::keepalive`].
    pub fn set_keepalive(&mut self, on: bool) {
        self.keepalive = on;
    }

    fn iface(&self, linktype: u16) -> Option<u32> {
        self.interfaces
            .iter()
            .position(|&l| l == linktype)
            .map(|i| i as u32)
    }

    fn write_idb(&mut self, linktype: u16, name: &str) -> io::Result<()> {
        let mut opts = Vec::new();
        push_option(&mut opts, 2, name.as_bytes()); // if_name
        push_option(&mut opts, 9, &[9]); // if_tsresol: 10^-9 s
        push_option(&mut opts, 0, &[]);
        let len = 20 + opts.len() as u32;
        self.w.write_all(&1u32.to_le_bytes())?;
        self.w.write_all(&len.to_le_bytes())?;
        self.w.write_all(&linktype.to_le_bytes())?;
        self.w.write_all(&0u16.to_le_bytes())?;
        self.w.write_all(&0u32.to_le_bytes())?; // snaplen: unlimited
        self.w.write_all(&opts)?;
        self.w.write_all(&len.to_le_bytes())
    }

    pub fn write_epb(&mut self, iface: u32, ts_ns: u64, data: &[u8]) -> io::Result<()> {
        let pad = pad4(data.len());
        let len = (32 + data.len() + pad) as u32;
        self.w.write_all(&6u32.to_le_bytes())?;
        self.w.write_all(&len.to_le_bytes())?;
        self.w.write_all(&iface.to_le_bytes())?;
        self.w.write_all(&((ts_ns >> 32) as u32).to_le_bytes())?;
        self.w.write_all(&(ts_ns as u32).to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w.write_all(data)?;
        self.w.write_all(&[0u8; 3][..pad])?;
        self.w.write_all(&len.to_le_bytes())?;
        if self.flush_each {
            self.w.flush()?;
        }
        Ok(())
    }
}

fn push_option(buf: &mut Vec<u8>, code: u16, val: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(val.len() as u16).to_le_bytes());
    buf.extend_from_slice(val);
    buf.extend(std::iter::repeat_n(0u8, pad4(val.len())));
}

impl<W: Write + Send> PacketSink for PcapNgWriter<W> {
    fn write_ble(&mut self, ts_ns: u64, p: &BlePacket) -> io::Result<()> {
        match self.iface(LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR) {
            Some(i) => self.write_epb(i, ts_ns, &le_record(p)),
            None => Ok(()),
        }
    }
    fn write_bredr(&mut self, ts_ns: u64, p: &BrPacket) -> io::Result<()> {
        match self.iface(LINKTYPE_BLUETOOTH_BREDR_BB) {
            Some(i) => self.write_epb(i, ts_ns, &bredr_record(p)),
            None => Ok(()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
    fn keepalive(&mut self, ts_ns: u64) -> io::Result<()> {
        if !self.keepalive {
            return Ok(());
        }
        // Interface Statistics Block without options (24 bytes).
        self.w.write_all(&5u32.to_le_bytes())?;
        self.w.write_all(&24u32.to_le_bytes())?;
        self.w.write_all(&0u32.to_le_bytes())?;
        self.w.write_all(&((ts_ns >> 32) as u32).to_le_bytes())?;
        self.w.write_all(&(ts_ns as u32).to_le_bytes())?;
        self.w.write_all(&24u32.to_le_bytes())?;
        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcapng_blocks_are_aligned() {
        let mut buf = Vec::new();
        {
            let mut w = PcapNgWriter::new(&mut buf, false).unwrap();
            w.write_epb(0, 123_456_789_000, &[1, 2, 3, 4, 5]).unwrap();
        }
        // walk the blocks
        let mut off = 0;
        let mut types = Vec::new();
        while off < buf.len() {
            let t = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let len = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
            assert_eq!(len % 4, 0);
            let trailer =
                u32::from_le_bytes(buf[off + len - 4..off + len].try_into().unwrap()) as usize;
            assert_eq!(len, trailer);
            types.push(t);
            off += len;
        }
        assert_eq!(types, vec![0x0A0D0D0A, 1, 1, 6]);
    }
}
