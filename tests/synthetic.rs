//! End-to-end test: synthesise a wideband capture with LE and BR traffic,
//! run it through the complete pipeline and check what comes out.

use btsdr::ble::BlePacket;
use btsdr::ble::decoder::BleConfig;
use btsdr::bredr::decoder::{BrConfig, BrKind, BrPacket};
use btsdr::pcap::PacketSink;
use btsdr::pipeline::{self, CaptureConfig};
use btsdr::report::Reporter;
use btsdr::source::MemorySource;
use btsdr::synth::{self, ScenarioInfo};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Collected {
    ble: Vec<BlePacket>,
    br: Vec<BrPacket>,
}

struct Collect(Arc<Mutex<Collected>>);

impl PacketSink for Collect {
    fn write_ble(&mut self, _ts: u64, p: &BlePacket) -> std::io::Result<()> {
        self.0.lock().unwrap().ble.push(p.clone());
        Ok(())
    }
    fn write_bredr(&mut self, _ts: u64, p: &BrPacket) -> std::io::Result<()> {
        self.0.lock().unwrap().br.push(p.clone());
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn run(snr_db: f64, seed: u64) -> (Collected, ScenarioInfo) {
    let (data, info) =
        synth::demo_scenario(2426, 20, 0.25, snr_db, seed, synth::Impairments::IDEAL);
    let cfg = CaptureConfig {
        center_mhz: 2426,
        sample_rate_mhz: 20,
        channels_mhz: CaptureConfig::default_channels(2426, 20),
        squelch_db: 8.0,
        ble: Some(BleConfig::default()),
        bredr: Some(BrConfig::default()),
        follow: vec![],
        max_duration: None,
        record: None,
        wall_start_ns: 0,
        status_interval: None,
    };
    let out = Arc::new(Mutex::new(Collected::default()));
    let mut rep = Reporter::new(Box::new(std::io::sink()), true, false);
    pipeline::run(
        Box::new(MemorySource::new(data)),
        cfg,
        vec![Box::new(Collect(out.clone()))],
        &mut rep,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let c = std::mem::take(&mut *out.lock().unwrap());
    (c, info)
}

fn ratio(got: usize, expected: usize) -> f64 {
    got as f64 / expected.max(1) as f64
}

#[test]
fn decodes_demo_scenario() {
    let (c, info) = run(25.0, 7);

    // LE advertising, all with a valid CRC
    let adv = c
        .ble
        .iter()
        .filter(|p| p.is_advertising() && p.crc_valid)
        .count();
    assert!(
        adv + 1 >= info.adv_packets,
        "advertising {adv}/{}",
        info.adv_packets
    );

    // connection announced by CONNECT_IND
    let conn: Vec<_> = c
        .ble
        .iter()
        .filter(|p| p.access_address == info.conn_aa)
        .collect();
    assert!(
        ratio(conn.len(), info.conn_packets) > 0.95,
        "connection {}/{}",
        conn.len(),
        info.conn_packets
    );
    assert!(conn.iter().all(|p| p.crc_valid));
    // central and peripheral alternate within each event
    let c2p = conn
        .iter()
        .filter(|p| p.direction == btsdr::ble::Direction::CentralToPeripheral)
        .count();
    assert!(
        (c2p as i64 - (conn.len() / 2) as i64).abs() <= 2,
        "directions {c2p}/{}",
        conn.len()
    );

    // connection discovered promiscuously (no CONNECT_IND)
    let hidden = c
        .ble
        .iter()
        .filter(|p| p.access_address == info.hidden_aa)
        .count();
    assert!(
        ratio(hidden, info.hidden_packets) > 0.9,
        "hidden {hidden}/{}",
        info.hidden_packets
    );

    // BR piconet: UAP and clock discovered, headers de-whitened, CRCs valid
    let pico: Vec<_> = c.br.iter().filter(|p| p.lap == info.br_lap).collect();
    let decoded = pico
        .iter()
        .filter(|p| p.clk6.is_some() && p.hec_valid)
        .count();
    assert!(
        ratio(decoded, info.br_packets) > 0.95,
        "BR decoded {decoded}/{}",
        info.br_packets
    );
    assert!(
        pico.iter()
            .filter(|p| p.clk6.is_some())
            .all(|p| p.uap == Some(info.br_uap))
    );
    let crc_ok = pico.iter().filter(|p| p.crc_valid == Some(true)).count();
    assert!(
        crc_ok + 1 >= info.br_crc_packets,
        "BR CRC {crc_ok}/{}",
        info.br_crc_packets
    );

    // EDR: 2-DH1 / 2-DH3 (pi/4-DQPSK) and 3-DH1 (8DPSK) payloads with valid CRC
    let edr: Vec<_> = pico
        .iter()
        .filter(|p| p.rate > 0 && p.crc_valid == Some(true))
        .collect();
    assert!(
        ratio(edr.len(), info.br_edr_packets) > 0.9,
        "EDR {}/{}",
        edr.len(),
        info.br_edr_packets
    );
    for p in &edr {
        let expected_rate = if p.ptype() == Some(8) { 2 } else { 1 };
        assert_eq!(p.rate, expected_rate, "{}", p.describe());
        assert_eq!(p.transport, 0x30 | expected_rate);
    }

    // inquiry
    // inquiry
    let ids =
        c.br.iter()
            .filter(|p| p.kind == BrKind::Id && p.lap == btsdr::bredr::GIAC)
            .count();
    assert!(
        ratio(ids, info.inquiry_ids) > 0.9,
        "inquiry IDs {ids}/{}",
        info.inquiry_ids
    );
    let fhs: Vec<_> = c.br.iter().filter_map(|p| p.fhs()).collect();
    assert_eq!(fhs.len(), 1);
    assert_eq!(fhs[0].bd_addr(), info.fhs_bd_addr);
}

#[test]
fn degrades_gracefully_at_low_snr() {
    let (c, info) = run(14.0, 11);
    let adv = c
        .ble
        .iter()
        .filter(|p| p.is_advertising() && p.crc_valid)
        .count();
    assert!(
        ratio(adv, info.adv_packets) > 0.6,
        "advertising {adv}/{}",
        info.adv_packets
    );
    // no false CRC passes: every LE packet reported valid really is one of ours
    let known = [btsdr::ble::ADV_AA, info.conn_aa, info.hidden_aa];
    assert!(c.ble.iter().all(|p| known.contains(&p.access_address)));
    // the piconet must still be identified correctly
    assert!(
        c.br.iter()
            .filter(|p| p.lap == info.br_lap && p.clk6.is_some())
            .all(|p| p.uap == Some(info.br_uap))
    );
    let decoded =
        c.br.iter()
            .filter(|p| p.lap == info.br_lap && p.clk6.is_some())
            .count();
    assert!(
        ratio(decoded, info.br_packets) > 0.5,
        "BR decoded {decoded}/{}",
        info.br_packets
    );
}
