//! Packet success rate versus SNR on synthetic captures.
//!
//! ```text
//! cargo run --release --example benchmark -- [--seeds N] [--snr 6,8,10] [--squelch DB] [--hard] [--edr] [--ideal | --impaired]
//! ```
//!
//! Each point runs the demo scenario (LE advertising and connections, a BR
//! piconet, inquiry) through the complete pipeline and reports the fraction
//! of transmitted packets that were decoded with a valid CRC/HEC. SNR is per
//! 1 MHz channel, which equals Eb/N0 at 1 Mbit/s.

use btsdr::ble::BlePacket;
use btsdr::ble::decoder::BleConfig;
use btsdr::bredr::decoder::{BrConfig, BrKind, BrPacket};
use btsdr::pcap::PacketSink;
use btsdr::pipeline::{self, CaptureConfig};
use btsdr::report::Reporter;
use btsdr::source::MemorySource;
use btsdr::synth::{self, Impairments};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Collected {
    ble: Vec<BlePacket>,
    br: Vec<BrPacket>,
}

struct Collect(Arc<Mutex<Collected>>);

impl PacketSink for Collect {
    fn write_ble(&mut self, _: u64, p: &BlePacket) -> std::io::Result<()> {
        self.0.lock().unwrap().ble.push(p.clone());
        Ok(())
    }
    fn write_bredr(&mut self, _: u64, p: &BrPacket) -> std::io::Result<()> {
        self.0.lock().unwrap().br.push(p.clone());
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// (decoded, transmitted) per category
#[derive(Default, Clone, Copy)]
struct Counts {
    adv: (usize, usize),
    le_data: (usize, usize),
    br_sync: (usize, usize),
    br_hdr: (usize, usize),
    br_crc: (usize, usize),
    br_edr: (usize, usize),
    ids: (usize, usize),
}

impl Counts {
    fn add(&mut self, o: &Counts) {
        for (a, b) in [
            (&mut self.adv, o.adv),
            (&mut self.le_data, o.le_data),
            (&mut self.br_sync, o.br_sync),
            (&mut self.br_hdr, o.br_hdr),
            (&mut self.br_crc, o.br_crc),
            (&mut self.br_edr, o.br_edr),
            (&mut self.ids, o.ids),
        ] {
            a.0 += b.0;
            a.1 += b.1;
        }
    }
}

fn run_one(snr: f64, seed: u64, imp: Impairments, squelch: f32, soft: bool) -> Counts {
    let (data, info) = synth::demo_scenario(2426, 20, 0.25, snr, seed, imp);
    let cfg = CaptureConfig {
        center_mhz: 2426,
        sample_rate_mhz: 20,
        channels_mhz: CaptureConfig::default_channels(2426, 20),
        squelch_db: squelch,
        ble: Some(BleConfig {
            crc_repair: soft,
            ..Default::default()
        }),
        bredr: Some(BrConfig {
            soft_decisions: soft,
            ..Default::default()
        }),
        follow: vec![],
        max_duration: None,
        record: None,
        wall_start_ns: 0,
        status_interval: None,
    };
    let out = Arc::new(Mutex::new(Collected::default()));
    let mut rep = Reporter::new(Box::new(std::io::sink()), true, false);
    rep.set_print_summary(false);
    pipeline::run(
        Box::new(MemorySource::new(data)),
        cfg,
        vec![Box::new(Collect(out.clone()))],
        &mut rep,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let c = out.lock().unwrap();
    let cap = |n: usize, m: usize| (n.min(m), m);
    let adv = c
        .ble
        .iter()
        .filter(|p| p.is_advertising() && p.crc_valid)
        .count();
    let data = c
        .ble
        .iter()
        .filter(|p| {
            p.crc_valid && (p.access_address == info.conn_aa || p.access_address == info.hidden_aa)
        })
        .count();
    let pico = || c.br.iter().filter(|p| p.lap == info.br_lap);
    let sync = pico().count();
    let hdr = pico().filter(|p| p.clk6.is_some() && p.hec_valid).count();
    let crc = pico()
        .filter(|p| p.crc_valid == Some(true) && p.rate == 0)
        .count();
    let edr = pico()
        .filter(|p| p.crc_valid == Some(true) && p.rate > 0)
        .count();
    let ids =
        c.br.iter()
            .filter(|p| p.kind == BrKind::Id && p.lap == btsdr::bredr::GIAC)
            .count();
    Counts {
        adv: cap(adv, info.adv_packets),
        le_data: cap(data, info.conn_packets + info.hidden_packets),
        br_sync: cap(sync, info.br_packets),
        br_hdr: cap(hdr, info.br_packets),
        br_crc: cap(crc, info.br_crc_packets),
        br_edr: cap(edr, info.br_edr_packets),
        ids: cap(ids, info.inquiry_ids),
    }
}

/// EDR-only run: (decoded with valid CRC, sent) per EDR type.
fn run_edr(snr: f64, seed: u64, imp: Impairments) -> [(usize, usize); 6] {
    let (data, lap, sent) = synth::edr_scenario(2426, 20, 0.5, snr, seed, imp);
    let cfg = CaptureConfig {
        center_mhz: 2426,
        sample_rate_mhz: 20,
        channels_mhz: CaptureConfig::default_channels(2426, 20),
        squelch_db: 8.0,
        ble: None,
        bredr: Some(BrConfig::default()),
        follow: vec![],
        max_duration: None,
        record: None,
        wall_start_ns: 0,
        status_interval: None,
    };
    let out = Arc::new(Mutex::new(Collected::default()));
    let mut rep = Reporter::new(Box::new(std::io::sink()), true, false);
    rep.set_print_summary(false);
    pipeline::run(
        Box::new(MemorySource::new(data)),
        cfg,
        vec![Box::new(Collect(out.clone()))],
        &mut rep,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let c = out.lock().unwrap();
    let mut res = [(0usize, 0usize); 6];
    for (i, &t) in synth::EDR_SCENARIO_TYPES.iter().enumerate() {
        let ok =
            c.br.iter()
                .filter(|p| {
                    p.lap == lap && p.rate > 0 && p.crc_valid == Some(true) && p.ptype() == Some(t)
                })
                .count();
        res[i] = (ok.min(sent[i]), sent[i]);
    }
    res
}

fn pct(x: (usize, usize)) -> String {
    format!("{:>6.1}", 100.0 * x.0 as f64 / x.1.max(1) as f64)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let seeds: u64 = get("--seeds").map(|s| s.parse().unwrap()).unwrap_or(4);
    let squelch: f32 = get("--squelch").map(|s| s.parse().unwrap()).unwrap_or(8.0);
    let soft = !args.iter().any(|a| a == "--hard");
    let snrs: Vec<f64> = get("--snr")
        .map(|s| s.split(',').map(|x| x.parse().unwrap()).collect())
        .unwrap_or_else(|| vec![6.0, 8.0, 10.0, 12.0, 14.0, 17.0, 20.0]);
    let mut sets = vec![
        ("ideal", Impairments::IDEAL),
        ("impaired", Impairments::REALISTIC),
    ];
    if args.iter().any(|a| a == "--ideal") {
        sets.retain(|s| s.0 == "ideal");
    }
    if args.iter().any(|a| a == "--impaired") {
        sets.retain(|s| s.0 == "impaired");
    }
    if args.iter().any(|a| a == "--edr") {
        for (name, imp) in sets {
            println!(
                "
{name} channel, EDR only ({seeds} seeds per point): % of packets with valid CRC"
            );
            println!("SNR dB   2-DH1  3-DH1  2-DH3  3-DH3  2-DH5  3-DH5");
            for &snr in &snrs {
                let mut tot = [(0usize, 0usize); 6];
                for seed in 1..=seeds {
                    for (t, r) in tot.iter_mut().zip(run_edr(snr, seed * 7919, imp)) {
                        t.0 += r.0;
                        t.1 += r.1;
                    }
                }
                let cols: Vec<String> = tot.iter().map(|&x| pct(x)).collect();
                println!("{snr:>6.1}  {}", cols.join(" "));
            }
        }
        return;
    }
    for (name, imp) in sets {
        println!(
            "\n{name} channel, {} decisions, squelch {squelch} dB, {seeds} seeds per point: % of packets decoded",
            if soft { "soft" } else { "hard" }
        );
        println!("SNR dB  LE adv LE data BR sync  BR hdr  BR CRC  BR EDR   BR ID");
        for &snr in &snrs {
            let mut tot = Counts::default();
            for seed in 1..=seeds {
                tot.add(&run_one(snr, seed * 7919, imp, squelch, soft));
            }
            println!(
                "{snr:>6.1}  {} {} {} {} {} {} {}",
                pct(tot.adv),
                pct(tot.le_data),
                pct(tot.br_sync),
                pct(tot.br_hdr),
                pct(tot.br_crc),
                pct(tot.br_edr),
                pct(tot.ids)
            );
        }
    }
}
