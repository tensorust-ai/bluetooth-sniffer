//! Capture pipeline: source thread -> DSP thread (channelizer + burst
//! detection) -> decoder (demodulation, LE/BR link layers, outputs).

use crate::ble::decoder::{BleConfig, BleDecoder, BurstInfo};
use crate::bredr::decoder::{BrConfig, BrDecoder};
use crate::dsp::burst::{Burst, BurstDetector, BurstParams};
use crate::dsp::channelizer::Channelizer;
use crate::dsp::demod::GfskDemod;
use crate::pcap::PacketSink;
use crate::report::Reporter;
use crate::source::{IqBlock, IqSource, SourceStats};
use anyhow::{Context, bail};
use crossbeam_channel::RecvTimeoutError;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Oversampling of the channelizer outputs (2 samples per 1 Msym/s symbol).
pub const OVERSAMPLE: usize = 2;
/// Prototype filter taps per PFB branch.
pub const TAPS_PER_BRANCH: usize = 16;
/// One-sided -6 dB bandwidth used by the GFSK demodulator.
pub const GFSK_CUTOFF_HZ: f64 = 600e3;

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    pub center_mhz: u32,
    pub sample_rate_mhz: u32,
    pub channels_mhz: Vec<u32>,
    pub squelch_db: f32,
    pub ble: Option<BleConfig>,
    pub bredr: Option<BrConfig>,
    /// LE connections to follow from the start: (AA, CRCInit).
    pub follow: Vec<(u32, u32)>,
    pub max_duration: Option<f64>,
    pub record: Option<PathBuf>,
    /// Wall-clock time (ns since the Unix epoch) of sample 0.
    pub wall_start_ns: u64,
    /// Print a status line every N seconds of wall time.
    pub status_interval: Option<f64>,
}

impl CaptureConfig {
    /// Default set of channels: all 1 MHz channels whose centre is at least
    /// 2 MHz inside the band edge, restricted to the 2.4 GHz Bluetooth band.
    pub fn default_channels(center_mhz: u32, rate_mhz: u32) -> Vec<u32> {
        let half = (rate_mhz / 2) as i64 - 2;
        (-half..=half)
            .map(|k| center_mhz as i64 + k)
            .filter(|f| (2402..=2480).contains(f))
            .map(|f| f as u32)
            .collect()
    }

    fn validate(&self) -> anyhow::Result<Vec<usize>> {
        let m = self.sample_rate_mhz as usize;
        if !(4..=20).contains(&m) || m % OVERSAMPLE != 0 {
            bail!("sample rate must be an even number of MHz between 4 and 20");
        }
        if self.channels_mhz.is_empty() {
            bail!("no Bluetooth channels inside the captured bandwidth");
        }
        let mut bins = Vec::new();
        for &f in &self.channels_mhz {
            let k = f as i64 - self.center_mhz as i64;
            if k.abs() >= (m / 2) as i64 {
                bail!(
                    "channel {f} MHz is outside the captured band ({} MHz +- {} MHz)",
                    self.center_mhz,
                    m / 2
                );
            }
            bins.push(k.rem_euclid(m as i64) as usize);
        }
        Ok(bins)
    }
}

#[derive(Default, Debug, Clone)]
pub struct CaptureStats {
    pub source: SourceStats,
    pub bursts: u64,
    /// Bursts discarded as wideband interference (e.g. Wi-Fi).
    pub wideband: u64,
    /// Complex samples with a clipped I or Q component (ADC saturation).
    pub clipped: u64,
    pub ble_packets: u64,
    pub br_packets: u64,
    pub elapsed: f64,
}

struct DspResult {
    samples: u64,
    bursts: u64,
    wideband: u64,
}

/// Number of complex 8-bit samples whose I or Q is at full scale.
pub fn count_clipped_ci8(raw: &[u8]) -> u64 {
    raw.chunks_exact(2)
        .filter(|c| {
            let (i, q) = (c[0] as i8, c[1] as i8);
            i == i8::MAX || i <= -127 || q == i8::MAX || q <= -127
        })
        .count() as u64
}

/// Wi-Fi and other wideband signals switch on in many 1 MHz channels at the
/// same instant with a flat spectrum. A strong Bluetooth packet also shows up
/// in neighbouring channels, but with power falling off quickly away from its
/// own channel. A group of simultaneous bursts is rejected when at least
/// `FLAT_CHANNELS` of them are within 6 dB of the strongest one.
/// Returns a keep-flag per burst (`bursts` must be sorted by onset).
pub fn wideband_filter(bursts: &[Burst], num_channels: usize) -> Vec<bool> {
    const FLAT_CHANNELS: usize = 5;
    let mut keep = vec![true; bursts.len()];
    if num_channels < 2 * FLAT_CHANNELS {
        return keep;
    }
    let onset = |b: &Burst| b.start_index + b.core_start as u64;
    let mut i = 0;
    while i < bursts.len() {
        let mut j = i;
        while j + 1 < bursts.len() && onset(&bursts[j + 1]) - onset(&bursts[i]) <= 4 {
            j += 1;
        }
        let group = &bursts[i..=j];
        if group.len() >= FLAT_CHANNELS {
            let pmax = group.iter().map(|b| b.signal_db).fold(f32::MIN, f32::max);
            let flat = group.iter().filter(|b| b.signal_db >= pmax - 6.0).count();
            if flat >= FLAT_CHANNELS {
                keep[i..=j].iter_mut().for_each(|k| *k = false);
            }
        }
        i = j + 1;
    }
    keep
}

pub fn run(
    source: Box<dyn IqSource>,
    cfg: CaptureConfig,
    mut sinks: Vec<Box<dyn PacketSink>>,
    reporter: &mut Reporter,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<CaptureStats> {
    let bins = cfg.validate()?;
    let fs_in = cfg.sample_rate_mhz as f64 * 1e6;
    let m = cfg.sample_rate_mhz as usize;
    let fs_ch = 1e6 * OVERSAMPLE as f64;
    let max_samples = cfg.max_duration.map(|d| (d * fs_in) as u64);

    let (tx_iq, rx_iq) = crossbeam_channel::bounded::<IqBlock>(256);
    let (tx_burst, rx_burst) = crossbeam_channel::bounded::<Burst>(50_000);

    let started = Instant::now();
    // ---- source thread
    let src_stop = stop.clone();
    let src_thread = std::thread::Builder::new()
        .name("source".into())
        .spawn(move || source.run(tx_iq, src_stop))?;

    // ---- DSP thread
    let mut record = match &cfg.record {
        Some(p) => Some(BufWriter::with_capacity(
            1 << 22,
            File::create(p).with_context(|| format!("creating {}", p.display()))?,
        )),
        None => None,
    };
    let channels = cfg.channels_mhz.clone();
    let squelch = cfg.squelch_db;
    let dsp_stop = stop.clone();
    let clipped = Arc::new(AtomicU64::new(0));
    let dsp_clipped = clipped.clone();
    let mut last_clipped = (0u64, 0u64); // (clipped, samples) at the last status line
    let chz = Channelizer::new(m, OVERSAMPLE, TAPS_PER_BRANCH, bins);
    let extra_delay = -chz.delay_samples() / fs_in;
    let dsp_thread = std::thread::Builder::new().name("dsp".into()).spawn(
        move || -> anyhow::Result<DspResult> {
            let mut chz = chz;
            let params = BurstParams::for_rate(fs_ch, squelch);
            let mut dets: Vec<BurstDetector> = channels
                .iter()
                .map(|&f| BurstDetector::new(f, fs_ch, params))
                .collect();
            let mut outs = vec![Vec::new(); channels.len()];
            let mut samples = 0u64;
            let mut nbursts = 0u64;
            let mut wideband = 0u64;
            let mut bursts = Vec::new();
            for block in rx_iq.iter() {
                match &block {
                    IqBlock::Ci8(v) => {
                        if let Some(r) = record.as_mut() {
                            r.write_all(v)?;
                        }
                        dsp_clipped.fetch_add(count_clipped_ci8(v), Ordering::Relaxed);
                        chz.push_ci8(v);
                    }
                    IqBlock::Cf32(v) => {
                        if let Some(r) = record.as_mut() {
                            let b: Vec<u8> = v
                                .iter()
                                .flat_map(|c| {
                                    [
                                        (c.re * 127.0).round().clamp(-127.0, 127.0) as i8 as u8,
                                        (c.im * 127.0).round().clamp(-127.0, 127.0) as i8 as u8,
                                    ]
                                })
                                .collect();
                            r.write_all(&b)?;
                        }
                        chz.push_cf32(v);
                    }
                    IqBlock::Gap(n) => {
                        if let Some(r) = record.as_mut() {
                            // keep the recording's time base intact
                            r.write_all(&vec![0u8; (*n as usize) * 2])?;
                        }
                        chz.skip(*n);
                        let j = chz.next_output_index();
                        for d in &mut dets {
                            d.resync(j);
                        }
                    }
                }
                samples += block.num_samples();
                chz.process(&mut outs);
                for (d, o) in dets.iter_mut().zip(outs.iter_mut()) {
                    d.process(o, &mut bursts);
                    o.clear();
                }
                bursts.sort_by_key(|b: &Burst| b.start_index + b.core_start as u64);
                let keep = wideband_filter(&bursts, channels.len());
                for (b, k) in bursts.drain(..).zip(keep) {
                    nbursts += 1;
                    if !k {
                        wideband += 1;
                        continue;
                    }
                    if tx_burst.send(b).is_err() {
                        break;
                    }
                }
                if max_samples.is_some_and(|mx| samples >= mx) {
                    dsp_stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
            if let Some(mut r) = record {
                r.flush()?;
            }
            Ok(DspResult {
                samples,
                bursts: nbursts,
                wideband,
            })
        },
    )?;

    // ---- decoder (this thread)
    // GFSK works best with a narrower channel than EDR needs.
    let demod = GfskDemod::with_prefilter(extra_delay, GFSK_CUTOFF_HZ, fs_ch);
    let mut ble = cfg.ble.clone().map(BleDecoder::new);
    let mut br = cfg.bredr.clone().map(BrDecoder::new);
    if let Some(b) = ble.as_mut() {
        for &(aa, crc) in &cfg.follow {
            b.add_connection(aa, crc, 0.0);
        }
    }
    let wall0 = cfg.wall_start_ns;
    let ts = |t: f64| -> u64 { wall0.saturating_add((t.max(0.0) * 1e9) as u64) };
    let mut ble_pkts = Vec::new();
    let mut br_pkts = Vec::new();
    let mut stats = CaptureStats::default();
    let mut last_status = Instant::now();
    let mut sink_error: Option<anyhow::Error> = None;

    let emit = |ble_pkts: &mut Vec<crate::ble::BlePacket>,
                br_pkts: &mut Vec<crate::bredr::decoder::BrPacket>,
                reporter: &mut Reporter,
                sinks: &mut Vec<Box<dyn PacketSink>>,
                stats: &mut CaptureStats|
     -> anyhow::Result<()> {
        for p in ble_pkts.drain(..) {
            stats.ble_packets += 1;
            reporter.ble(&p);
            for s in sinks.iter_mut() {
                s.write_ble(ts(p.time), &p)?;
            }
        }
        for p in br_pkts.drain(..) {
            stats.br_packets += 1;
            reporter.bredr(&p);
            for s in sinks.iter_mut() {
                s.write_bredr(ts(p.time), &p)?;
            }
        }
        Ok(())
    };

    let mut last_keepalive = Instant::now();
    let mut last_t = 0.0;
    loop {
        let burst = match rx_burst.recv_timeout(Duration::from_millis(250)) {
            Ok(b) => Some(b),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if let Some(burst) = burst {
            stats.bursts += 1;
            let info = BurstInfo {
                freq_mhz: burst.freq_mhz,
                signal_db: burst.signal_db,
                noise_db: burst.noise_db,
            };
            if let Some(d) = demod.demodulate(&burst) {
                last_t = d.t0;
                let mut found = false;
                if let Some(b) = br.as_mut() {
                    found = b.process(&d, &burst, &info, &mut br_pkts);
                }
                if !found {
                    if let Some(b) = ble.as_mut() {
                        b.process(&d, &info, &mut ble_pkts);
                    }
                }
            }
        }
        if let Some(b) = ble.as_mut() {
            for n in b.take_notes() {
                reporter.note(&n);
            }
        }
        if let Some(b) = br.as_mut() {
            for n in b.take_notes() {
                reporter.note(&n);
            }
        }
        if sink_error.is_none() {
            let mut r = emit(
                &mut ble_pkts,
                &mut br_pkts,
                reporter,
                &mut sinks,
                &mut stats,
            );
            // Periodic keep-alive lets a pipe reader (Wireshark extcap)
            // that went away be noticed even when no packets arrive.
            if r.is_ok() && last_keepalive.elapsed() >= Duration::from_secs(1) {
                last_keepalive = Instant::now();
                r = sinks
                    .iter_mut()
                    .try_for_each(|s| s.keepalive(ts(last_t)))
                    .map_err(Into::into);
            }
            if let Err(e) = r {
                sink_error = Some(e.context("writing capture output"));
                stop.store(true, Ordering::Relaxed);
            }
        } else {
            ble_pkts.clear();
            br_pkts.clear();
        }
        if let Some(iv) = cfg.status_interval {
            if last_status.elapsed().as_secs_f64() >= iv {
                last_status = Instant::now();
                reporter.flush();
                // ADC clipping since the previous status line
                let c = clipped.load(Ordering::Relaxed);
                let n = (last_t.max(0.0) * fs_in) as u64;
                let (dc, dn) = (c - last_clipped.0, n.saturating_sub(last_clipped.1));
                last_clipped = (c, n);
                let clip = if dc > 0 && dn > 0 {
                    format!(
                        " | ADC CLIPPING {:.3}% - lower --lna/--vga",
                        100.0 * dc as f64 / dn as f64
                    )
                } else {
                    String::new()
                };
                reporter.status(&format!(
                    "[{:>8.1} s] bursts {} | BLE {} | BR {} | queue {}{clip}",
                    last_t,
                    stats.bursts,
                    stats.ble_packets,
                    stats.br_packets,
                    rx_burst.len()
                ));
            }
        }
    }
    if let Some(b) = br.as_mut() {
        b.flush(&mut br_pkts);
    }
    if sink_error.is_none() {
        if let Err(e) = emit(
            &mut ble_pkts,
            &mut br_pkts,
            reporter,
            &mut sinks,
            &mut stats,
        ) {
            sink_error = Some(e);
        }
    }
    for s in sinks.iter_mut() {
        let _ = s.flush();
    }
    reporter.flush();
    stop.store(true, Ordering::Relaxed);

    let dsp = dsp_thread
        .join()
        .map_err(|_| anyhow::anyhow!("DSP thread panicked"))??;
    let src = src_thread
        .join()
        .map_err(|_| anyhow::anyhow!("source thread panicked"))??;
    stats.source = src;
    stats.source.samples = stats.source.samples.max(dsp.samples);
    stats.bursts = dsp.bursts;
    stats.wideband = dsp.wideband;
    stats.clipped = clipped.load(Ordering::Relaxed);
    stats.elapsed = started.elapsed().as_secs_f64();
    reporter.summary(ble.as_ref(), br.as_ref());
    if let Some(e) = sink_error {
        return Err(e);
    }
    Ok(stats)
}
