use anyhow::{Context, bail};
use btsdr::ble::decoder::BleConfig;
use btsdr::bredr::decoder::BrConfig;
use btsdr::pcap::{
    LINKTYPE_BLUETOOTH_BREDR_BB, LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR, PacketSink, PcapNgWriter,
    PcapWriter,
};
use btsdr::pipeline::{self, CaptureConfig};
use btsdr::report::Reporter;
use btsdr::source::IqSource;
use btsdr::source::file::{FileSource, IqFormat};
use btsdr::source::hackrf::{self, HackRfConfig, HackRfSource};
use clap::{Args, Parser, Subcommand};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "btsdr",
    version,
    about = "Bluetooth LE + BR (Classic) sniffer for the HackRF One with PCAP/PCAPNG output for Wireshark"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Capture and decode Bluetooth traffic (live from a HackRF or from an IQ file)
    Capture(CaptureArgs),
    /// List connected HackRF devices
    Devices {
        /// Path to the libhackrf shared library
        #[arg(long)]
        hackrf_lib: Option<PathBuf>,
    },
    /// Generate a synthetic IQ recording with LE and BR traffic (no hardware needed)
    Synth(SynthArgs),
    /// Install or remove btsdr as a Wireshark extcap capture interface
    Extcap {
        #[command(subcommand)]
        action: ExtcapAction,
    },
}

#[derive(Subcommand)]
enum ExtcapAction {
    /// Copy btsdr into Wireshark's personal extcap folder
    Install {
        /// Install into this folder instead
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Remove btsdr from Wireshark's personal extcap folder
    Uninstall {
        /// Remove from this folder instead
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show Wireshark's personal extcap folder
    Path,
}

#[derive(Args)]
struct CaptureArgs {
    /// Centre frequency in MHz (integer; Bluetooth channels lie on a 1 MHz grid)
    #[arg(short = 'f', long, default_value_t = 2426)]
    center: u32,
    /// Sample rate in Msps (even, 4..=20); one 1 MHz channel per Msps
    #[arg(short = 's', long, default_value_t = 20)]
    rate: u32,
    /// Channels to decode in MHz, e.g. "2402,2426,2430-2434" (default: all channels
    /// at least 2 MHz inside the captured band)
    #[arg(short = 'c', long)]
    channels: Option<String>,

    /// Read IQ samples from a file instead of a HackRF
    #[arg(short = 'i', long, value_name = "FILE")]
    input: Option<PathBuf>,
    /// Sample format of --input
    #[arg(long, value_enum, default_value = "auto")]
    format: IqFormat,

    /// Write LE and BR packets to one PCAPNG file ("-" = stdout, e.g. for `wireshark -k -i -`)
    #[arg(short = 'w', long, value_name = "FILE")]
    pcapng: Option<PathBuf>,
    /// Write LE packets to a PCAP file (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR)
    #[arg(long, value_name = "FILE")]
    ble_pcap: Option<PathBuf>,
    /// Write BR packets to a PCAP file (LINKTYPE_BLUETOOTH_BREDR_BB)
    #[arg(long, value_name = "FILE")]
    bredr_pcap: Option<PathBuf>,
    /// Also save the raw IQ stream (signed 8-bit) for later offline analysis
    #[arg(long, value_name = "FILE")]
    record: Option<PathBuf>,
    /// Stop after this many seconds
    #[arg(short = 't', long)]
    duration: Option<f64>,

    /// HackRF LNA (IF) gain in dB (0-40, steps of 8)
    #[arg(long, default_value_t = 32)]
    lna: u32,
    /// HackRF VGA (baseband) gain in dB (0-62, steps of 2)
    #[arg(long, default_value_t = 20)]
    vga: u32,
    /// Enable the HackRF RF amplifier (+14 dB)
    #[arg(long)]
    amp: bool,
    /// Enable antenna port power (bias tee)
    #[arg(long)]
    bias_tee: bool,
    /// Baseband filter bandwidth in MHz (default: 75% of the sample rate)
    #[arg(long)]
    bb_filter: Option<f64>,
    /// Serial number of the HackRF to use
    #[arg(long)]
    serial: Option<String>,
    /// Path to the libhackrf shared library (default: search common locations)
    #[arg(long)]
    hackrf_lib: Option<PathBuf>,

    /// Burst detection threshold above the noise floor in dB
    #[arg(long, default_value_t = 8.0)]
    squelch: f32,
    /// Do not decode Bluetooth LE
    #[arg(long)]
    no_ble: bool,
    /// Do not decode Bluetooth BR (Classic)
    #[arg(long)]
    no_bredr: bool,
    /// Do not discover LE connections whose CONNECT_IND was not captured
    #[arg(long)]
    no_promiscuous: bool,
    /// Keep LE packets with a bad CRC
    #[arg(long)]
    keep_bad_crc: bool,
    /// Hard decisions only: no LE CRC repair, no soft BR FEC decoding
    #[arg(long)]
    hard_decisions: bool,
    /// Bit errors tolerated in a BR sync word (0-2)
    #[arg(long, default_value_t = 2)]
    max_ac_errors: u32,
    /// Bit errors tolerated in an LE access address
    #[arg(long, default_value_t = 2)]
    max_aa_errors: u32,
    /// Follow an LE connection: ACCESS_ADDRESS:CRC_INIT in hex (repeatable)
    #[arg(long, value_name = "AA:CRCINIT")]
    follow: Vec<String>,
    /// Known UAP of a BR piconet: LAP:UAP in hex (repeatable)
    #[arg(long, value_name = "LAP:UAP")]
    uap: Vec<String>,
    /// Added to the dBFS signal/noise levels written to the capture
    #[arg(long, default_value_t = 0.0, allow_hyphen_values = true)]
    rssi_offset: f32,
    /// Do not print packets, only the summary
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Status line interval in seconds (0 = off)
    #[arg(long, default_value_t = 5.0)]
    status: f64,
}

#[derive(Args)]
struct SynthArgs {
    /// Output file (signed 8-bit interleaved IQ)
    #[arg(short = 'o', long)]
    output: PathBuf,
    /// Centre frequency in MHz
    #[arg(short = 'f', long, default_value_t = 2426)]
    center: u32,
    /// Sample rate in Msps
    #[arg(short = 's', long, default_value_t = 20)]
    rate: u32,
    /// Duration in seconds
    #[arg(short = 't', long, default_value_t = 0.25)]
    duration: f64,
    /// Signal-to-noise ratio per 1 MHz channel in dB
    #[arg(long, default_value_t = 25.0)]
    snr: f64,
    /// Random seed
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Add realistic radio impairments (carrier offset and drift,
    /// modulation index spread, phase noise)
    #[arg(long)]
    impaired: bool,
}

fn parse_hex_pair(s: &str, what: &str) -> anyhow::Result<(u32, u32)> {
    let (a, b) = s
        .split_once(':')
        .with_context(|| format!("{what} must look like XXXX:YYYY (hex)"))?;
    let p = |x: &str| u32::from_str_radix(x.trim().trim_start_matches("0x"), 16);
    Ok((p(a)?, p(b)?))
}

fn open_output(path: &Path) -> anyhow::Result<(Box<dyn Write + Send>, bool)> {
    if path.as_os_str() == "-" {
        Ok((Box::new(std::io::stdout()), true))
    } else {
        let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
        Ok((Box::new(BufWriter::new(f)), false))
    }
}

fn capture(a: CaptureArgs) -> anyhow::Result<()> {
    let channels = match &a.channels {
        Some(s) => btsdr::extcap::parse_channel_list(s)?,
        None => CaptureConfig::default_channels(a.center, a.rate),
    };
    let mut sinks: Vec<Box<dyn PacketSink>> = Vec::new();
    let mut stdout_used = false;
    if let Some(p) = &a.pcapng {
        let (w, is_stdout) = open_output(p)?;
        stdout_used |= is_stdout;
        sinks.push(Box::new(PcapNgWriter::new(w, true)?));
    }
    if let Some(p) = &a.ble_pcap {
        let (w, is_stdout) = open_output(p)?;
        stdout_used |= is_stdout;
        sinks.push(Box::new(PcapWriter::new(
            w,
            LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR,
            true,
        )?));
    }
    if let Some(p) = &a.bredr_pcap {
        let (w, is_stdout) = open_output(p)?;
        stdout_used |= is_stdout;
        sinks.push(Box::new(PcapWriter::new(
            w,
            LINKTYPE_BLUETOOTH_BREDR_BB,
            true,
        )?));
    }
    let console: Box<dyn Write + Send> = if stdout_used {
        Box::new(std::io::stderr())
    } else {
        Box::new(std::io::stdout())
    };
    let mut reporter = Reporter::new(console, a.quiet, a.keep_bad_crc);

    let follow = a
        .follow
        .iter()
        .map(|s| parse_hex_pair(s, "--follow"))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut known_uaps = HashMap::new();
    for s in &a.uap {
        let (lap, uap) = parse_hex_pair(s, "--uap")?;
        known_uaps.insert(lap & 0xFF_FFFF, uap as u8);
    }
    let ble = (!a.no_ble).then(|| BleConfig {
        promiscuous: !a.no_promiscuous,
        keep_bad_crc: a.keep_bad_crc,
        max_aa_errors: a.max_aa_errors,
        rssi_offset: a.rssi_offset,
        crc_repair: !a.hard_decisions,
        ..Default::default()
    });
    let bredr = (!a.no_bredr).then(|| BrConfig {
        max_ac_errors: a.max_ac_errors.min(2),
        rssi_offset: a.rssi_offset,
        known_uaps,
        soft_decisions: !a.hard_decisions,
    });
    if ble.is_none() && bredr.is_none() {
        bail!("nothing to decode (--no-ble and --no-bredr)");
    }

    let source: Box<dyn IqSource> = match &a.input {
        Some(p) => Box::new(FileSource::new(p, a.format)?),
        None => Box::new(HackRfSource::new(HackRfConfig {
            serial: a.serial.clone(),
            library: a.hackrf_lib.clone(),
            center_hz: a.center as u64 * 1_000_000,
            sample_rate: a.rate as f64 * 1e6,
            baseband_filter_hz: a.bb_filter.map(|m| (m * 1e6) as u32),
            lna_gain: a.lna.min(40) / 8 * 8,
            vga_gain: a.vga.min(62) / 2 * 2,
            amp: a.amp,
            bias_tee: a.bias_tee,
            verbose: true,
        })),
    };
    let wall_start_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let cfg = CaptureConfig {
        center_mhz: a.center,
        sample_rate_mhz: a.rate,
        channels_mhz: channels.clone(),
        squelch_db: a.squelch,
        ble,
        bredr,
        follow,
        max_duration: a.duration,
        record: a.record.clone(),
        wall_start_ns,
        status_interval: (a.status > 0.0).then_some(a.status),
    };
    eprintln!(
        "btsdr {}: {} MHz +- {} MHz, decoding {} channels ({}..{} MHz){}{}",
        env!("CARGO_PKG_VERSION"),
        a.center,
        a.rate / 2,
        channels.len(),
        channels.first().copied().unwrap_or(0),
        channels.last().copied().unwrap_or(0),
        if cfg.ble.is_some() { ", LE" } else { "" },
        if cfg.bredr.is_some() { ", BR" } else { "" },
    );
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || {
            if stop.swap(true, Ordering::SeqCst) {
                std::process::exit(130);
            }
            eprintln!("\nstopping (press Ctrl-C again to abort)...");
        })
        .context("installing Ctrl-C handler")?;
    }
    let stats = pipeline::run(source, cfg, sinks, &mut reporter, stop)?;
    let secs = stats.source.samples as f64 / (a.rate as f64 * 1e6);
    eprintln!(
        "Processed {:.2} s of samples in {:.2} s ({:.2}x real time), {} bursts ({} wideband/Wi-Fi ignored), {} LE + {} BR packets{}",
        secs,
        stats.elapsed,
        if stats.elapsed > 0.0 {
            secs / stats.elapsed
        } else {
            0.0
        },
        stats.bursts,
        stats.wideband,
        stats.ble_packets,
        stats.br_packets,
        if stats.source.dropped > 0 {
            format!(
                ", {:.1}% of samples DROPPED (CPU too slow or USB overloaded)",
                100.0 * stats.source.dropped as f64 / stats.source.samples.max(1) as f64
            )
        } else {
            String::new()
        }
    );
    let clip = stats.clipped as f64 / stats.source.samples.max(1) as f64;
    if clip > 1e-4 {
        eprintln!(
            "WARNING: {:.3}% of samples were clipped by the ADC. A strong transmitter close to the \
             antenna saturates the HackRF, which distorts the whole band (EDR/PSK suffers first). \
             Lower --lna and/or --vga, or move the antenna away.",
            100.0 * clip
        );
    }
    Ok(())
}

fn devices(lib: Option<PathBuf>) -> anyhow::Result<()> {
    let (path, ver, devs) = hackrf::list_devices(lib.as_deref())?;
    println!("libhackrf: {path} (version {ver})");
    if devs.is_empty() {
        println!("no HackRF found");
    }
    for (i, d) in devs.iter().enumerate() {
        println!(
            "{i}: {} serial={} firmware={}",
            d.board, d.serial, d.firmware
        );
    }
    Ok(())
}

fn synth(a: SynthArgs) -> anyhow::Result<()> {
    let (data, info) = btsdr::synth::demo_scenario(
        a.center,
        a.rate,
        a.duration,
        a.snr,
        a.seed,
        if a.impaired {
            btsdr::synth::Impairments::REALISTIC
        } else {
            btsdr::synth::Impairments::IDEAL
        },
    );
    std::fs::write(&a.output, &data).with_context(|| format!("writing {}", a.output.display()))?;
    eprintln!(
        "wrote {} ({:.2} s at {} Msps, centre {} MHz): {} LE advertising, {} + {} LE data, {} BR piconet packets (LAP {:06x}, UAP {:02x}), {} inquiry IDs, 1 FHS ({})",
        a.output.display(),
        a.duration,
        a.rate,
        a.center,
        info.adv_packets,
        info.conn_packets,
        info.hidden_packets,
        info.br_packets,
        info.br_lap,
        info.br_uap,
        info.inquiry_ids,
        info.fhs_bd_addr
    );
    eprintln!(
        "decode with: btsdr capture -i {} -f {} -s {} -w demo.pcapng",
        a.output.display(),
        a.center,
        a.rate
    );
    Ok(())
}

fn extcap_cmd(action: ExtcapAction) -> anyhow::Result<()> {
    match action {
        ExtcapAction::Install { dir } => {
            let dest = btsdr::extcap::install(dir.as_deref())?;
            println!("Installed {}", dest.display());
            println!(
                "Restart Wireshark (or use Capture > Refresh Interfaces) and pick one of the interfaces:"
            );
            for i in &btsdr::extcap::INTERFACES {
                println!("  {} ({})", i.display, i.value);
            }
            println!("Re-run this command after updating btsdr; the extcap folder holds a copy.");
        }
        ExtcapAction::Uninstall { dir } => match btsdr::extcap::uninstall(dir.as_deref())? {
            Some(p) => println!("Removed {}", p.display()),
            None => println!("btsdr is not installed there"),
        },
        ExtcapAction::Path => {
            let (dir, from_wireshark) = btsdr::extcap::personal_extcap_dir()?;
            println!("{}", dir.display());
            if !from_wireshark {
                eprintln!(
                    "(guessed: tshark was not found; check Help > About Wireshark > Folders > Personal Extcap path)"
                );
            }
        }
    }
    Ok(())
}

fn main() {
    // Wireshark runs extcap tools with --extcap-* options instead of a subcommand.
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if btsdr::extcap::is_extcap_invocation(&args) {
        std::process::exit(btsdr::extcap::main(&args));
    }
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Capture(a) => capture(a),
        Cmd::Devices { hackrf_lib } => devices(hackrf_lib),
        Cmd::Synth(a) => synth(a),
        Cmd::Extcap { action } => extcap_cmd(action),
    };
    if let Err(e) = r {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
