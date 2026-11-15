//! Wireshark extcap integration.
//!
//! Wireshark runs every executable found in its extcap folders and talks to
//! it through command-line options:
//!
//! * `--extcap-interfaces`: list the capture interfaces this tool provides;
//! * `--extcap-interface X --extcap-dlts`: link-layer type of interface X;
//! * `--extcap-interface X --extcap-config`: options shown in the interface's
//!   settings dialog;
//! * `--extcap-interface X --capture --fifo PATH [options]`: capture,
//!   writing a pcap/pcapng stream into PATH (a FIFO, or a named pipe on
//!   Windows) until Wireshark stops it.
//!
//! When btsdr is started with any `--extcap-*` option (or `--capture`) it
//! speaks this protocol instead of its normal command line. `btsdr extcap
//! install` copies the executable into Wireshark's personal extcap folder.

use crate::ble::decoder::BleConfig;
use crate::bredr::decoder::BrConfig;
use crate::pcap::{
    LINKTYPE_BLUETOOTH_BREDR_BB, LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR, PacketSink, PcapNgWriter,
};
use crate::pipeline::{self, CaptureConfig};
use crate::report::Reporter;
use crate::source::Sweep;
use crate::source::hackrf::{HackRfConfig, HackRfSource};
use anyhow::{Context, bail};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const HELP_URL: &str = "https://github.com/venglin/bluetooth-sniffer";

/// A capture interface offered to Wireshark.
pub struct Interface {
    pub value: &'static str,
    pub display: &'static str,
    pub linktypes: &'static [u16],
    pub dlt_name: &'static str,
    pub dlt_display: &'static str,
}

pub const INTERFACES: [Interface; 3] = [
    Interface {
        value: "btsdr",
        display: "Bluetooth LE + BR/EDR sniffer (HackRF One)",
        linktypes: &[
            LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR,
            LINKTYPE_BLUETOOTH_BREDR_BB,
        ],
        dlt_name: "BLUETOOTH_LE_LL_WITH_PHDR",
        dlt_display: "Bluetooth LE and BR/EDR",
    },
    Interface {
        value: "btsdr-le",
        display: "Bluetooth LE sniffer (HackRF One)",
        linktypes: &[LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR],
        dlt_name: "BLUETOOTH_LE_LL_WITH_PHDR",
        dlt_display: "Bluetooth Low Energy link layer",
    },
    Interface {
        value: "btsdr-bredr",
        display: "Bluetooth BR/EDR sniffer (HackRF One)",
        linktypes: &[LINKTYPE_BLUETOOTH_BREDR_BB],
        dlt_name: "BLUETOOTH_BREDR_BB",
        dlt_display: "Bluetooth BR/EDR baseband",
    },
];

/// Options without a value.
const FLAGS: &[&str] = &[
    "--extcap-interfaces",
    "--extcap-dlts",
    "--extcap-config",
    "--capture",
    "--amp",
    "--bias-tee",
    "--no-promiscuous",
    "--keep-bad-crc",
];

/// True if the process was started by Wireshark as an extcap tool.
pub fn is_extcap_invocation(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|a| a.starts_with("--extcap-") || a == "--capture")
}

#[derive(Default, Debug, Clone)]
pub struct ExtcapArgs {
    pub list_interfaces: bool,
    pub dlts: bool,
    pub config: bool,
    pub capture: bool,
    pub interface: Option<String>,
    pub fifo: Option<String>,
    pub capture_filter: Option<String>,
    /// Remaining options, e.g. "--center" -> Some("2426"), "--amp" -> None.
    pub options: HashMap<String, Option<String>>,
}

/// Lenient parser: accepts `--opt value` and `--opt=value` and keeps
/// options it does not know (newer Wireshark versions add some).
pub fn parse_args(args: &[String]) -> ExtcapArgs {
    let mut r = ExtcapArgs::default();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if !a.starts_with("--") {
            continue;
        }
        let (name, mut value) = match a.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (a.clone(), None),
        };
        if value.is_none()
            && !FLAGS.contains(&name.as_str())
            && i < args.len()
            && !args[i].starts_with("--")
        {
            value = Some(args[i].clone());
            i += 1;
        }
        match name.as_str() {
            "--extcap-interfaces" => r.list_interfaces = true,
            "--extcap-dlts" => r.dlts = true,
            "--extcap-config" => r.config = true,
            "--capture" => r.capture = true,
            "--extcap-interface" => r.interface = value,
            "--fifo" => r.fifo = value,
            "--extcap-capture-filter" => r.capture_filter = value,
            "--extcap-version" => {}
            _ => {
                r.options.insert(name, value);
            }
        }
    }
    r
}

fn find_interface(name: Option<&str>) -> anyhow::Result<&'static Interface> {
    let name = name.context("missing --extcap-interface")?;
    INTERFACES
        .iter()
        .find(|i| i.value == name)
        .with_context(|| format!("unknown extcap interface {name}"))
}

pub fn interfaces_text() -> String {
    let mut s = format!(
        "extcap {{version={}}}{{help={HELP_URL}}}\n",
        env!("CARGO_PKG_VERSION")
    );
    for i in &INTERFACES {
        s += &format!("interface {{value={}}}{{display={}}}\n", i.value, i.display);
    }
    s
}

pub fn dlts_text(iface: &Interface) -> String {
    format!(
        "dlt {{number={}}}{{name={}}}{{display={}}}\n",
        iface.linktypes[0], iface.dlt_name, iface.dlt_display
    )
}

pub fn config_text() -> String {
    let mut s = String::new();
    let mut arg = |n: usize, body: &str| s.push_str(&format!("arg {{number={n}}}{body}\n"));
    arg(
        0,
        "{call=--center}{display=Centre frequency (MHz)}{type=integer}{range=2400,2482}{default=2426}\
         {tooltip=Centre of the captured band. LE advertising channels: 2402, 2426 and 2480 MHz}{group=Radio}",
    );
    arg(
        1,
        "{call=--rate}{display=Sample rate}{type=selector}{default=20}\
         {tooltip=One 1 MHz Bluetooth channel per Msps; lower rates need less CPU}{group=Radio}",
    );
    arg(
        2,
        "{call=--channels}{display=Channels (MHz)}{type=string}{validation=^[0-9, -]*$}\
         {tooltip=Optional list such as 2402,2426,2430-2434. Empty: all channels in the band}{group=Radio}",
    );
    arg(
        3,
        "{call=--lna}{display=LNA gain (dB)}{type=selector}{default=32}{tooltip=HackRF IF gain}{group=Gain}",
    );
    arg(
        4,
        "{call=--vga}{display=VGA gain (dB)}{type=integer}{range=0,62}{default=20}\
         {tooltip=HackRF baseband gain, steps of 2 dB}{group=Gain}",
    );
    arg(
        5,
        "{call=--amp}{display=RF amplifier (+14 dB)}{type=boolflag}{default=false}{group=Gain}",
    );
    arg(
        6,
        "{call=--squelch}{display=Squelch (dB above noise)}{type=double}{range=3,30}{default=8}\
         {tooltip=Burst detection threshold}{group=Decoder}",
    );
    arg(
        7,
        "{call=--no-promiscuous}{display=Do not discover LE connections without CONNECT_IND}\
         {type=boolflag}{default=false}{group=Decoder}",
    );
    arg(
        8,
        "{call=--keep-bad-crc}{display=Keep LE packets with a bad CRC}{type=boolflag}{default=false}{group=Decoder}",
    );
    arg(
        9,
        "{call=--serial}{display=HackRF serial number}{type=string}\
         {tooltip=Leave empty to use the first HackRF}{group=Device}",
    );
    arg(
        10,
        "{call=--bias-tee}{display=Antenna port power (bias tee)}{type=boolflag}{default=false}{group=Device}",
    );
    arg(
        11,
        "{call=--hackrf-lib}{display=libhackrf library}{type=fileselect}{mustexist=true}\
         {tooltip=Leave empty to search the usual install locations}{group=Device}",
    );
    arg(
        12,
        "{call=--record}{display=Also save raw IQ to}{type=fileselect}{mustexist=false}\
         {tooltip=Optional signed 8-bit IQ recording for later offline analysis (not with a sweep)}{group=Device}",
    );
    arg(
        13,
        "{call=--sweep}{display=Sweep the whole band}{type=boolflag}{default=false}\
         {tooltip=Retune through all 79 channels, ignoring the centre frequency and channel list}{group=Radio}",
    );
    arg(
        14,
        "{call=--dwell}{display=Sweep dwell time (s)}{type=double}{range=0.5,60}{default=2}\
         {tooltip=Time on each centre frequency when sweeping}{group=Radio}",
    );
    for (rate, chans, default) in [
        (20, 17, true),
        (16, 13, false),
        (12, 9, false),
        (8, 5, false),
    ] {
        s += &format!(
            "value {{arg=1}}{{value={rate}}}{{display={rate} Msps ({chans} channels)}}{{default={default}}}\n"
        );
    }
    for g in [0, 8, 16, 24, 32, 40] {
        s += &format!(
            "value {{arg=3}}{{value={g}}}{{display={g} dB}}{{default={}}}\n",
            g == 32
        );
    }
    s
}

fn opt_str<'a>(a: &'a ExtcapArgs, name: &str) -> Option<&'a str> {
    a.options
        .get(name)
        .and_then(|v| v.as_deref())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn opt_num<T: std::str::FromStr>(a: &ExtcapArgs, name: &str, default: T) -> anyhow::Result<T> {
    match opt_str(a, name) {
        Some(v) => v
            .parse()
            .ok()
            .with_context(|| format!("invalid value for {name}: {v}")),
        None => Ok(default),
    }
}

fn opt_flag(a: &ExtcapArgs, name: &str) -> bool {
    match a.options.get(name) {
        Some(None) => true,
        Some(Some(v)) => !matches!(v.as_str(), "false" | "0" | ""),
        None => false,
    }
}

/// Parse "2402,2426,2430-2434".
pub fn parse_channel_list(spec: &str) -> anyhow::Result<Vec<u32>> {
    let mut v = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let (a, b): (u32, u32) = (a.trim().parse()?, b.trim().parse()?);
            if a > b {
                bail!("bad channel range {part}");
            }
            v.extend(a..=b);
        } else {
            v.push(
                part.parse()
                    .with_context(|| format!("bad channel {part}"))?,
            );
        }
    }
    v.sort_unstable();
    v.dedup();
    Ok(v)
}

fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::BrokenPipe)
    })
}

fn capture(a: &ExtcapArgs, iface: &Interface) -> anyhow::Result<()> {
    let fifo = a.fifo.as_deref().context("missing --fifo")?;
    if a.capture_filter
        .as_deref()
        .is_some_and(|f| !f.trim().is_empty())
    {
        bail!("capture filters are not supported; use a display filter such as btle or btbredr_rf");
    }
    let rate: u32 = opt_num(a, "--rate", 20)?;
    let sweep = if opt_flag(a, "--sweep") {
        let dwell: f64 = opt_num(a, "--dwell", 2.0)?;
        if dwell < 0.5 {
            bail!("the sweep dwell time must be at least 0.5 s");
        }
        if opt_str(a, "--record").is_some() {
            bail!("a raw IQ recording cannot be combined with a sweep");
        }
        Some(Sweep {
            centers_mhz: pipeline::sweep_centers(rate),
            dwell,
        })
    } else {
        None
    };
    let center: u32 = match &sweep {
        Some(s) => s.centers_mhz[0],
        None => opt_num(a, "--center", 2426)?,
    };
    let channels = match opt_str(a, "--channels").filter(|_| sweep.is_none()) {
        Some(s) => parse_channel_list(s)?,
        None => CaptureConfig::default_channels(center, rate),
    };
    let le = iface
        .linktypes
        .contains(&LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR);
    let br = iface.linktypes.contains(&LINKTYPE_BLUETOOTH_BREDR_BB);
    let ble = le.then(|| BleConfig {
        promiscuous: !opt_flag(a, "--no-promiscuous"),
        keep_bad_crc: opt_flag(a, "--keep-bad-crc"),
        ..Default::default()
    });
    let bredr = br.then(BrConfig::default);
    let lna: u32 = opt_num(a, "--lna", 32)?;
    let vga: u32 = opt_num(a, "--vga", 20)?;
    let source = Box::new(HackRfSource::new(HackRfConfig {
        serial: opt_str(a, "--serial").map(String::from),
        library: opt_str(a, "--hackrf-lib").map(PathBuf::from),
        center_hz: center as u64 * 1_000_000,
        sample_rate: rate as f64 * 1e6,
        baseband_filter_hz: None,
        lna_gain: lna.min(40) / 8 * 8,
        vga_gain: vga.min(62) / 2 * 2,
        amp: opt_flag(a, "--amp"),
        bias_tee: opt_flag(a, "--bias-tee"),
        verbose: false,
        sweep,
    }));
    let cfg = CaptureConfig {
        center_mhz: center,
        sample_rate_mhz: rate,
        channels_mhz: channels,
        squelch_db: opt_num(a, "--squelch", 8.0)?,
        ble,
        bredr,
        follow: Vec::new(),
        max_duration: None,
        record: opt_str(a, "--record").map(PathBuf::from),
        wall_start_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
        status_interval: None,
    };
    let pipe = OpenOptions::new()
        .write(true)
        .open(fifo)
        .with_context(|| format!("opening extcap fifo {fifo}"))?;
    let mut writer = PcapNgWriter::with_interfaces(BufWriter::new(pipe), true, iface.linktypes)?;
    writer.set_keepalive(true);
    let sinks: Vec<Box<dyn PacketSink>> = vec![Box::new(writer)];
    let mut reporter = Reporter::new(Box::new(io::sink()), true, false);
    reporter.set_print_summary(false);
    let stop = Arc::new(AtomicBool::new(false));
    {
        // Wireshark stops extcap tools with SIGTERM (Unix) or by closing the
        // pipe; both end the capture cleanly so the HackRF is released.
        let stop = stop.clone();
        let _ = ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst));
    }
    match pipeline::run(source, cfg, sinks, &mut reporter, stop) {
        Ok(_) => Ok(()),
        // Wireshark closed the pipe: the normal way a capture ends.
        Err(e) if is_broken_pipe(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

fn dispatch(a: &ExtcapArgs) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    if a.list_interfaces {
        out.write_all(interfaces_text().as_bytes())?;
        return Ok(());
    }
    let iface = find_interface(a.interface.as_deref())?;
    if a.dlts {
        out.write_all(dlts_text(iface).as_bytes())?;
    } else if a.config {
        out.write_all(config_text().as_bytes())?;
    } else if a.capture {
        drop(out);
        capture(a, iface)?;
    } else if let Some(f) = &a.capture_filter {
        // Filter validation request: only the empty filter is valid.
        if !f.trim().is_empty() {
            bail!("capture filters are not supported");
        }
    }
    Ok(())
}

/// Entry point for extcap invocations; returns the process exit code.
pub fn main(args: &[String]) -> i32 {
    let a = parse_args(args);
    match dispatch(&a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("btsdr: {e:#}");
            1
        }
    }
}

// ---------------------------------------------------------------- install

fn tshark_candidates() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("tshark")];
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
            if let Some(p) = std::env::var_os(var) {
                v.push(PathBuf::from(p).join("Wireshark").join("tshark.exe"));
            }
        }
    } else if cfg!(target_os = "macos") {
        v.push(PathBuf::from(
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
        ));
    }
    v
}

/// Ask Wireshark (`tshark -G folders`) for its personal extcap folder.
fn extcap_dir_from_tshark() -> Option<PathBuf> {
    for t in tshark_candidates() {
        let Ok(out) = Command::new(&t).args(["-G", "folders"]).output() else {
            continue;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some((key, val)) = line.split_once(':') {
                if key.trim() == "Personal Extcap path" {
                    let p = val.trim();
                    if !p.is_empty() {
                        return Some(PathBuf::from(p));
                    }
                }
            }
        }
    }
    None
}

fn default_extcap_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("Wireshark").join("extcap"))
    } else {
        // Wireshark >= 4.4; older versions use ~/.config/wireshark/extcap
        std::env::var_os("HOME").map(|h| {
            PathBuf::from(h)
                .join(".local")
                .join("lib")
                .join("wireshark")
                .join("extcap")
        })
    }
}

/// Wireshark's personal extcap folder and whether Wireshark itself reported it.
pub fn personal_extcap_dir() -> anyhow::Result<(PathBuf, bool)> {
    if let Some(p) = extcap_dir_from_tshark() {
        return Ok((p, true));
    }
    default_extcap_dir()
        .map(|p| (p, false))
        .context("cannot determine Wireshark's extcap folder; use --dir")
}

fn installed_name() -> String {
    format!("btsdr{}", std::env::consts::EXE_SUFFIX)
}

/// Copy the running executable into `dir` (or the personal extcap folder).
pub fn install(dir: Option<&Path>) -> anyhow::Result<PathBuf> {
    let dir = match dir {
        Some(d) => d.to_path_buf(),
        None => personal_extcap_dir()?.0,
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let dest = dir.join(installed_name());
    let src = std::env::current_exe().context("locating the btsdr executable")?;
    let same = match (src.canonicalize(), dest.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        std::fs::copy(&src, &dest).with_context(|| {
            format!(
                "copying {} to {} (is a capture running in Wireshark?)",
                src.display(),
                dest.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    // Make sure the installed copy answers like Wireshark expects.
    let out = Command::new(&dest)
        .arg("--extcap-interfaces")
        .output()
        .with_context(|| format!("running {}", dest.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !text.starts_with("extcap ") {
        bail!("{} does not respond to --extcap-interfaces", dest.display());
    }
    Ok(dest)
}

pub fn uninstall(dir: Option<&Path>) -> anyhow::Result<Option<PathBuf>> {
    let dir = match dir {
        Some(d) => d.to_path_buf(),
        None => personal_extcap_dir()?.0,
    };
    let dest = dir.join(installed_name());
    if dest.exists() {
        std::fs::remove_file(&dest).with_context(|| format!("removing {}", dest.display()))?;
        Ok(Some(dest))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        std::iter::once("btsdr")
            .chain(s.split_whitespace())
            .map(String::from)
            .collect()
    }

    #[test]
    fn detects_invocation() {
        assert!(is_extcap_invocation(&args("--extcap-interfaces")));
        assert!(is_extcap_invocation(&args("--capture --fifo x")));
        assert!(!is_extcap_invocation(&args("capture -f 2426")));
    }

    #[test]
    fn parses_capture_call() {
        let a = parse_args(&args(
            r"--capture --extcap-interface=btsdr-le --fifo \\.\pipe\wireshark_extcap_1 --center 2410 --amp --lna=24 --extcap-version=4.6 --unknown-new-option 7",
        ));
        assert!(a.capture);
        assert_eq!(a.interface.as_deref(), Some("btsdr-le"));
        assert_eq!(a.fifo.as_deref(), Some(r"\\.\pipe\wireshark_extcap_1"));
        assert_eq!(opt_num(&a, "--center", 0u32).unwrap(), 2410);
        assert_eq!(opt_num(&a, "--lna", 0u32).unwrap(), 24);
        assert_eq!(opt_num(&a, "--vga", 20u32).unwrap(), 20);
        assert!(opt_flag(&a, "--amp"));
        assert!(!opt_flag(&a, "--bias-tee"));
        assert!(a.options.contains_key("--unknown-new-option"));
    }

    #[test]
    fn protocol_text() {
        let i = interfaces_text();
        assert!(i.starts_with("extcap {version="));
        assert_eq!(i.matches("\ninterface {value=").count(), 3);
        assert_eq!(
            dlts_text(&INTERFACES[2]),
            "dlt {number=255}{name=BLUETOOTH_BREDR_BB}{display=Bluetooth BR/EDR baseband}\n"
        );
        let c = config_text();
        assert_eq!(
            c.lines().filter(|l| l.starts_with("arg {number=")).count(),
            15
        );
        assert_eq!(
            c.lines().filter(|l| l.contains("{default=true}")).count(),
            2
        );
        // every line is a sequence of {key=value} groups
        for l in c.lines() {
            assert_eq!(l.matches('{').count(), l.matches('}').count(), "{l}");
        }
    }

    #[test]
    fn channel_list() {
        assert_eq!(
            parse_channel_list("2402, 2426,2430-2432").unwrap(),
            vec![2402, 2426, 2430, 2431, 2432]
        );
        assert!(parse_channel_list("2432-2430").is_err());
    }
}
