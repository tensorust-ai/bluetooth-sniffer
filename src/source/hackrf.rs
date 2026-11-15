//! HackRF One receiver using libhackrf, loaded at run time.
//!
//! Loading the library dynamically means the binary builds without any
//! native SDK and works with whichever libhackrf the user has installed
//! (PothosSDR / radioconda on Windows, distribution packages on Linux,
//! Homebrew on macOS).

use super::dynlib::DynLib;
use super::{IqBlock, IqSource, SourceStats, Sweep};
use anyhow::{Context, anyhow, bail};
use crossbeam_channel::{Sender, TrySendError};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

#[repr(C)]
struct HackrfTransfer {
    device: *mut c_void,
    buffer: *mut u8,
    buffer_length: c_int,
    valid_length: c_int,
    rx_ctx: *mut c_void,
    tx_ctx: *mut c_void,
}

#[repr(C)]
struct HackrfDeviceList {
    serial_numbers: *mut *mut c_char,
    usb_board_ids: *mut c_int,
    usb_device_index: *mut c_int,
    devicecount: c_int,
    usb_devices: *mut *mut c_void,
    usb_devicecount: c_int,
}

type Dev = *mut c_void;
type RxCallback = unsafe extern "C" fn(*mut HackrfTransfer) -> c_int;

struct Api {
    _lib: DynLib,
    init: unsafe extern "C" fn() -> c_int,
    exit: unsafe extern "C" fn() -> c_int,
    open_by_serial: unsafe extern "C" fn(*const c_char, *mut Dev) -> c_int,
    close: unsafe extern "C" fn(Dev) -> c_int,
    start_rx: unsafe extern "C" fn(Dev, RxCallback, *mut c_void) -> c_int,
    stop_rx: unsafe extern "C" fn(Dev) -> c_int,
    is_streaming: unsafe extern "C" fn(Dev) -> c_int,
    set_sample_rate: unsafe extern "C" fn(Dev, f64) -> c_int,
    set_freq: unsafe extern "C" fn(Dev, u64) -> c_int,
    set_lna_gain: unsafe extern "C" fn(Dev, u32) -> c_int,
    set_vga_gain: unsafe extern "C" fn(Dev, u32) -> c_int,
    set_amp_enable: unsafe extern "C" fn(Dev, u8) -> c_int,
    set_antenna_enable: unsafe extern "C" fn(Dev, u8) -> c_int,
    set_baseband_filter_bandwidth: unsafe extern "C" fn(Dev, u32) -> c_int,
    compute_baseband_filter_bw: unsafe extern "C" fn(u32) -> u32,
    error_name: unsafe extern "C" fn(c_int) -> *const c_char,
    device_list: unsafe extern "C" fn() -> *mut HackrfDeviceList,
    device_list_free: unsafe extern "C" fn(*mut HackrfDeviceList),
    board_id_read: unsafe extern "C" fn(Dev, *mut u8) -> c_int,
    version_string_read: unsafe extern "C" fn(Dev, *mut c_char, u8) -> c_int,
    library_version: Option<unsafe extern "C" fn() -> *const c_char>,
    path: String,
}

fn candidate_paths(explicit: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(p) = explicit {
        v.push(p.to_path_buf());
        return v;
    }
    if let Some(p) = std::env::var_os("HACKRF_LIB") {
        v.push(PathBuf::from(p));
    }
    let names: &[&str] = if cfg!(windows) {
        &["hackrf.dll", "libhackrf.dll"]
    } else if cfg!(target_os = "macos") {
        &["libhackrf.0.dylib", "libhackrf.dylib"]
    } else {
        &["libhackrf.so.0", "libhackrf.so"]
    };
    // next to the executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for n in names {
                v.push(dir.join(n));
            }
        }
    }
    for n in names {
        v.push(PathBuf::from(n));
    }
    if cfg!(windows) {
        let mut dirs: Vec<PathBuf> = vec![PathBuf::from(r"C:\Program Files\PothosSDR\bin")];
        if let Some(p) = std::env::var_os("CONDA_PREFIX") {
            dirs.push(PathBuf::from(p).join("Library").join("bin"));
        }
        if let Some(p) = std::env::var_os("USERPROFILE") {
            dirs.push(
                PathBuf::from(&p)
                    .join("radioconda")
                    .join("Library")
                    .join("bin"),
            );
            dirs.push(
                PathBuf::from(&p)
                    .join("miniforge3")
                    .join("Library")
                    .join("bin"),
            );
        }
        for d in dirs {
            v.push(d.join("hackrf.dll"));
        }
    } else if cfg!(target_os = "macos") {
        for d in ["/opt/homebrew/lib", "/usr/local/lib", "/opt/local/lib"] {
            v.push(Path::new(d).join("libhackrf.dylib"));
        }
    } else {
        for d in [
            "/usr/lib",
            "/usr/local/lib",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
        ] {
            v.push(Path::new(d).join("libhackrf.so.0"));
        }
    }
    v
}

impl Api {
    fn load(explicit: Option<&Path>) -> anyhow::Result<Api> {
        let mut errors = Vec::new();
        for p in candidate_paths(explicit) {
            match DynLib::open(&p) {
                Ok(lib) => return Self::bind(lib, p.display().to_string()),
                Err(e) => errors.push(format!("  {}: {e}", p.display())),
            }
        }
        bail!(
            "could not load libhackrf. Install the HackRF host tools (see README) or pass \
             --hackrf-lib / set HACKRF_LIB. Tried:\n{}",
            errors.join("\n")
        )
    }

    fn bind(lib: DynLib, path: String) -> anyhow::Result<Api> {
        unsafe {
            macro_rules! sym {
                ($name:literal) => {
                    lib.get($name)
                        .with_context(|| format!("symbol {} missing in {}", $name, path))?
                };
            }
            let library_version =
                lib.get::<unsafe extern "C" fn() -> *const c_char>("hackrf_library_version");
            Ok(Api {
                init: sym!("hackrf_init"),
                exit: sym!("hackrf_exit"),
                open_by_serial: sym!("hackrf_open_by_serial"),
                close: sym!("hackrf_close"),
                start_rx: sym!("hackrf_start_rx"),
                stop_rx: sym!("hackrf_stop_rx"),
                is_streaming: sym!("hackrf_is_streaming"),
                set_sample_rate: sym!("hackrf_set_sample_rate"),
                set_freq: sym!("hackrf_set_freq"),
                set_lna_gain: sym!("hackrf_set_lna_gain"),
                set_vga_gain: sym!("hackrf_set_vga_gain"),
                set_amp_enable: sym!("hackrf_set_amp_enable"),
                set_antenna_enable: sym!("hackrf_set_antenna_enable"),
                set_baseband_filter_bandwidth: sym!("hackrf_set_baseband_filter_bandwidth"),
                compute_baseband_filter_bw: sym!("hackrf_compute_baseband_filter_bw"),
                error_name: sym!("hackrf_error_name"),
                device_list: sym!("hackrf_device_list"),
                device_list_free: sym!("hackrf_device_list_free"),
                board_id_read: sym!("hackrf_board_id_read"),
                version_string_read: sym!("hackrf_version_string_read"),
                library_version,
                path,
                _lib: lib,
            })
        }
    }

    fn check(&self, what: &str, rc: c_int) -> anyhow::Result<()> {
        if rc == 0 {
            return Ok(());
        }
        let name = unsafe {
            let p = (self.error_name)(rc);
            if p.is_null() {
                format!("error {rc}")
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        Err(anyhow!("{what} failed: {name} ({rc})"))
    }
}

/// Information about one connected HackRF.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub serial: String,
    pub board: String,
    pub firmware: String,
}

/// Enumerate connected devices. Returns (library path, library version, devices).
pub fn list_devices(lib: Option<&Path>) -> anyhow::Result<(String, String, Vec<DeviceInfo>)> {
    let api = Api::load(lib)?;
    unsafe {
        api.check("hackrf_init", (api.init)())?;
        let ver = api
            .library_version
            .map(|f| CStr::from_ptr(f()).to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        let list = (api.device_list)();
        let mut devices = Vec::new();
        if !list.is_null() {
            let l = &*list;
            for i in 0..l.devicecount as isize {
                let sp = *l.serial_numbers.offset(i);
                let serial = if sp.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(sp).to_string_lossy().into_owned()
                };
                let mut board = "?".to_string();
                let mut firmware = "?".to_string();
                let cs = CString::new(serial.clone()).unwrap_or_default();
                let mut dev: Dev = std::ptr::null_mut();
                if (api.open_by_serial)(cs.as_ptr(), &mut dev) == 0 {
                    let mut id = 0u8;
                    if (api.board_id_read)(dev, &mut id) == 0 {
                        board = match id {
                            0 => "Jellybean".into(),
                            1 => "Jawbreaker".into(),
                            2 | 4 | 5 => "HackRF One".into(),
                            3 => "rad1o".into(),
                            other => format!("board id {other}"),
                        };
                    }
                    let mut buf = [0 as c_char; 255];
                    if (api.version_string_read)(dev, buf.as_mut_ptr(), 254) == 0 {
                        firmware = CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned();
                    }
                    (api.close)(dev);
                }
                devices.push(DeviceInfo {
                    serial,
                    board,
                    firmware,
                });
            }
            (api.device_list_free)(list);
        }
        (api.exit)();
        Ok((api.path.clone(), ver, devices))
    }
}

#[derive(Clone, Debug)]
pub struct HackRfConfig {
    pub serial: Option<String>,
    pub library: Option<PathBuf>,
    pub center_hz: u64,
    pub sample_rate: f64,
    pub baseband_filter_hz: Option<u32>,
    pub lna_gain: u32,
    pub vga_gain: u32,
    pub amp: bool,
    pub bias_tee: bool,
    /// Print device settings and warnings on stderr.
    pub verbose: bool,
    /// Retune through these centre frequencies (the first one replaces
    /// `center_hz`).
    pub sweep: Option<Sweep>,
}

/// The retune marker goes in front of the first USB buffer delivered after
/// the retune was requested. That buffer and any filled but not yet delivered
/// ones (at most the libhackrf transfer count, 4) can hold samples from the
/// old frequency. Measured: the switch shows up within the first buffer.
const RETUNE_STALE_BUFFERS: u64 = 5;
/// Synthesizer settling time after the stale buffers, in seconds.
const RETUNE_SETTLE_S: f64 = 1e-3;

pub struct HackRfSource {
    cfg: HackRfConfig,
}

impl HackRfSource {
    pub fn new(cfg: HackRfConfig) -> Self {
        Self { cfg }
    }
}

struct RxContext {
    tx: Sender<IqBlock>,
    stop: Arc<AtomicBool>,
    samples: AtomicU64,
    dropped: AtomicU64,
    pending_gap: AtomicU64,
    /// Centre frequency (MHz) of a retune not yet announced; 0 = none.
    pending_retune: AtomicU32,
    /// Samples of synthesizer settling time.
    settle_samples: u64,
}

unsafe extern "C" fn rx_callback(t: *mut HackrfTransfer) -> c_int {
    let t = unsafe { &*t };
    let ctx = unsafe { &*(t.rx_ctx as *const RxContext) };
    if ctx.stop.load(Ordering::Relaxed) {
        return -1;
    }
    let n = t.valid_length.max(0) as usize;
    if n == 0 || t.buffer.is_null() {
        return 0;
    }
    let data = unsafe { std::slice::from_raw_parts(t.buffer, n) }.to_vec();
    let ns = (n / 2) as u64;
    ctx.samples.fetch_add(ns, Ordering::Relaxed);
    let gap = ctx.pending_gap.load(Ordering::Relaxed);
    if gap > 0 {
        match ctx.tx.try_send(IqBlock::Gap(gap)) {
            Ok(()) => ctx.pending_gap.store(0, Ordering::Relaxed),
            Err(TrySendError::Full(_)) => {
                ctx.pending_gap.fetch_add(ns, Ordering::Relaxed);
                ctx.dropped.fetch_add(ns, Ordering::Relaxed);
                return 0;
            }
            Err(TrySendError::Disconnected(_)) => return -1,
        }
    }
    // Announce a retune before the first buffer delivered after it; that
    // buffer and the following stale ones are covered by `settle`.
    let center_mhz = ctx.pending_retune.load(Ordering::Relaxed);
    if center_mhz != 0 {
        let settle = RETUNE_STALE_BUFFERS * ns + ctx.settle_samples;
        match ctx.tx.try_send(IqBlock::Retune { center_mhz, settle }) {
            Ok(()) => {
                let _ = ctx.pending_retune.compare_exchange(
                    center_mhz,
                    0,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            Err(TrySendError::Full(_)) => {
                ctx.pending_gap.fetch_add(ns, Ordering::Relaxed);
                ctx.dropped.fetch_add(ns, Ordering::Relaxed);
                return 0;
            }
            Err(TrySendError::Disconnected(_)) => return -1,
        }
    }
    match ctx.tx.try_send(IqBlock::Ci8(data)) {
        Ok(()) => 0,
        Err(TrySendError::Full(_)) => {
            ctx.pending_gap.fetch_add(ns, Ordering::Relaxed);
            ctx.dropped.fetch_add(ns, Ordering::Relaxed);
            0
        }
        Err(TrySendError::Disconnected(_)) => -1,
    }
}

impl IqSource for HackRfSource {
    fn run(
        self: Box<Self>,
        tx: Sender<IqBlock>,
        stop: Arc<AtomicBool>,
    ) -> anyhow::Result<SourceStats> {
        let api = Api::load(self.cfg.library.as_deref())?;
        let c = &self.cfg;
        unsafe {
            api.check("hackrf_init", (api.init)())?;
            let serial = c
                .serial
                .as_ref()
                .map(|s| CString::new(s.as_str()).unwrap_or_default());
            let mut dev: Dev = std::ptr::null_mut();
            let rc = (api.open_by_serial)(
                serial.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                &mut dev,
            );
            if rc != 0 {
                (api.exit)();
                return Err(api.check("hackrf_open", rc).unwrap_err()).context(
                    "is the HackRF connected and not used by another program? \
                     (on Windows it needs the WinUSB driver, e.g. installed with Zadig)",
                );
            }
            // The context must outlive hackrf_close(), which joins the USB
            // transfer thread that invokes the callback.
            let ctx = Box::new(RxContext {
                tx,
                stop: stop.clone(),
                samples: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                pending_gap: AtomicU64::new(0),
                pending_retune: AtomicU32::new(0),
                settle_samples: (RETUNE_SETTLE_S * c.sample_rate) as u64,
            });
            let sweep = c.sweep.as_ref().filter(|s| !s.centers_mhz.is_empty());
            let center_hz = sweep.map_or(c.center_hz, |s| s.centers_mhz[0] as u64 * 1_000_000);
            let ctx_ptr = &*ctx as *const RxContext as *mut c_void;
            let result = (|| -> anyhow::Result<SourceStats> {
                api.check("set_sample_rate", (api.set_sample_rate)(dev, c.sample_rate))?;
                let bw_req = c
                    .baseband_filter_hz
                    .unwrap_or((c.sample_rate * 0.75) as u32);
                let bw = (api.compute_baseband_filter_bw)(bw_req);
                api.check(
                    "set_baseband_filter_bandwidth",
                    (api.set_baseband_filter_bandwidth)(dev, bw),
                )?;
                api.check("set_freq", (api.set_freq)(dev, center_hz))?;
                api.check("set_amp_enable", (api.set_amp_enable)(dev, c.amp as u8))?;
                api.check("set_lna_gain", (api.set_lna_gain)(dev, c.lna_gain))?;
                api.check("set_vga_gain", (api.set_vga_gain)(dev, c.vga_gain))?;
                api.check(
                    "set_antenna_enable",
                    (api.set_antenna_enable)(dev, c.bias_tee as u8),
                )?;
                if c.verbose {
                    eprintln!(
                        "HackRF: {} | {:.3} MHz, {:.1} Msps, baseband filter {:.2} MHz, LNA {} dB, VGA {} dB, amp {}",
                        api.path,
                        center_hz as f64 / 1e6,
                        c.sample_rate / 1e6,
                        bw as f64 / 1e6,
                        c.lna_gain,
                        c.vga_gain,
                        if c.amp { "on" } else { "off" }
                    );
                }
                api.check("start_rx", (api.start_rx)(dev, rx_callback, ctx_ptr))?;
                // Sweep schedule, in samples so that it follows the stream.
                let dwell = sweep.map(|s| ((s.dwell * c.sample_rate) as u64).max(1));
                let mut step = 0usize;
                let mut next_retune = dwell.unwrap_or(u64::MAX);
                let mut retune_error = None;
                while !stop.load(Ordering::Relaxed) && (api.is_streaming)(dev) == 1 {
                    std::thread::sleep(Duration::from_millis(10));
                    let (Some(sw), Some(dwell)) = (sweep, dwell) else {
                        continue;
                    };
                    let n = ctx.samples.load(Ordering::Relaxed);
                    if sw.centers_mhz.len() < 2 || n < next_retune {
                        continue;
                    }
                    step = (step + 1) % sw.centers_mhz.len();
                    let f = sw.centers_mhz[step];
                    // Announce first: every buffer delivered after the marker
                    // is covered by the settling time, so no sample from the
                    // new frequency is processed with the old channel map.
                    ctx.pending_retune.store(f, Ordering::Relaxed);
                    if let Err(e) = api.check("set_freq", (api.set_freq)(dev, f as u64 * 1_000_000))
                    {
                        retune_error = Some(e);
                        break;
                    }
                    // stay on a fixed time grid: step k starts at k * dwell
                    while next_retune <= n {
                        next_retune += dwell;
                    }
                }
                let streaming_ended = !stop.load(Ordering::Relaxed) && retune_error.is_none();
                stop.store(true, Ordering::Relaxed);
                (api.stop_rx)(dev);
                if let Some(e) = retune_error {
                    return Err(e);
                }
                let st = SourceStats {
                    samples: ctx.samples.load(Ordering::Relaxed),
                    dropped: ctx.dropped.load(Ordering::Relaxed),
                };
                if streaming_ended {
                    // Not silent even in extcap mode: Wireshark should show it.
                    eprintln!("HackRF: streaming stopped unexpectedly (device disconnected?)");
                }
                Ok(st)
            })();
            stop.store(true, Ordering::Relaxed);
            (api.close)(dev);
            (api.exit)();
            drop(ctx);
            result
        }
    }
}
