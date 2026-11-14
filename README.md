# btsdr

[![CI](https://github.com/venglin/bluetooth-sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/venglin/bluetooth-sniffer/actions/workflows/ci.yml)

**Bluetooth LE and Bluetooth Classic (BR) sniffer for the HackRF One, with PCAP/PCAPNG output for Wireshark.**

btsdr captures up to 20 MHz of the 2.4 GHz band at once, splits it into
1 MHz Bluetooth channels and decodes every packet that lands on any of them.
It doesn't follow frequency hopping. It listens to up to 19 channels at the
same time, which is enough to see advertising, ongoing LE connections and
Classic piconets in that slice of the band. Decoded packets go to the console
and to capture files that Wireshark dissects natively.

```
HackRF One ──► channelizer (PFB) ──► burst detector ──► GFSK demod ──┬─► LE link layer ──┐
 20 Msps        17-19 × 1 MHz         per channel        per burst    └─► BR baseband ────┴─► console
                                                                                            PCAPNG / PCAP
```

## Features

**Wideband capture**
- Polyphase filter-bank channelizer: one HackRF covers up to 19 channels
  (default 17) simultaneously.
- Packets from every monitored channel are decoded, including Classic
  piconets hopping at 1600 hops/s and LE connections hopping on all 37 data
  channels.
- Wi-Fi and other wideband interference is detected and discarded early.

**Bluetooth Low Energy (LE 1M PHY)**
- Advertising on the primary and secondary channels: `ADV_IND`,
  `ADV_NONCONN_IND`, `SCAN_REQ`/`SCAN_RSP`, `CONNECT_IND`, `ADV_EXT_IND`/`AUX_*`.
- Connections announced by a `CONNECT_IND` are followed by access address and
  CRCInit on every monitored data channel.
- Connections established *before* the capture started are discovered
  promiscuously: the CRCInit is recovered by running the CRC backwards.
- CRC-24 verification on every packet, plus central/peripheral direction
  inference from the 150 µs inter-frame spacing.
- Device names, company IDs and service UUIDs are extracted from
  advertising data.

**Bluetooth Classic (BR, basic rate)**
- The LAP is read directly from the access code: a BCH(64,30) sync word with
  error correction.
- Inquiry (GIAC/DIAC) and page ID packets.
- The UAP and master clock (CLK6-1) of each piconet are discovered
  automatically, so headers are de-whitened and their HEC verified.
- Payload decoding with CRC check for FHS, DM1, DH1, DM3, DH3, DM5 and DH5.
- An FHS packet (inquiry or page response) reveals the full BD_ADDR, class of
  device and clock.

**Output**
- PCAPNG with both link types in one file, or separate PCAP files:
  `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` (256) and `LINKTYPE_BLUETOOTH_BREDR_BB` (255).
- Live streaming into Wireshark through stdout.
- Raw IQ recording and offline re-analysis of `ci8`, `cu8`, `ci16` and
  `cf32` files.
- A built-in synthetic signal generator lets you try everything without
  hardware.

**Portable**
- Windows, Linux and macOS.
- libhackrf is loaded at run time, so no SDK is needed to build.

## Hardware

- **HackRF One.** Tested with firmware 2023.01.1 and libhackrf 0.6.
- **A 2.4 GHz antenna.** The ANT500 works; a Wi-Fi antenna works better.
- **A USB 2.0 port** that sustains 20 Msps (40 MB/s).
- **A reasonably modern CPU.** Decoding 17 channels at 20 Msps runs at about
  2× real time on a current desktop.

## Installation

### 1. Install libhackrf and check the device

| OS | How |
|----|-----|
| Windows | Install [PothosSDR](https://downloads.myriadrf.org/builds/PothosSDR/) or [radioconda](https://github.com/ryanvolz/radioconda) (both ship `hackrf.dll` and `libusb-1.0.dll`). If `hackrf_info` cannot open the device, install the WinUSB driver for "HackRF One" with [Zadig](https://zadig.akeo.ie/). |
| Debian/Ubuntu | `sudo apt install hackrf` (installs `libhackrf0` and udev rules; log in again after adding yourself to the `plugdev` group if needed) |
| Fedora | `sudo dnf install hackrf` |
| macOS | `brew install hackrf` |

Verify with `hackrf_info`. btsdr looks for the library next to its own
executable, on the system search path, in the PothosSDR/radioconda/Homebrew
locations, and in `$HACKRF_LIB` or `--hackrf-lib <path>`.

### 2. Build btsdr

You need [Rust](https://rustup.rs/) 1.85 or newer. On Windows use the MSVC
toolchain, which needs the *Visual Studio Build Tools* with the
"Desktop development with C++" / VC tools workload.

```bash
git clone https://github.com/venglin/bluetooth-sniffer.git
cd bluetooth-sniffer
cargo build --release
```

The binary is `target/release/btsdr` (`btsdr.exe` on Windows). Run
`cargo install --path .` to put it on your `PATH`.

## Quick start

List devices:

```bash
btsdr devices
```

Capture for 60 s around 2426 MHz (LE advertising channel 38 plus its neighbours):

```bash
btsdr capture -t 60 -w capture.pcapng
```

Watch packets live in Wireshark:

```bash
btsdr capture -w - | wireshark -k -i -
```

On Windows, run the live pipe from `cmd.exe` or PowerShell 7.4+. Windows
PowerShell 5.1 corrupts binary data in pipelines.

No HackRF at hand? Generate a synthetic recording and decode it:

```bash
btsdr synth -o demo.ci8
```

```bash
btsdr capture -i demo.ci8 -w demo.pcapng
```

Example console output (from the synthetic recording):

```
   0.012500 BLE 2426 MHz ch38  -12 dB AA=8e89bed6 CONNECT_IND InitA=46:05:04:03:02:01 AdvA=c1:22:33:44:55:66 AA=50654a3c CRCInit=7a3b5c interval=7.50ms hop=7
   0.014500 BLE 2418 MHz ch7   -12 dB AA=50654a3c C->P LL Empty PDU SN=0 NESN=0 MD=0
   0.014730 BLE 2418 MHz ch7   -14 dB AA=50654a3c P->C LL Data (start) ATT cid=0x0004 l2len=3 SN=0 NESN=1 MD=0
# BLE discovered connection AA=6a7c4f31 CRCInit=13579b (promiscuous)
   0.016000 BR  2429 MHz ch27  -13 dB LAP=9e8b33 ID (GIAC inquiry)
# BR piconet LAP=a1b2c3: UAP=5d and clock discovered after 2 packets
   0.016975 BR  2419 MHz ch17  -12 dB LAP=a1b2c3 UAP=5d clk6=53 LT_ADDR=1 DH1 F-- len=20 L2CAP start CRC ok
   0.017600 BR  2434 MHz ch32  -15 dB LAP=a1b2c3 UAP=5d clk6=54 LT_ADDR=1 NULL F--
   0.022000 BLE 2426 MHz ch38  -12 dB AA=8e89bed6 ADV_IND AdvA=c1:22:33:44:55:66 (random) name="btsdr-demo"
```

Each line shows:
- capture time in seconds;
- PHY (`BLE` or `BR`), centre frequency and channel number (LE channel index
  or BR RF channel);
- signal level in dBFS;
- the decoded packet.

The BR flags `F`, `A` and `S` are FLOW, ARQN and SEQN. Lines starting with
`#` are events. A summary of devices, connections and piconets is printed at
the end.

## Choosing the frequency

A HackRF sees at most 20 MHz, so pick the slice of the band you care about.
The centre frequency must be an integer number of MHz.

| `-f` (MHz) | Channels decoded (default) | Contains |
|-----------:|----------------------------|----------|
| 2410 | 2402–2418 MHz | LE advertising ch 37, LE data 0–7, BR 0–16 |
| 2426 (default) | 2418–2434 MHz | LE advertising ch 38, LE data 7–14, BR 16–32 |
| 2441 | 2433–2449 MHz | LE data 14–21, BR 31–47 |
| 2472 | 2464–2480 MHz | LE advertising ch 39, LE data 29–36, BR 62–78 |

- Channels closer than 2 MHz to the band edge are skipped by default because
  the HackRF's anti-aliasing filter attenuates them. Override with
  `-c 2420-2432` or `-c 2402,2426,2480`.
- A lower sample rate (`-s 10`) monitors fewer channels with less CPU.
- A Classic piconet hops over all 79 channels, so a 17-channel window sees
  about a fifth of its packets. That is enough to identify the piconet,
  discover its UAP and clock, and decode what you see.
- An LE connection is visible whenever one of its connection events falls
  into the window.

## Command reference

### `btsdr capture`

Capture and decode, live from a HackRF or from a file (`-i`).

| Option | Default | Description |
|--------|---------|-------------|
| `-f, --center <MHz>` | 2426 | Centre frequency |
| `-s, --rate <Msps>` | 20 | Sample rate, an even number from 4 to 20; one channel per Msps |
| `-c, --channels <list>` | auto | Channels to decode, e.g. `2402,2426,2430-2434` |
| `-w, --pcapng <file>` | | Write LE and BR packets to one PCAPNG file (`-` = stdout) |
| `--ble-pcap <file>` | | LE only, PCAP with link type 256 |
| `--bredr-pcap <file>` | | BR only, PCAP with link type 255 |
| `--record <file>` | | Save the raw IQ stream (signed 8-bit) for later |
| `-i, --input <file>` | | Decode an IQ recording instead of a live HackRF |
| `--format <fmt>` | auto | `ci8`, `cu8`, `ci16`, `cf32` (guessed from the extension) |
| `-t, --duration <s>` | | Stop after this many seconds (Ctrl-C stops any time) |
| `--lna <dB>` | 32 | LNA (IF) gain, 0–40 in steps of 8 |
| `--vga <dB>` | 20 | VGA (baseband) gain, 0–62 in steps of 2 |
| `--amp` | off | RF amplifier (+14 dB) |
| `--bias-tee` | off | Antenna port power |
| `--bb-filter <MHz>` | 0.75 × rate | Baseband filter bandwidth |
| `--serial <sn>` | | Select a HackRF by serial number |
| `--hackrf-lib <path>` | | Explicit path to libhackrf |
| `--squelch <dB>` | 8 | Burst detection threshold above the noise floor |
| `--no-ble`, `--no-bredr` | | Disable one of the decoders |
| `--no-promiscuous` | | Don't discover LE connections without a `CONNECT_IND` |
| `--follow <AA:CRCINIT>` | | Follow a known LE connection (hex, repeatable) |
| `--uap <LAP:UAP>` | | Known UAP of a BR piconet (hex, repeatable) |
| `--max-ac-errors <n>` | 2 | Bit errors corrected in a BR sync word |
| `--max-aa-errors <n>` | 2 | Bit errors tolerated in an LE access address |
| `--keep-bad-crc` | | Also output LE packets with a bad CRC |
| `--rssi-offset <dB>` | 0 | Calibration offset added to signal/noise levels |
| `-q, --quiet` | | Print only the summary |
| `--status <s>` | 5 | Status line interval on stderr (0 = off) |

### `btsdr devices`

Lists the connected HackRF devices and shows which libhackrf was loaded.

### `btsdr synth`

Writes a synthetic `ci8` recording containing:
- LE advertising;
- a `CONNECT_IND` and the connection it announces;
- a second, pre-existing connection;
- a Classic piconet with POLL, NULL, DM1 and DH1 packets;
- inquiry ID packets and an FHS response.

Options: `-o <file>`, `-f <MHz>`, `-s <Msps>`, `-t <seconds>`, `--snr <dB>`,
`--seed <n>`.

## Working with the captures in Wireshark

Open the `.pcapng` file directly; no plugins are needed. Useful display filters:

| Filter | Shows |
|--------|-------|
| `btle` | all LE packets |
| `btle.advertising_header.pdu_type == 0x05` | `CONNECT_IND` |
| `btle.access_address == 0x50654a3c` | one LE connection |
| `btatt` / `btsmp` / `btl2cap` | LE upper layers |
| `btbredr_rf` | all BR packets |
| `btbredr_rf.lower_address_part == 0x9e8b33` | general inquiry (GIAC) |
| `btbredr_fhs` | FHS packets (BD_ADDR, class of device) |
| `btbredr_rf.flags.crc_pass == 1` | BR packets with a verified payload |

Notes on the pseudo-headers:
- **Signal and noise levels** are in dBFS, not dBm. Use `--rssi-offset` if
  you have a calibration.
- **LE packets** are written de-whitened with the CRC check result. Data
  packets also carry the inferred direction (central → peripheral or
  peripheral → central).
- **BR packets** carry the LAP, the UAP (once known), the de-whitened header
  (once the clock is known) and, when the CRC passes, the de-whitened and
  FEC-decoded payload. Wireshark then dissects LMP and L2CAP.
- **BR packets captured before their piconet's UAP was discovered** are kept
  back for a few seconds and written decoded afterwards. Their timestamps
  stay correct, but they can appear slightly out of order in the file.

## Tuning tips

- **Too few packets:** raise `--vga` in steps of 4–6 dB, then `--lna`. Try
  `--amp` only for weak signals.
- **Many bad CRCs on strong signals (above -10 dBFS):** the front end is
  saturating. Lower the gain.
- **"samples DROPPED" in the summary:** the machine can't keep up. Reduce the
  sample rate (`-s 10`) or the channel list.
- **Busy Wi-Fi channel inside your window:** consider another centre
  frequency. Wideband bursts are discarded automatically, but they still
  cost air time.
- **Repeatable experiments:** record the IQ once with `--record` and re-run
  the decoder offline with different settings.

## Limitations

- **LE:** only the LE 1M PHY. LE 2M and LE Coded are not demodulated.
- **Classic: basic rate only.** EDR payloads (π/4-DQPSK, 8DPSK) are not
  demodulated. For EDR packets you still get the access code and the header,
  because the header is always GFSK. SCO/eSCO voice payloads are not
  decoded.
- **No frequency hopping:** btsdr monitors a fixed window of up to 20 MHz.
  Traffic outside it is not seen.
- **No decryption:** encrypted payloads stay encrypted. A valid BR CRC
  normally means the payload is readable, so such packets are marked
  "decrypted" so that Wireshark dissects them.
- **UAP discovery needs data:** a piconet's UAP and clock are found after a
  few packets (one CRC-protected packet plus one more is usually enough).
  Until then its packets are reported with the LAP only.
- **Timestamps** are the host clock at start plus the sample count, so
  relative timing is precise to well under a microsecond.
- **Validation:** decoding of live LE advertising and Classic inquiry traffic
  has been verified with a HackRF One. LE connection following and BR
  piconet/payload decoding are covered by end-to-end tests with synthetic
  signals, and the codecs are cross-checked against reference tables.
  Reports from other environments are welcome.

## How it works

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the signal chain:
- the channelizer math;
- burst detection and the GFSK demodulator;
- LE connection discovery;
- Classic UAP/clock recovery;
- the exact capture formats.

## Development

Run the tests:

```bash
cargo test --release
```

The test suite includes:
- **Codec unit tests:** sync words, whitening, FEC, HEC and CRC, cross-checked
  against libbtbb tables, Wireshark's checks and a reference LE CRC.
- **Channelizer and detector tests.**
- **An end-to-end test** that synthesises LE and BR traffic and runs it
  through the whole pipeline.

Source layout:

```
src/
  main.rs            command line
  pipeline.rs        threads: source -> DSP -> decoders -> outputs
  source/            HackRF (run-time loaded libhackrf), IQ files
  dsp/               channelizer, burst detector, GFSK demodulator, filters
  ble/               LE link layer: codec, connection tracking
  bredr/             BR baseband: codec, piconet UAP/clock discovery
  pcap.rs            PCAP / PCAPNG writers
  report.rs          console output and summary
  synth.rs           packet encoders, GFSK modulator, demo scenario
tests/synthetic.rs   end-to-end test
```

## Legal

btsdr is a passive receiver. Bluetooth traffic can contain personal data, and
intercepting communications you are not a party to may be illegal where you
live. Only capture traffic you are authorised to analyse, and handle captures
in line with applicable privacy law.

## Acknowledgements

- **Bluetooth Core Specification**: Vol 2 Part B (Baseband) and Vol 6 Part B
  (LE Link Layer).
- **Wireshark's `btle_rf` / `btbredr_rf` dissectors** and the
  [tcpdump.org link-type registry](https://www.tcpdump.org/linktypes.html)
  define the capture formats.
- **[libbtbb](https://github.com/greatscottgadgets/libbtbb) / Ubertooth**:
  their published tables are used as independent test vectors.
- **[ice9-bluetooth-sniffer](https://github.com/mikeryan/ice9-bluetooth-sniffer)**
  showed that wideband SDR sniffing with a filter bank is practical.

## License

MIT, see [LICENSE](LICENSE).
