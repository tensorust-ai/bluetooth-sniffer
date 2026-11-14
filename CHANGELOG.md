# Changelog

## 0.1.0 (unreleased)

First release.

- HackRF One live capture (libhackrf loaded at run time) and IQ file input
  (`ci8`, `cu8`, `ci16`, `cf32`).
- Polyphase filter-bank channelizer for up to 19 simultaneous 1 MHz channels,
  with wideband (Wi-Fi) rejection.
- Bluetooth LE 1M:
  - advertising decoding;
  - following connections announced by `CONNECT_IND`;
  - promiscuous discovery of existing connections (CRCInit recovery);
  - direction inference.
- Bluetooth BR:
  - LAP extraction with sync word error correction;
  - inquiry and page ID packets;
  - per-piconet UAP and clock discovery;
  - header de-whitening and HEC check;
  - FHS and DM/DH payload decoding with CRC check.
- PCAPNG (LE + BR/EDR) and PCAP output for Wireshark, including live
  streaming to stdout.
- `synth` command and an end-to-end test suite built on synthetic signals.
- Wireshark extcap integration: `btsdr extcap install` registers three
  capture interfaces (LE + BR/EDR, LE only, BR only) with a settings dialog.
- Sensitivity improvements, measured with the new `examples/benchmark.rs`.
  At 50% decoding they gain about 2.5 dB for LE advertising and about 3 dB
  for BR headers:
  - narrower channel filter (±0.6 MHz);
  - soft-decision CRC repair for LE (up to two bit errors);
  - soft majority header decoding and Chase decoding of the rate-2/3 FEC
    for BR;
  - more robust piconet UAP/clock lock (partial-alias aware, POLL slot
    rule).

  `--hard-decisions` restores the previous behaviour for comparison.
- `btsdr synth --impaired` adds realistic radio impairments.
- EDR payload demodulation (π/4-DQPSK and 8DPSK) for 2-DH1 … 3-DH5, with
  CRC check and Wireshark transport/rate flags.
  - The channelizer is widened to ±0.7 MHz for EDR; GFSK keeps a ±0.6 MHz
    filter in its demodulator.
  - GFSK CFO/timing estimation is limited to the start of the burst.
  - `synth` generates EDR packets; `examples/benchmark.rs --edr` measures
    them.
