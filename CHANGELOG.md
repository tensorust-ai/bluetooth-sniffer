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
