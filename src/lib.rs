//! btsdr - Bluetooth LE and BR (Classic) baseband sniffer for the HackRF One.
//!
//! The crate is organised as a pipeline:
//!
//! 1. [`source`] delivers wideband complex samples (HackRF One or IQ file).
//! 2. [`dsp::channelizer`] splits the band into 1 MHz Bluetooth channels.
//! 3. [`dsp::burst`] finds packet bursts in each channel by energy.
//! 4. [`dsp::demod`] demodulates GFSK bursts into bits.
//! 5. [`ble`] and [`bredr`] recover link-layer packets.
//! 6. [`pcap`] writes them for Wireshark; [`report`] prints them.
//!
//! [`extcap`] lets Wireshark run btsdr directly as a capture interface.

pub mod bits;
pub mod ble;
pub mod bredr;
pub mod dsp;
pub mod extcap;
pub mod pcap;
pub mod pipeline;
pub mod report;
pub mod source;
pub mod synth;
