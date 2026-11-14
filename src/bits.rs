//! Bit-level helpers.
//!
//! Throughout the crate a *bit stream* is a `&[u8]` holding one bit (0 or 1)
//! per element, in on-air (transmission) order. Integers assembled from a bit
//! stream are in *air order*: bit `i` of the integer is the `i`-th transmitted
//! bit. Both Bluetooth LE and BR/EDR transmit fields LSB first, so an air-order
//! integer is simply the field value.

/// Assemble up to 64 bits (air order) into an integer.
#[inline]
pub fn to_u64(bits: &[u8]) -> u64 {
    debug_assert!(bits.len() <= 64);
    bits.iter()
        .enumerate()
        .fold(0u64, |acc, (i, &b)| acc | (((b & 1) as u64) << i))
}

/// Assemble up to 32 bits (air order) into an integer.
#[inline]
pub fn to_u32(bits: &[u8]) -> u32 {
    debug_assert!(bits.len() <= 32);
    to_u64(bits) as u32
}

/// Append the `n` least significant bits of `value` (LSB first).
#[inline]
pub fn push_bits(out: &mut Vec<u8>, value: u64, n: usize) {
    for i in 0..n {
        out.push(((value >> i) & 1) as u8);
    }
}

/// Expand the `n` least significant bits of `value` into a bit stream.
pub fn from_u64(value: u64, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    push_bits(&mut v, value, n);
    v
}

/// Pack a bit stream into bytes, LSB first. A trailing partial byte is
/// zero-padded.
pub fn pack_lsb(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| {
            c.iter()
                .enumerate()
                .fold(0u8, |acc, (i, &b)| acc | ((b & 1) << i))
        })
        .collect()
}

/// Unpack bytes into a bit stream, LSB first.
pub fn unpack_lsb(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        push_bits(&mut v, b as u64, 8);
    }
    v
}

/// Reverse the order of the `n` least significant bits of `x`.
#[inline]
pub fn reverse_bits(x: u64, n: u32) -> u64 {
    if n == 0 {
        0
    } else {
        x.reverse_bits() >> (64 - n)
    }
}

/// Number of positions in which two bit streams differ.
#[inline]
pub fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).filter(|(x, y)| x != y).count() as u32
}

/// The 7-bit whitening LFSR (g(D) = D^7 + D^4 + 1) shared by Bluetooth LE and
/// BR/EDR. Bit `k` of `state` is register position `k` as drawn in the core
/// specification; the output is taken from position 6, which is fed back into
/// position 0 and XOR-ed into position 4.
#[derive(Clone, Copy, Debug)]
pub struct Lfsr7 {
    state: u8,
}

impl Lfsr7 {
    pub fn new(state: u8) -> Self {
        Self {
            state: state & 0x7f,
        }
    }

    /// LE initialisation: position 0 = 1, positions 1..6 = channel index with
    /// the MSB in position 1 (Core spec Vol 6, Part B, 3.2).
    pub fn ble(channel_index: u8) -> Self {
        let mut s = 1u8;
        for pos in 1..=6 {
            let bit = (channel_index >> (6 - pos)) & 1;
            s |= bit << pos;
        }
        Self::new(s)
    }

    /// BR/EDR initialisation: positions 0..5 = CLK1..CLK6, position 6 = 1
    /// (Core spec Vol 2, Part B, 7.2). `clk6` holds CLK6-1 with CLK1 in bit 0.
    pub fn bredr(clk6: u8) -> Self {
        Self::new((clk6 & 0x3f) | 0x40)
    }

    #[inline]
    pub fn next_bit(&mut self) -> u8 {
        let out = (self.state >> 6) & 1;
        let mut s = (self.state << 1) & 0x7f;
        s |= out;
        if out == 1 {
            s ^= 1 << 4;
        }
        self.state = s;
        out
    }

    /// Skip `n` output bits.
    pub fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.next_bit();
        }
    }

    /// XOR the whitening sequence onto a bit stream (whitening and
    /// de-whitening are the same operation).
    pub fn apply(&mut self, bits: &mut [u8]) {
        for b in bits.iter_mut() {
            *b ^= self.next_bit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u64() {
        let v = 0x8E89_BED6u64;
        let b = from_u64(v, 32);
        assert_eq!(b[0], 0); // 0xD6 = 1101_0110, LSB first
        assert_eq!(b[1], 1);
        assert_eq!(to_u64(&b), v);
    }

    #[test]
    fn pack_unpack() {
        let bytes = [0xD6u8, 0xBE, 0x89, 0x8E, 0x01];
        assert_eq!(pack_lsb(&unpack_lsb(&bytes)), bytes);
    }

    #[test]
    fn reverse() {
        assert_eq!(reverse_bits(0x555555, 24), 0xAAAAAA);
        assert_eq!(reverse_bits(0x01, 8), 0x80);
        assert_eq!(reverse_bits(0x123456, 24), 0x6A2C48);
    }

    /// Cross-check the LE whitening against the well-known byte-oriented
    /// implementation (coefficient = bitswap(channel) | 2, taps 0x11).
    #[test]
    fn ble_whitening_matches_byte_implementation() {
        fn byte_whiten(data: &mut [u8], chan: u8) {
            let mut coeff = chan.reverse_bits() | 2;
            for d in data.iter_mut() {
                let mut m = 1u8;
                while m != 0 {
                    if coeff & 0x80 != 0 {
                        coeff ^= 0x11;
                        *d ^= m;
                    }
                    coeff <<= 1;
                    m = m.wrapping_shl(1);
                }
            }
        }
        for chan in 0..40u8 {
            let mut a = vec![0u8; 40];
            byte_whiten(&mut a, chan);
            let mut bits = vec![0u8; 320];
            Lfsr7::ble(chan).apply(&mut bits);
            assert_eq!(pack_lsb(&bits), a, "channel {chan}");
        }
    }
}
