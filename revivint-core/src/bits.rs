//! Tiny fixed-capacity bit buffer (no alloc), used by the software OOK path.
//!
//! 512 chips is comfortably more than a 96-bit frame's 192 Manchester chips plus
//! preamble; it costs 512 bytes of RAM (one bool per chip) which is fine on a C3.

pub const MAX_BITS: usize = 512;

#[derive(Clone)]
pub struct BitBuf {
    bits: [bool; MAX_BITS],
    len: usize,
}

impl Default for BitBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl BitBuf {
    pub const fn new() -> Self {
        Self {
            bits: [false; MAX_BITS],
            len: 0,
        }
    }

    /// Push one bit; returns false if the buffer is full (bit dropped).
    pub fn push(&mut self, b: bool) -> bool {
        if self.len < MAX_BITS {
            self.bits[self.len] = b;
            self.len += 1;
            true
        } else {
            false
        }
    }

    /// Push the same bit `n` times (used when expanding pulse runs to chips).
    pub fn push_n(&mut self, b: bool, n: usize) -> bool {
        let mut ok = true;
        for _ in 0..n {
            ok &= self.push(b);
        }
        ok
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn as_slice(&self) -> &[bool] {
        &self.bits[..self.len]
    }
}

/// Pack `bits` (MSB-first within each byte) into `out`, returning the number of
/// whole bytes produced. Trailing partial bits are ignored.
pub fn pack_msb_first(bits: &[bool], out: &mut [u8]) -> usize {
    let nbytes = (bits.len() / 8).min(out.len());
    for (i, byte) in out.iter_mut().enumerate().take(nbytes) {
        let mut v = 0u8;
        for j in 0..8 {
            if bits[i * 8 + j] {
                v |= 1 << (7 - j);
            }
        }
        *byte = v;
    }
    nbytes
}

/// Expand `bytes` to MSB-first bits in `out`.
pub fn unpack_msb_first(bytes: &[u8], out: &mut BitBuf) {
    out.clear();
    for &b in bytes {
        for j in 0..8 {
            out.push((b >> (7 - j)) & 1 != 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let bytes = [0xff, 0xfe, 0x7a, 0x01];
        let mut bb = BitBuf::new();
        unpack_msb_first(&bytes, &mut bb);
        assert_eq!(bb.len(), 32);
        let mut out = [0u8; 4];
        assert_eq!(pack_msb_first(bb.as_slice(), &mut out), 4);
        assert_eq!(out, bytes);
    }

    #[test]
    fn push_n_and_full() {
        let mut bb = BitBuf::new();
        assert!(bb.push_n(true, 10));
        assert_eq!(bb.len(), 10);
        // overflow returns false but does not panic
        assert!(!bb.push_n(false, MAX_BITS));
        assert_eq!(bb.len(), MAX_BITS);
    }
}
