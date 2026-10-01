// `no_std`, no-alloc reimplementation of the Vivint/Honeywell 345 MHz door-sensor
// keystream cipher, plus keyed-status decode — for running on the sensor's new
// host (ESP32-C3 + CC1101, etc.) so an orphaned sensor can be reused.
//
// # It's the Rabbit stream cipher (RFC 4503)
//
// The generator is the **Rabbit stream cipher** under a custom, weak key setup
// that stretches a 16-bit seed into Rabbit's state instead of a real 128-bit key
// and 64-bit IV — which is the entire weakness (only ~2^16 keystreams). `ed74`
// is Rabbit's next-state function (`g = LSW(sq) ^ MSW(sq)` via `x*x`, plus the
// `<<<16`/`<<<8` mixing), the repeating `0x4d,0xd3,0x34` constant is Rabbit's
// counter constants A0..A7, and `f386` is the extraction scheme (c1 = status
// key, c3 = byte-10 MAC).
//
// The cipher is byte-identical to the host `revivint/src/cipher.rs` (which
// was validated byte-exact against an emulator oracle over 150+ seeds, and
// cross-checked against the SME's textbook-Rabbit C++ implementation); the
// known-answer tests below guard against drift. NO firmware is embedded — the
// only firmware-derived value is the constant `0x4d34d34d`.
//
// # Compile-time key material
//
// Recover each sensor's 16-bit seed **once, offline**, with the `revivint crack`
// tool, then bake a **TXID→seed table** into the firmware at build time.
// `VIVINT_KEYS` declares **devices**, and optionally their keys. Three shapes:
//
// | entry | meaning |
// |---|---|
// | `405817=0c5e` | a keyed sensor and its seed |
// | `405718` | a declared sensor that needs no seed (64-bit legacy) |
// | `+legacy` | also accept legacy senders that were not listed |
//
// ```sh
// # one keyed sensor:
// VIVINT_KEYS='405817=0c5e' cargo build --release
// # ...or paste what `revivint crack` printed, verbatim:
// VIVINT_KEYS='0019-050-7610=05c9,0019-050-7743=dda9' cargo build --release
// # a keyed sensor plus a seedless legacy one:
// VIVINT_KEYS='405817=0c5e,405718' cargo build --release
// ```
//
// A seedless sensor still has to be *declared*: the list is what separates "my
// sensor" from a stranger's, and 345 MHz is a shared band. See [`crate::Policy`]
// for what that gate is protecting against and the measurement behind it.
//
// [`KEYS`] parses `VIVINT_KEYS` at compile time into a [`KeyMap`]. The TXID is
// accepted in every spelling the host tooling uses — decimal (`405817`),
// `0x`-hex (`0x63139`), or the sensor label (`0056-040-5817`) — and **the seed
// is hex** (`05c9`, `0x05c9`), matching what `crack` prints, so a recovered
// mapping pastes in unchanged. If `VIVINT_KEYS` is unset it defaults to the
// reference unit (`405817=0x0c5e`) so the crate still builds and tests.
//
// `VIVINT_KEYS` is the single knob: firmware builds its [`Registry`] from
// [`KEYS`], and there is no separate single-seed variable. [`SEED`] is just the
// reference unit's seed, exposed for the known-answer tests and the [`Decoder`]
// example below.
//
// # Use
//
// ```ignore
// use revivint_core::cipher::{Decoder, SEED};
// let mut dec = Decoder::new(SEED);
// // for each received 0x7x frame (counter = bytes 3..5, byte5 = status byte):
// if let Some(contact) = dec.contact(counter, byte5) {
//     // publish `open` (true = OPEN, false = closed)
// }
// ```

const ENTRY_COUNTER: u16 = 0x17;

/// The reference unit's seed (`405817` → `0x0c5e`). **Not** read from the
/// environment: firmware is keyed through [`KEYS`]/[`crate::Registry`] (`VIVINT_KEYS`),
/// so this exists only for the known-answer tests and the [`Decoder`] example.
/// Recover a real device's seed with `revivint crack` and bake it in via
/// `VIVINT_KEYS`.
pub const SEED: u16 = 0x0c5e;

/// Maximum number of `(txid, seed)` pairs bakeable at compile time. Bump this if
/// you have more keyed sensors; each configured slot costs one [`crate::Decoder`]
/// worth of RAM in the firmware (~0x300 bytes).
pub const KEY_CAP: usize = 8;

/// A compile-time TXID→seed table (see crate docs / [`KEYS`]). Fixed-capacity and
/// `Copy`, so it lives in flash with no allocation. `Default` is the empty map
/// (nothing keyed — every event decodes in the clear until a seed is learned).
#[derive(Clone, Copy, Default)]
pub struct KeyMap {
    /// `(txid, seed)`; `seed == None` for a **declared but unkeyed** device.
    entries: [(u32, Option<u16>); KEY_CAP],
    len: usize,
    /// The `+legacy` token was present: accept 64-bit legacy frames from TXIDs
    /// that were never declared. See [`KeyMap::undeclared_legacy`].
    undeclared_legacy: bool,
}

impl KeyMap {
    /// Number of declared devices, keyed or not.
    pub const fn len(&self) -> usize {
        self.len
    }
    /// True when nothing at all was declared.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// The seed configured for `txid`. `None` covers two different cases —
    /// "declared, no seed needed" and "not declared at all" — so use
    /// [`KeyMap::declares`] when the question is membership.
    pub const fn seed_for(&self, txid: u32) -> Option<u16> {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].0 == txid {
                return self.entries[i].1;
            }
            i += 1;
        }
        None
    }
    /// Whether `txid` was declared, with or without a seed.
    ///
    /// This is the membership test that gates the sync-less decode fallback and
    /// Home Assistant discovery — *not* [`KeyMap::seed_for`], which cannot tell
    /// a seedless legacy sensor apart from a stranger.
    pub const fn declares(&self, txid: u32) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].0 == txid {
                return true;
            }
            i += 1;
        }
        false
    }
    /// The `(txid, seed)` entry at `i` (`i < len`), for building per-device state.
    pub const fn entry(&self, i: usize) -> (u32, Option<u16>) {
        self.entries[i]
    }
    /// True when `VIVINT_KEYS` carried the `+legacy` token, meaning "also accept
    /// 64-bit legacy sensors I did not list".
    ///
    /// This is deliberately **not** the default. A legacy frame's full 16-bit
    /// CRC is strong evidence for *one* trial, but the sync-less rescue path
    /// slides over ~1000 (phase x polarity x bit offset), which turns a
    /// 1-in-65536 filter into roughly 1-in-60. Measured against valid-Manchester
    /// traffic that is not one of our frames, that fabricated a device from
    /// 0.092% of bursts, each with a fresh random TXID.
    pub const fn undeclared_legacy(&self) -> bool {
        self.undeclared_legacy
    }
}

/// True for characters that separate `VIVINT_KEYS` entries.
const fn is_sep(c: u8) -> bool {
    matches!(c, b',' | b';' | b' ' | b'\t' | b'\n' | b'\r')
}

/// End of the token starting at `start` (stops at a `=`/`:` or a separator).
///
/// `=` is the documented separator, mirroring `rtl_433`'s own `txid=seed`
/// spelling; a nested `=` inside a quoted environment assignment is unambiguous
/// to the shell, so `VIVINT_KEYS='405817=0c5e'` exports fine. `:` is also
/// accepted, and costs nothing to keep.
const fn token_end(b: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < b.len() && b[end] != b':' && b[end] != b'=' && !is_sep(b[end]) {
        end += 1;
    }
    end
}

/// Parse a TXID in any spelling the host tooling uses:
///
/// | form | example | source |
/// |---|---|---|
/// | decimal | `405817` | the id `revivint` prints |
/// | `0x`-hex | `0x63139` | the id in logs |
/// | sensor label | `0056-040-5817` | what `crack` emits / printed on the device |
/// | compact label | `0056-0405817` | the label with the middle hyphen dropped |
///
/// The last two are the same number: everything after the **first** hyphen, with
/// any remaining hyphens removed, is the decimal 20-bit id
/// (`0056-040-5817` → `405817` → `0x63139`).
const fn parse_txid(b: &[u8], start: usize) -> (u32, usize) {
    let end = token_end(b, start);
    assert!(end > start, "VIVINT_KEYS entry has an empty txid");

    if end - start > 2 && b[start] == b'0' && (b[start + 1] == b'x' || b[start + 1] == b'X') {
        let mut v: u32 = 0;
        let mut i = start + 2;
        while i < end {
            let c = b[i];
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => panic!("VIVINT_KEYS txid has a non-hex digit after 0x"),
            };
            v = v * 16 + d;
            i += 1;
        }
        return (v, end);
    }

    // Skip the leading `PPPP-` group of a label / rtl_433 id, if present.
    let mut i = start;
    let mut hyphen = end;
    while i < end {
        if b[i] == b'-' {
            hyphen = i;
            break;
        }
        i += 1;
    }
    let mut j = if hyphen < end { hyphen + 1 } else { start };

    let mut v: u32 = 0;
    let mut any = false;
    while j < end {
        let c = b[j];
        if c == b'-' {
            j += 1; // inner hyphen of the sensor-label form
            continue;
        }
        assert!(c >= b'0' && c <= b'9', "VIVINT_KEYS txid has a non-digit");
        v = v * 10 + (c - b'0') as u32;
        any = true;
        j += 1;
    }
    assert!(any, "VIVINT_KEYS entry has no txid digits");
    (v, end)
}

/// Parse a seed from a mapping entry.
///
/// **Seeds are hex**, with or without a `0x` prefix, because that is what
/// `revivint crack` prints (`…=05c9`), so its output pastes straight into
/// `VIVINT_KEYS`.
const fn parse_mapped_seed(b: &[u8], start: usize) -> (u32, usize) {
    let end = token_end(b, start);
    let mut i = start;
    if end - start > 2 && b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X') {
        i += 2;
    }
    assert!(i < end, "VIVINT_KEYS entry has an empty seed");
    let mut v: u32 = 0;
    while i < end {
        let c = b[i];
        let d = match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'a'..=b'f' => (c - b'a' + 10) as u32,
            b'A'..=b'F' => (c - b'A' + 10) as u32,
            _ => panic!("VIVINT_KEYS seed must be hex (e.g. 05c9 or 0x05c9)"),
        };
        v = v * 16 + d;
        assert!(v <= 0xffff, "VIVINT_KEYS seed is out of 16-bit range");
        i += 1;
    }
    (v, end)
}

/// Parse a `VIVINT_KEYS` string (`txid=seed` pairs, comma/semicolon separated)
/// into a [`KeyMap`] in const context.
const fn parse_keys(src: &str) -> KeyMap {
    let b = src.as_bytes();
    let mut entries = [(0u32, None); KEY_CAP];
    let mut len = 0usize;
    let mut undeclared_legacy = false;
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && is_sep(b[i]) {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        // `+legacy` is a policy token, not a device. The leading `+` keeps it
        // unmistakable at a glance and means it can never collide with a TXID
        // spelling, however the id is written.
        if b[i] == b'+' {
            let end = token_end(b, i);
            assert!(
                slice_eq(b, i + 1, end, b"legacy"),
                "VIVINT_KEYS: the only supported policy token is `+legacy`"
            );
            undeclared_legacy = true;
            i = end;
            continue;
        }
        let (txid, ni) = parse_txid(b, i);
        i = ni;
        // Look past whitespace for a `:`/`=`, so `405817 : 0c5e` parses. A
        // *separator* (comma/semicolon/newline) instead means this entry ended
        // and the next begins, so only spaces and tabs may be skipped here.
        let mut j = i;
        while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
            j += 1;
        }
        if j < b.len() && (b[j] == b':' || b[j] == b'=') {
            i = j;
        }
        // A bare entry declares a device that needs no seed — a 64-bit legacy
        // sensor, whose status byte is in the clear. Declaring it is still
        // required: it is what separates "my sensor" from a stranger's, for the
        // decode fallback and for Home Assistant discovery alike.
        let seed = if i < b.len() && (b[i] == b':' || b[i] == b'=') {
            i += 1;
            while i < b.len() && is_sep(b[i]) {
                i += 1; // tolerate whitespace after the separator
            }
            let (s, ni) = parse_mapped_seed(b, i);
            i = ni;
            Some(s as u16)
        } else {
            None
        };
        assert!(len < KEY_CAP, "VIVINT_KEYS has more entries than KEY_CAP");
        entries[len] = (txid, seed);
        len += 1;
    }
    KeyMap { entries, len, undeclared_legacy }
}

/// `b[start..end] == want`, in const context.
const fn slice_eq(b: &[u8], start: usize, end: usize, want: &[u8]) -> bool {
    if end - start != want.len() {
        return false;
    }
    let mut i = 0;
    while i < want.len() {
        if b[start + i] != want[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// [`parse_keys`] for tests in other modules of this crate.
#[doc(hidden)]
pub const fn parse_keys_for_test(src: &str) -> KeyMap {
    parse_keys(src)
}

/// The compile-time TXID→seed table, parsed from `VIVINT_KEYS` (default: the
/// reference unit `405817=0x0c5e`). See the crate docs.
pub const KEYS: KeyMap = parse_keys(match option_env!("VIVINT_KEYS") {
    Some(s) => s,
    None => "405817=0x0c5e",
});

/// Map a c3 keystream byte to the transmitted byte-10 high nibble.
#[inline]
pub fn byte10_from_c3(c3: u8) -> u8 {
    (c3 ^ 0x10) & 0xf0
}

/// Seed expansion (FUN_f6d2): the pristine entropy table.
fn expand(seed: u16) -> [u16; 8] {
    let base = seed ^ 0x0008;
    [
        base,
        base.wrapping_add(0x25),
        base.wrapping_sub(0x04),
        base.wrapping_add(0x2c),
        base.wrapping_sub(0x09),
        base.wrapping_sub(0x1d),
        base ^ 0x00f9,
        base ^ 0x0022,
    ]
}

const ROMPAT: [u8; 3] = [0x4d, 0xd3, 0x34]; // the repeating ROM constant (0x4d34d34d)
#[inline]
fn rom_word(off: usize) -> u16 {
    ROMPAT[off % 3] as u16 | ((ROMPAT[(off + 1) % 3] as u16) << 8)
}
#[inline]
fn rom_dword(off: usize) -> u32 {
    rom_word(off) as u32 | ((rom_word(off + 2) as u32) << 16)
}

/// The cipher state: a flat 0x200..0x2ff RAM window (768 bytes), matching the
/// firmware layout. Small enough to live comfortably on an ESP32-C3.
struct Cipher {
    m: [u8; 0x300],
}

impl Cipher {
    fn new() -> Self {
        Cipher { m: [0u8; 0x300] }
    }
    #[inline]
    fn r16(&self, a: usize) -> u16 {
        self.m[a] as u16 | ((self.m[a + 1] as u16) << 8)
    }
    #[inline]
    fn w16(&mut self, a: usize, v: u16) {
        self.m[a] = v as u8;
        self.m[a + 1] = (v >> 8) as u8;
    }
    #[inline]
    fn r32(&self, a: usize) -> u32 {
        self.r16(a) as u32 | ((self.r16(a + 2) as u32) << 16)
    }
    #[inline]
    fn w32(&mut self, a: usize, v: u32) {
        self.w16(a, v as u16);
        self.w16(a + 2, (v >> 16) as u16);
    }

    fn f294(&mut self) {
        let counter = self.r16(0x206);
        let m = (counter % 7) as usize;
        self.w16(0x27a + m * 2, self.r16(0x27a + m * 2).wrapping_add(counter).wrapping_add(m as u16));
        self.w16(0x288, self.r16(0x288) ^ m as u16);
        let e: [u16; 8] = core::array::from_fn(|i| self.r16(0x27a + 2 * i));
        let mut s1 = [0u16; 16];
        let mut s2 = [0u16; 16];
        for r in 0..8usize {
            if r % 2 == 0 {
                s1[2 * r] = e[r];
                s1[2 * r + 1] = e[(r + 1) % 8];
                s2[2 * r] = e[(r + 5) % 8];
                s2[2 * r + 1] = e[(r + 4) % 8];
            } else {
                s1[2 * r] = e[(r + 4) % 8];
                s1[2 * r + 1] = e[(r + 5) % 8];
                s2[2 * r] = e[(r + 1) % 8];
                s2[2 * r + 1] = e[r];
            }
        }
        for i in 0..16 {
            self.w16(0x232 + 2 * i, s1[i]);
            self.w16(0x252 + 2 * i, s2[i]);
        }
    }

    fn ed74(&mut self) {
        const SC: usize = 0x294;
        for r8 in 0..8 {
            let lo = self.r16(0x252 + r8 * 4);
            let hi = self.r16(0x254 + r8 * 4);
            self.w16(SC + r8 * 4, lo);
            self.w16(SC + 2 + r8 * 4, hi);
        }
        let lcg = self.r32(0x272).wrapping_add(0x4d34_d34d);
        self.w32(0x252, self.r32(0x252).wrapping_add(lcg));
        for r8 in 1..8 {
            let a = self.r32(0x252 + r8 * 4);
            let b = self.r32(0x24e + r8 * 4);
            let sub = self.r32(SC - 4 + r8 * 4);
            let borrow = (b < sub) as u32;
            self.w32(0x252 + r8 * 4, a.wrapping_add(rom_dword(r8 * 4)).wrapping_add(borrow));
        }
        let borrow = (self.r32(0x26e) < self.r32(0x2b0)) as u16;
        self.w16(0x272, borrow);
        self.w16(0x274, 0);
        for r8 in 0..8 {
            let x = self.r32(0x232 + r8 * 4).wrapping_add(self.r32(0x252 + r8 * 4));
            let lo = x & 0xffff;
            let hi = x >> 16;
            let xsq = x.wrapping_mul(x);
            let mut acc = (lo.wrapping_mul(lo) >> 16) >> 1;
            acc = acc.wrapping_add(lo.wrapping_mul(hi));
            acc >>= 15;
            acc = acc.wrapping_add(hi.wrapping_mul(hi));
            acc ^= xsq;
            self.w32(SC + r8 * 4, acc);
        }
        let (mut r11, mut r10) = (7usize, 6usize);
        for r8 in [0usize, 2, 4, 6] {
            let t1 = self.r32(SC + r11 * 4).rotate_left(16);
            let t2 = self.r32(SC + r10 * 4).rotate_left(16);
            self.w32(0x232 + r8 * 4, t1.wrapping_add(self.r32(SC + r8 * 4)).wrapping_add(t2));
            r11 = (r11 + 1) % 8;
            r10 = (r10 + 1) % 8;
            let t3 = self.r32(SC + r11 * 4).rotate_left(8);
            self.w32(0x236 + r8 * 4, t3.wrapping_add(self.r32(SC + 4 + r8 * 4)).wrapping_add(self.r32(SC + r10 * 4)));
            r11 = (r11 + 1) % 8;
            r10 = (r10 + 1) % 8;
        }
    }

    fn f986(&mut self) {
        for r10 in 0..8usize {
            let r11 = r10 * 4;
            let r14 = ((r10 + 4) % 8) * 4;
            self.w16(0x252 + r11, self.r16(0x252 + r11) ^ self.r16(0x232 + r14));
            self.w16(0x254 + r11, self.r16(0x254 + r11) ^ self.r16(0x234 + r14));
        }
    }

    fn f386(&mut self) {
        let k = self.r16(0x206) & 3;
        let (r14, r12, r13) = match k {
            0 => (self.r16(0x23e), self.r16(0x248) ^ self.r16(0x232), self.r16(0x234)),
            1 => (self.r16(0x246), self.r16(0x250) ^ self.r16(0x23a), self.r16(0x23c)),
            2 => (self.r16(0x24e), self.r16(0x238) ^ self.r16(0x242), self.r16(0x244)),
            _ => (self.r16(0x236), self.r16(0x240) ^ self.r16(0x24a), self.r16(0x24c)),
        };
        let r13 = r13 ^ r14;
        self.m[0x2c1] = r12 as u8;
        self.m[0x2c2] = (r12 >> 8) as u8;
        self.m[0x2c3] = r13 as u8;
        self.m[0x2c4] = (r13 >> 8) as u8;
    }

    fn f9b0(&mut self) {
        self.w16(0x272, 0);
        self.w16(0x274, 0);
        self.f294();
        for _ in 0..4 {
            self.ed74();
        }
        self.f986();
        self.ed74();
        self.f386();
    }

    fn begin(&mut self, seed: u16) {
        self.m = [0u8; 0x300];
        let e = expand(seed);
        for (i, v) in e.iter().enumerate() {
            self.w16(0x27a + 2 * i, *v);
        }
    }

    /// Advance one transmit; returns (counter, c1, c3).
    fn tick(&mut self, counter: u16) -> (u16, u8, u8) {
        let counter = if counter == 0xfff7 { 0 } else { counter + 1 };
        self.w16(0x206, counter);
        if counter % 12 == 0 {
            self.f9b0();
        } else if counter % 4 == 0 {
            self.ed74();
            self.f386();
        } else {
            self.f386();
        }
        (counter, self.m[0x2c1], self.m[0x2c3])
    }
}

/// Streaming keystream/decode for a live frame feed. No allocation: it keeps one
/// running cipher and advances the per-transmit schedule to each frame's counter,
/// re-syncing from event entry if the counter jumps backward (sensor power-cycle).
pub struct Decoder {
    c: Cipher,
    seed: u16,
    counter: u16,
    last_c1: u8,
    last_c3: u8,
}

impl Cipher {
    /// Replay from event entry, checking each `(counter, byte10_hi)` target as it
    /// is reached; returns false at the first mismatch. `targets` must be sorted
    /// by counter and free of duplicates (see [`normalize_targets`]).
    fn replay_matches(&mut self, seed: u16, targets: &[(u16, u8)]) -> bool {
        if targets.is_empty() {
            return true;
        }
        let max_counter = targets[targets.len() - 1].0;
        self.begin(seed);
        let mut counter = ENTRY_COUNTER;
        let mut ti = 0usize;
        while counter < max_counter && ti < targets.len() {
            let (c, _c1, c3) = self.tick(counter);
            counter = c;
            while ti < targets.len() && targets[ti].0 == counter {
                if byte10_from_c3(c3) != targets[ti].1 {
                    return false;
                }
                ti += 1;
            }
        }
        ti == targets.len()
    }
}

/// Put on-air observations into the shape the seed search needs: only the high
/// nibble of byte 10 is significant, one entry per counter, ascending. Returns
/// the number of usable entries at the front of `targets`.
pub fn normalize_targets(targets: &mut [(u16, u8)]) -> usize {
    for t in targets.iter_mut() {
        t.1 &= 0xf0;
    }
    targets.sort_unstable_by_key(|t| t.0);
    let mut n = 0;
    let mut i = 0;
    while i < targets.len() {
        if n == 0 || targets[n - 1].0 != targets[i].0 {
            targets[n] = targets[i];
            n += 1;
        }
        i += 1;
    }
    n
}

/// Brute-force the 16-bit seed against on-air observations `(counter, byte10)`,
/// writing every consistent seed into `out` and returning how many were written.
///
/// This is the `no_std` form: a single-threaded sweep of all 65536 seeds, and
/// `targets` is normalized in place. Hosts should prefer [`crack`], which is the
/// same search spread across cores.
pub fn seeds_matching(targets: &mut [(u16, u8)], out: &mut [u16]) -> usize {
    let n = normalize_targets(targets);
    if n == 0 {
        return 0;
    }
    let targets = &targets[..n];
    let mut c = Cipher::new();
    let mut found = 0usize;
    let mut s = 0u32;
    while s <= 0xffff {
        let seed = s as u16;
        if c.replay_matches(seed, targets) {
            if found < out.len() {
                out[found] = seed;
            }
            found += 1;
        }
        s += 1;
    }
    if found > out.len() { out.len() } else { found }
}

/// Brute-force the seed across all cores. Returns every seed consistent with the
/// observations, ascending — usually exactly one; more than one means the capture
/// needs more distinct low counters.
#[cfg(feature = "std")]
pub fn crack(targets: &[(u16, u8)]) -> std::vec::Vec<u16> {
    let mut owned: std::vec::Vec<(u16, u8)> = targets.to_vec();
    let n = normalize_targets(&mut owned);
    owned.truncate(n);
    if owned.is_empty() {
        return std::vec::Vec::new();
    }
    let nthreads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let chunk = 0x10000usize.div_ceil(nthreads);
    let targets_ref = &owned;
    std::thread::scope(|scope| {
        let handles: std::vec::Vec<_> = (0..nthreads)
            .map(|t| {
                scope.spawn(move || {
                    let mut c = Cipher::new();
                    let lo = t * chunk;
                    let hi = ((t + 1) * chunk).min(0x10000);
                    let mut hits = std::vec::Vec::new();
                    for s in lo..hi {
                        // lo..hi ⊆ 0..=0xffff (hi capped at 0x10000), so this never fails.
                        let seed = u16::try_from(s).expect("seed index fits in u16");
                        if c.replay_matches(seed, targets_ref) {
                            hits.push(seed);
                        }
                    }
                    hits
                })
            })
            .collect();
        let mut all: std::vec::Vec<u16> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all.sort_unstable();
        all
    })
}

impl Decoder {
    pub fn new(seed: u16) -> Self {
        let mut c = Cipher::new();
        c.begin(seed);
        Decoder { c, seed, counter: ENTRY_COUNTER, last_c1: 0, last_c3: 0 }
    }

    fn advance_to(&mut self, counter: u16) -> bool {
        if counter == self.counter {
            return true;
        }
        // backward jump (not a small in-window repeat) => re-sync from entry
        if counter < self.counter {
            self.c.begin(self.seed);
            self.counter = ENTRY_COUNTER;
        }
        let mut steps = 0u32;
        while self.counter != counter {
            let (c, c1, c3) = self.c.tick(self.counter);
            self.counter = c;
            self.last_c1 = c1;
            self.last_c3 = c3;
            steps += 1;
            if steps > 0x1_0000 {
                return false; // unreachable within one counter cycle
            }
        }
        true
    }

    /// (c1, c3) keystream at `counter`, or None if unreachable from entry.
    pub fn keystream_at(&mut self, counter: u16) -> Option<(u8, u8)> {
        if self.advance_to(counter) {
            Some((self.last_c1, self.last_c3))
        } else {
            None
        }
    }

    /// The **un-keyed** status byte for a keyed 0x7x event: `byte5 ^ c1`, or None
    /// if the counter is unreachable from entry. Plaintext is the classic Honeywell
    /// event byte: 0x80 loop-1, 0x40 tamper, 0x20 loop-2/reed, 0x10 alarm, 0x08
    /// battery-low, 0x04 heartbeat. `byte5` is the frame's status byte (offset 5).
    pub fn plain_status(&mut self, counter: u16, byte5: u8) -> Option<u8> {
        let (c1, _c3) = self.keystream_at(counter)?;
        Some(byte5 ^ c1)
    }

    /// Loop-1 (0x80) contact state for a keyed 0x7x event. This is the DW21R's
    /// door contact; the DW11 reports on loop-2 (0x20) instead — read
    /// [`Self::plain_status`] for the full bitfield when the model is unknown.
    ///
    /// Returns a [`crate::Contact`], not a bool, so the caller cannot get the polarity
    /// backwards: the loop bit is 1 when the circuit is *broken*, which is the
    /// opposite of the "closed = true" reading most people expect.
    pub fn contact(&mut self, counter: u16, byte5: u8) -> Option<crate::Contact> {
        Some(crate::Contact::from_loop_bit(
            self.plain_status(counter, byte5)? & 0x80 != 0,
        ))
    }
}

/// One-shot: (c1, c3) for `(seed, counter)` on the on-air schedule. Allocation-free.
/// Prefer [`Decoder`] for a stream; this re-replays from entry each call.
pub fn keystream_at(seed: u16, counter: u16) -> Option<(u8, u8)> {
    Decoder::new(seed).keystream_at(counter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_seed_is_the_documented_default() {
        // SEED is a fixed reference constant now (firmware keys via VIVINT_KEYS);
        // it is the reference unit 405817's seed and drives the known-answer tests.
        assert_eq!(SEED, 0x0c5e);
    }

    #[test]
    fn known_answer_keystream() {
        // On-air keystream (c1,c3) at low counters for seed 0x0c5e, from the
        // validated reference implementation. Guards against cipher drift.
        let kat: &[(u16, u8, u8)] = &[
            (24, 0xbe, 0x15),
            (25, 0x5d, 0xbb),
            (26, 0x2e, 0xa7),
            (30, 0x4d, 0xeb),
            (36, 0xdf, 0x62),
        ];
        let mut d = Decoder::new(0x0c5e);
        for &(cnt, c1, c3) in kat {
            assert_eq!(d.keystream_at(cnt), Some((c1, c3)), "counter {cnt}");
        }
    }

    #[test]
    fn decode_true_contact_state() {
        // Real 5817 status bytes: OPEN => byte5 0xd8/0xac; closed => 0x58/0x28.
        let mut d = Decoder::new(0x0c5e);
        assert_eq!(d.contact(25, 0xd8), Some(crate::Contact::Open));
        assert_eq!(d.contact(26, 0xac), Some(crate::Contact::Open));
        let mut d = Decoder::new(0x0c5e);
        assert_eq!(d.contact(25, 0x58), Some(crate::Contact::Closed));
        assert_eq!(d.contact(26, 0x28), Some(crate::Contact::Closed));
    }

    #[test]
    fn resyncs_on_backward_counter() {
        // A power-cycle resets the counter; the decoder must re-sync, not stall.
        let mut d = Decoder::new(0x0c5e);
        assert_eq!(d.contact(40, 0x00), d.contact(40, 0x00)); // stable
        assert!(d.contact(25, 0xd8).is_some()); // backward -> resync -> OPEN
        assert_eq!(d.contact(25, 0xd8), Some(crate::Contact::Open));
    }

    #[test]
    fn byte10_helper() {
        assert_eq!(byte10_from_c3(0x15), 0x00);
    }

    #[test]
    fn default_keymap_is_reference_unit() {
        // No VIVINT_KEYS during plain `cargo test` -> the documented default.
        assert_eq!(KEYS.len(), 1);
        assert_eq!(KEYS.seed_for(405817), Some(0x0c5e)); // 405817 == 0x63139
        assert_eq!(KEYS.entry(0), (405817, Some(0x0c5e)));
        assert_eq!(KEYS.seed_for(0x630d6), None); // legacy sensor -> in the clear
    }

    #[test]
    fn parse_keys_handles_multiple_entries_and_txid_radixes() {
        // TXIDs may be decimal or 0x-hex; **seeds in a mapping are always hex**,
        // matching what `revivint crack` prints. This changed:
        // a bare `4660` used to mean decimal 4660 and now means 0x4660. Write
        // `0x` if you want to be explicit — it is accepted either way.
        let m = parse_keys("405817=0x0c5e, 0x63140=1234; 7 = 9");
        assert_eq!(m.len(), 3);
        assert_eq!(m.seed_for(405817), Some(0x0c5e));
        assert_eq!(m.seed_for(0x63140), Some(0x1234));
        assert_eq!(m.seed_for(7), Some(0x9));
        assert_eq!(m.seed_for(999), None);
        assert!(parse_keys("").is_empty());
    }
}

#[cfg(test)]
mod keymap_tests {
    use super::{parse_keys, KEY_CAP};

    /// 0x63139 == 405817, the id on a `0056-040-5817` sensor.
    const REF_TXID: u32 = 0x63139;

    #[test]
    fn every_txid_spelling_resolves_to_the_same_id() {
        for src in [
            "405817=0c5e",         // decimal, as revivint prints
            "0x63139=0c5e",        // hex, as logs show
            "0056-0405817=0c5e",   // rtl_433 form, as `crack` emits
            "0056-040-5817=0c5e",  // the label printed on the sensor
        ] {
            let m = parse_keys(src);
            assert_eq!(m.len(), 1, "{src}");
            assert_eq!(m.entry(0), (REF_TXID, Some(0x0c5e)), "{src}");
            assert_eq!(m.seed_for(REF_TXID), Some(0x0c5e), "{src}");
        }
    }

    #[test]
    fn seeds_are_hex_so_crack_output_pastes_in_unchanged() {
        // `crack` prints bare 4-digit hex; `0x` is also accepted.
        assert_eq!(parse_keys("405817=05c9").entry(0).1, Some(0x05c9));
        assert_eq!(parse_keys("405817=0x05c9").entry(0).1, Some(0x05c9));
        assert_eq!(parse_keys("405817=dda9").entry(0).1, Some(0xdda9));
    }

    #[test]
    fn accepts_a_whole_pasted_crack_mapping() {
        // Exactly the mapping `revivint crack` prints for two devices.
        let m = parse_keys("0019-050-7610=05c9,0019-050-7743=dda9");
        assert_eq!(m.len(), 2);
        assert_eq!(m.entry(0), (507610, Some(0x05c9)));
        assert_eq!(m.entry(1), (507743, Some(0xdda9)));
        assert_eq!(m.seed_for(507743), Some(0xdda9));
        assert_eq!(m.seed_for(1), None);
    }

    #[test]
    fn declares_seedless_devices_and_the_legacy_token() {
        // The three shapes, together, as a real install would write them.
        let m = parse_keys("405817=0c5e,405718,+legacy");
        assert_eq!(m.len(), 2, "+legacy is a policy token, not a device");
        assert_eq!(m.entry(0), (405817, Some(0x0c5e)));
        assert_eq!(m.entry(1), (405718, None), "a bare entry declares, unkeyed");
        assert!(m.undeclared_legacy());

        // Declaration and keying are different questions, and `seed_for` alone
        // cannot tell "declared, no seed" from "never heard of it".
        assert!(m.declares(405718) && m.seed_for(405718).is_none());
        assert!(!m.declares(999999) && m.seed_for(999999).is_none());

        // Absent the token, the permissive setting stays off.
        assert!(!parse_keys("405817=0c5e,405718").undeclared_legacy());
    }

    #[test]
    fn equals_and_colon_both_parse() {
        // `=` is what `crack` prints and what the docs use, mirroring rtl_433;
        // `:` is accepted too and costs nothing to keep.
        for src in ["405817=0c5e", "405817:0c5e", "405817 = 0c5e", "405817 : 0c5e"] {
            let m = parse_keys(src);
            assert_eq!(m.entry(0), (405817, Some(0x0c5e)), "{src}");
        }
    }

    #[test]
    fn separators_and_whitespace_are_flexible() {
        let m = parse_keys("405817 = 0c5e ; 0056-040-5818 = 1a2b");
        assert_eq!(m.len(), 2);
        assert_eq!(m.entry(0), (405817, Some(0x0c5e)));
        assert_eq!(m.entry(1), (405818, Some(0x1a2b)));
    }

    #[test]
    fn capacity_covers_a_whole_house() {
        const { assert!(KEY_CAP >= 8, "a typical install has more than a handful of sensors") };
        let mut src = std::string::String::new();
        for i in 0..KEY_CAP {
            if i > 0 {
                src.push(',');
            }
            src.push_str(&std::format!("{}=00{:02x}", 400000 + i, i));
        }
        assert_eq!(parse_keys(&src).len(), KEY_CAP);
    }

    #[test]
    fn empty_mapping_is_empty_not_a_phantom_device() {
        let m = parse_keys("");
        assert!(m.is_empty());
        assert_eq!(m.seed_for(0), None);
    }
}

#[cfg(test)]
mod crack_tests {
    use super::{byte10_from_c3, crack, keystream_at, seeds_matching, Cipher, Decoder, ENTRY_COUNTER};

    // Synthetic seeds used only to exercise the round trip; not real devices.
    const TEST_SEEDS: &[u16] = &[0x0001, 0x1234, 0xabcd, 0xfffe];
    const COUNTERS: &[u16] = &[24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36];

    /// Generate the on-air byte-10 high nibble each counter would carry for `seed`.
    fn observations_for(seed: u16, counters: &[u16]) -> Vec<(u16, u8)> {
        let max = *counters.iter().max().unwrap();
        let mut g = Cipher::new();
        g.begin(seed);
        let mut by_counter = std::collections::BTreeMap::new();
        let mut c = ENTRY_COUNTER;
        while c < max {
            let (nc, _c1, c3) = g.tick(c);
            c = nc;
            by_counter.insert(c, byte10_from_c3(c3));
        }
        counters.iter().map(|&cnt| (cnt, by_counter[&cnt])).collect()
    }

    #[test]
    fn crack_round_trips_each_seed() {
        // Generate frames from a seed, then recover exactly that seed. This
        // exercises the whole cipher and the brute force without any real secret.
        for &seed in TEST_SEEDS {
            assert_eq!(
                crack(&observations_for(seed, COUNTERS)),
                vec![seed],
                "seed {seed:#06x}"
            );
        }
    }

    #[test]
    fn too_few_frames_stays_ambiguous_but_includes_truth() {
        let seed = TEST_SEEDS[1];
        let hits = crack(&observations_for(seed, &[24, 25]));
        assert!(hits.len() > 1, "two frames should be ambiguous");
        assert!(hits.contains(&seed));
    }

    #[test]
    fn decoder_round_trips_status_byte() {
        // Craft a status byte = keystream XOR a known plaintext, then confirm the
        // decoder un-keys it back to that plaintext. Uses a synthetic seed.
        let seed = TEST_SEEDS[2];
        let (c1, _c3) = keystream_at(seed, 30).unwrap();
        // plaintext 0x80 (loop-1 open) and 0x20 (loop-2 open) recover exactly.
        assert_eq!(Decoder::new(seed).plain_status(30, c1 ^ 0x80), Some(0x80));
        assert_eq!(Decoder::new(seed).plain_status(30, c1 ^ 0x20), Some(0x20));
        assert_eq!(Decoder::new(seed).plain_status(30, c1), Some(0x00));
    }

    #[test]
    fn the_no_std_search_agrees_with_the_parallel_one() {
        // `seeds_matching` is what firmware would use; `crack` is the host path.
        // They must not drift apart — that is the whole point of one core crate.
        for &seed in TEST_SEEDS {
            let obs = observations_for(seed, COUNTERS);
            let parallel = crack(&obs);

            let mut targets = obs.clone();
            let mut out = [0u16; 8];
            let n = seeds_matching(&mut targets, &mut out);
            assert_eq!(&out[..n], parallel.as_slice(), "seed {seed:#06x}");
        }
    }
}
