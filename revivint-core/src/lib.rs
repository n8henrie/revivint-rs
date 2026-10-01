//! `no_std` decoder for Honeywell / 2GIG / Vivint 345 MHz door/window sensors.
//!
//! This is a Rust port of the project's `vivint_decode.py`, validated against
//! the same captured frames and the MSP430G2452 firmware dump. It is split so
//! the two firmware variants (hardware-assisted vs software OOK decode) can
//! share everything above the raw byte frame:
//!
//! * [`crc`]       - CRC-16/0x8050 (firmware `crc16_8050` @ 0xf92e).
//! * [`frame`]     - byte-frame parsing + CRC/check validation + field map.
//! * [`bits`]      - tiny fixed-capacity bit buffer (no alloc).
//! * [`manchester`]- OOK chip-stream <-> data-bit (de)coding for the SW path.
//! * [`framer`]    - 0xFFFE sync search + frame extraction from a data-bit run.
//! * [`cipher`]    - the Rabbit-based keystream, `Decoder`, and the seed search.
//! * [`report`]    - MQTT topic/JSON payload formatting (feature `mqtt`).
//!
//! The hardware-assisted firmware feeds [`frame::decode`] directly with bytes
//! the CC1101 already de-Manchestered; the software firmware runs
//! [`manchester`] + [`framer`] first.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

// The `std` feature adds the parallel seed search; everything else stays no_std.
#[cfg(any(feature = "std", test))]
extern crate std;

pub mod bits;
pub mod cipher;
pub mod crc;
pub mod frame;
pub mod framer;
pub mod manchester;
// `test` as well as the feature, so `cargo test` always exercises this module —
// a feature-gated module is otherwise silently untested by the default command.
#[cfg(any(feature = "mqtt", test))]
pub mod report;
// The CC1101 radio driver + 345 MHz OOK register profiles. It lives here rather
// than in its own crate because it has *no* external dependencies — it defines
// its own `SpiBus`/`OutputPin` traits — so it costs host-only users nothing and
// its register math stays host-testable. Same `test` gate as `report`.
#[cfg(any(feature = "cc1101", test))]
pub mod cc1101;

pub use crc::{crc16, crc16_8050};
pub use frame::{
    decode, decode_body, decode_body_aligned, decode_body_auto, Alignment, Battery, Body, Contact,
    DecodeError, DecodedFrame, Event, EventClass, EventKey, Family, Legacy, Startup, Status,
    StatusBits, StatusBitsTail, announced_seed_from_field, is_keyed_subtype, BODY_64, BODY_96, BODY_MAX, BODY_SLACK, CAPTURE_MAX, SYNC,
};
pub use framer::{
    for_each_frame, for_each_frame_at, for_each_frame_bytes, for_each_frame_in_run_unvetted,
    for_each_frame_in_run_vetted, decode_chip_capture, scan_chip_capture, ChipCapture,
    FrameSite, Recovery, MIN_CHIP_BYTES,
    SYNC_FFFE,
};

// The per-device keystream cipher and the compile-time TXID→seed table
// (`VIVINT_KEYS`). Re-exported so firmware builds one [`Registry`] for the RF
// loop; single-seed callers can still use [`Decoder`] + [`apply_key`] directly.
pub use cipher::{seeds_matching, Decoder, KeyMap, KEYS, KEY_CAP, SEED};
#[cfg(feature = "std")]
pub use cipher::crack;

/// A set of per-device keystream decoders, one per compile-time [`KEYS`] entry,
/// dispatched by TXID. This is the multi-sensor front door for firmware: it holds
/// each keyed sensor's running cipher so a frame is un-keyed with *its own* seed,
/// and it leaves unknown TXIDs (and non-`0x7x` families) exactly as decoded — the
/// contact bit of a legacy/startup frame is already in the clear, so those need
/// no seed at all.
pub struct Registry {
    decoders: [Decoder; KEY_CAP],
    txids: [u32; KEY_CAP],
    len: usize,
}

impl Registry {
    /// Build from the compile-time [`KEYS`] table (`VIVINT_KEYS`).
    pub fn new() -> Self {
        Self::from_map(&KEYS)
    }

    /// Build from an explicit [`KeyMap`] (useful for tests).
    ///
    /// **Only entries that carry a seed become decoders.** A declared-but-seedless
    /// entry (a 64-bit legacy sensor, which needs no key) is deliberately absent
    /// here: giving it a `Decoder::new(0)` would let [`Registry::apply_key`] match
    /// it and XOR its perfectly readable status byte with a keystream derived
    /// from a seed nobody configured, turning a correct contact state into a
    /// wrong one. Declaration lives in [`Policy`]; this type is only about keys.
    pub fn from_map(map: &KeyMap) -> Self {
        let mut seeds = [0u16; KEY_CAP];
        let mut ids = [u32::MAX; KEY_CAP];
        let mut len = 0usize;
        let mut i = 0;
        while i < map.len() {
            if let (txid, Some(seed)) = map.entry(i) {
                seeds[len] = seed;
                ids[len] = txid;
                len += 1;
            }
            i += 1;
        }
        let decoders = core::array::from_fn(|i| Decoder::new(seeds[i]));
        Registry { decoders, txids: ids, len }
    }

    /// Un-key a keyed `0x7x` event frame (0x7a/0x74/0x79) whose TXID has a
    /// configured seed, turning its [`Status::Sealed`] byte into a
    /// [`Status::Plain`] one carrying the true contact state and full event
    /// bitfield, from that device's running keystream.
    ///
    /// Frames from other families, or from TXIDs with no seed, are left exactly
    /// as decoded — legacy and startup bytes are already in the clear and need
    /// no seed, and a keyed frame we cannot open stays `Sealed`, so no consumer
    /// can mistake keystream for a door state.
    pub fn apply_key(&mut self, f: &mut DecodedFrame) {
        let Body::Event(e) = &mut f.body else { return };
        if !matches!(e.status, Status::Sealed(_)) {
            return;
        }
        let mut i = 0;
        while i < self.len {
            if self.txids[i] == f.txid {
                if let Some(plain) = self.decoders[i].plain_status(e.counter, e.status.raw()) {
                    e.status =
                        Status::Plain { raw: e.status.raw(), bits: StatusBits::from_byte(plain) };
                }
                return;
            }
            i += 1;
        }
    }

    /// An immutable snapshot of just the TXIDs this registry knows.
    ///
    /// Lets a caller vet frames (which needs a shared borrow) while the
    /// reporting path holds the registry mutably.
    pub fn key_snapshot(&self) -> KnownTxids {
        KnownTxids { txids: self.txids, len: self.len }
    }

    /// True if this TXID has a configured or learned seed.
    ///
    /// Used to vet frames recovered without a sync word — see
    /// [`for_each_frame_in_run_vetted`].
    pub const fn knows(&self, txid: u32) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.txids[i] == txid {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Adopt a seed at runtime: update an existing TXID's decoder or, if there is
    /// room (`< KEY_CAP`), add a new one. Returns false only when the table is full
    /// and the TXID is new. This is how a `0x73` seed-announce self-configures the
    /// receiver — see [`Registry::decode_keyed`], which calls it automatically.
    pub fn learn(&mut self, txid: u32, seed: u16) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.txids[i] == txid {
                self.decoders[i] = Decoder::new(seed);
                return true;
            }
            i += 1;
        }
        if self.len < KEY_CAP {
            self.txids[self.len] = txid;
            self.decoders[self.len] = Decoder::new(seed);
            self.len += 1;
            return true;
        }
        false
    }

    /// Decode a full `ff fe …` frame and resolve the true contact state for any
    /// keyed `0x7x` event. If the frame is a `0x73` seed-announce, the broadcast
    /// seed is [`learn`](Registry::learn)ed first, so the receiver configures
    /// itself from a sensor's power-up announcement. `decode` + auto-learn +
    /// [`apply_key`](Registry::apply_key).
    pub fn decode_keyed(&mut self, bytes: &[u8]) -> Result<DecodedFrame, DecodeError> {
        let mut df = decode(bytes)?;
        if let Some(seed) = df.announced_seed() {
            self.learn(df.txid, seed);
        }
        self.apply_key(&mut df);
        Ok(df)
    }

    /// [`decode_keyed`](Registry::decode_keyed) for **CC1101 FIFO bytes**: the
    /// frame body with the `ff fe` sync already consumed by the hardware sync
    /// engine. Handles both on-air lengths and both bit polarities
    /// ([`decode_body_auto`]), so one radio configuration serves 96-bit
    /// (5817-style) and 64-bit legacy (5718-style) sensors alike.
    ///
    /// Returns the un-keyed frame and whether the bytes were bit-inverted.
    /// `None` means nothing CRC-valid was in the FIFO.
    pub fn decode_body_keyed(&mut self, body: &[u8]) -> Option<(DecodedFrame, Alignment)> {
        let (mut df, alignment) = decode_body_aligned(body)?;
        if let Some(seed) = df.announced_seed() {
            self.learn(df.txid, seed);
        }
        self.apply_key(&mut df);
        Some((df, alignment))
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// What the operator declared, and therefore what may be believed.
///
/// Built from the same `VIVINT_KEYS` string as [`KEYS`], because "my devices"
/// and "my keys" are the same list — a seedless entry declares a device that
/// needs no key. Keeping declaration in its own type, rather than reading it off
/// [`Registry`], is what lets a legacy sensor be *declared* without being
/// *keyed*: see [`Registry::from_map`].
///
/// # Why declaration gates the decode fallback
///
/// A frame found by a real sync match is corroborated by that sync and is
/// reported regardless. A frame recovered by the **sync-less sliding fallback**
/// has nothing behind it but a CRC, and that fallback gets far more attempts
/// than a single check is worth:
///
/// | | trials per capture | effective filter |
/// |---|---|---|
/// | one CRC-16 check | 1 | 1 in 65 536 |
/// | the sliding fallback | ~1 000 (phase x polarity x bit offset) | ~1 in 60 |
///
/// Measured against valid-Manchester traffic that is not one of our frames — a
/// neighbour's 345 MHz sensor — the unrestricted fallback fabricated a frame
/// from **0.092%** of bursts, each with a *fresh random TXID*. With auto
/// discovery on, every one became a new Home Assistant device whose retained
/// config outlives the firmware that published it. Requiring a declared TXID
/// took the same measurement to **0**.
#[derive(Clone, Copy)]
pub struct Policy {
    declared: KnownTxids,
    undeclared_legacy: bool,
}

impl Policy {
    /// The policy `VIVINT_KEYS` describes.
    pub fn new() -> Self {
        Self::from_map(&KEYS)
    }

    /// `const` so the firmware can hold the policy in a `static`, with the whole
    /// allowlist resolved at build time and nothing to initialise at boot.
    pub const fn from_map(map: &KeyMap) -> Self {
        let mut txids = [u32::MAX; KEY_CAP];
        let mut i = 0;
        while i < map.len() {
            txids[i] = map.entry(i).0;
            i += 1;
        }
        Policy {
            declared: KnownTxids { txids, len: map.len() },
            undeclared_legacy: map.undeclared_legacy(),
        }
    }

    pub const fn declares(&self, txid: u32) -> bool {
        self.declared.knows(txid)
    }

    /// Whether `+legacy` was given: undeclared 64-bit legacy senders are welcome.
    pub const fn undeclared_legacy(&self) -> bool {
        self.undeclared_legacy
    }

    /// The **stateless** verdict on a frame recovered without a sync.
    ///
    /// Declared devices pass. With `+legacy`, an undeclared 64-bit legacy frame
    /// also passes here — but a caller that can remember what it has seen should
    /// corroborate it first rather than using this verdict directly, because
    /// `+legacy` on its own restores the 0.092% fabrication rate described above.
    /// A phantom never repeats its TXID; a real sensor sends every event ~6
    /// times. See `revivint_esp::hw::LegacyGate` for that second step.
    pub fn accepts_bare(&self, f: &DecodedFrame) -> bool {
        self.declares(f.txid)
            || (self.undeclared_legacy && f.family() == Family::Legacy64)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

/// The set of TXIDs a [`Registry`] knows, detached from it. See
/// [`Registry::key_snapshot`].
#[derive(Clone, Copy)]
pub struct KnownTxids {
    txids: [u32; KEY_CAP],
    len: usize,
}

impl KnownTxids {
    pub const fn knows(&self, txid: u32) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.txids[i] == txid {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// Un-key a keyed `0x7x` event frame using the per-device keystream, turning its
/// [`Status::Sealed`] byte into a [`Status::Plain`] one with the true open/closed
/// state and full event bitfield. No-op for non-keyed frames (legacy and startup
/// bytes are already in the clear). The stateful [`Decoder`] must be shared across
/// frames so its keystream tracks the counter sequence.
///
/// The sensor XORs byte 5 with keystream byte c1, so `status ^ c1` recovers the
/// exact Honeywell event byte, which [`StatusBits::from_byte`] then decodes —
/// the one place those masks live.
///
/// A frame this cannot un-key (unknown seed, or a counter unreachable from the
/// keystream entry point) keeps its `Sealed` status, and every reader of its
/// contact state therefore gets `None` rather than a value derived from
/// ciphertext.
pub fn apply_key(dec: &mut Decoder, f: &mut DecodedFrame) {
    if let Body::Event(e) = &mut f.body
        && matches!(e.status, Status::Sealed(_))
        && let Some(plain) = dec.plain_status(e.counter, e.status.raw())
    {
        e.status = Status::Plain { raw: e.status.raw(), bits: StatusBits::from_byte(plain) };
    }
}

/// Decode a full `ff fe ...` frame and, for `0x7x` events, resolve the true
/// contact state via the keystream. Convenience wrapper over [`decode`] +
/// [`apply_key`].
pub fn decode_keyed(dec: &mut Decoder, f: &[u8]) -> Result<DecodedFrame, DecodeError> {
    let mut df = decode(f)?;
    apply_key(dec, &mut df);
    Ok(df)
}

#[cfg(test)]
mod hw_dispatch_tests {
    use super::*;

    fn hx(s: &str) -> std::vec::Vec<u8> {
        s.split(|c: char| !c.is_ascii_hexdigit())
            .filter(|t| !t.is_empty())
            .map(|t| u8::from_str_radix(t, 16).unwrap())
            .collect()
    }

    /// The dispatch the hardware receive loop performs, kept here so it is
    /// covered by `cargo test` rather than only by the (untestable) firmware.
    fn hw_dispatch(reg: &mut Registry, fifo: &[u8]) -> usize {
        if reg.decode_body_keyed(fifo).is_some() {
            return 1;
        }
        for_each_frame_bytes(fifo, |_, _| {})
    }

    #[test]
    fn accepts_a_normal_sync_stripped_fifo_body() {
        // What the CC1101 actually delivers on a correct sync match: the packet
        // engine consumes `ff fe`, so the FIFO starts at the type byte.
        //
        // This is the case the firmware used to reject outright — it only ran a
        // scanner that searches *for* `ff fe`, which a correctly received packet
        // never contains. Every properly synced frame was dropped.
        let fifo = hx("7a 00 19 d8 03 86 31 39 a8 f8");
        assert_eq!(for_each_frame_bytes(&fifo, |_, _| {}), 0, "premise: the scanner alone cannot see it");

        let mut reg = Registry::new();
        assert_eq!(hw_dispatch(&mut reg, &fifo), 1, "dispatch must accept a plain body");

        let (f, _) = Registry::new().decode_body_keyed(&fifo).expect("decodes");
        assert_eq!(f.txid, 0x63139);
        assert!(f.crc_ok);
    }

    #[test]
    fn still_rescues_a_frame_after_an_early_false_trigger() {
        // The other shape: a bit error in the all-ones preamble matched the sync
        // word early, so the capture opens with preamble and the real frame sits
        // inside it. The fallback scan must still find that.
        let mut fifo = std::vec![0xffu8; 5];
        fifo.extend_from_slice(&hx("ff fe 7a 00 19 d8 03 86 31 39 a8 f8"));
        fifo.extend_from_slice(&[0xff; 4]);

        let mut reg = Registry::new();
        assert_eq!(hw_dispatch(&mut reg, &fifo), 1, "early-trigger capture must still decode");
    }

    #[test]
    fn noise_is_still_rejected_by_both_paths() {
        let mut reg = Registry::new();
        for junk in [&[0xffu8; 40][..], &[0x00; 40][..], &[0x5a; 40][..]] {
            assert_eq!(hw_dispatch(&mut reg, junk), 0, "{junk:02x?}");
        }
    }
}
