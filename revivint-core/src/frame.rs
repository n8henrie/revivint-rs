//! Byte-frame parsing for all three families, with the firmware-confirmed
//! field map. Input is the *full* frame including the `ff fe` sync, matching the
//! captured `data` strings and `vivint_decode.py`.

use crate::crc::{crc16, crc16_8050};

/// Frame family, keyed on length + type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// 64-bit legacy Honeywell/2GIG frame (e.g. sensor 5718).
    Legacy64,
    /// 96-bit power-on / startup beacon (`0xd0`), full 16-bit CRC.
    StartupD0,
    /// 96-bit `0x70`-family event frame (`0x71/0x72/0x74/0x7a/...`), packed check.
    Event7x,
}

/// High-level meaning, inferred from family + subtype.
///
/// Confirmed: `Startup` (d0 in power-on captures), `Heartbeat` (0x72 found only
/// in *-heartbeat captures), `Contact` (0x7a, the door open/close frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventClass {
    /// `0x7a` DW open/close — keystreamed contact event.
    Contact,
    /// `0x74` PIR motion — keystreamed event.
    Motion,
    /// `0x79` glass-break — keystreamed event.
    GlassBreak,
    Heartbeat,
    Startup,
    /// `0x73` — the sensor broadcasting its 16-bit seed in the clear. Emitted
    /// during the power-up announce window; recover the seed with no brute force.
    ///
    /// The seed lives in the variant rather than in a sibling `Option` field, so
    /// there is no way to hold an announce frame with no seed, or a seed on a
    /// frame that never announced one.
    SeedAnnounce { seed: u16 },
    Legacy,
    /// A valid `0x70`-family subtype we have not yet characterised (e.g. `0x76`).
    UnknownEvent,
}

/// Reed-switch state.
///
/// An enum rather than a `bool` because "true" has no obvious meaning here and
/// the two ends of this codebase want opposite conventions: the sensor reports a
/// *loop* bit where 1 means the circuit is broken (magnet away), while Home
/// Assistant's `door` class wants ON to mean open. Any `bool` spelling makes one
/// of those read backwards, and a silent inversion is invisible in tests that
/// only check "the value changed".
///
/// Naming the states removes the question. `Contact::Closed` means the magnet is
/// present and the door is shut, at every layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contact {
    /// Magnet away from the reed switch — door or window open.
    Open,
    /// Magnet against the reed switch — door or window shut.
    Closed,
}

impl Contact {
    /// From the sensor's loop bit, where 1 = circuit broken = open.
    pub const fn from_loop_bit(bit: bool) -> Self {
        if bit { Self::Open } else { Self::Closed }
    }

    pub const fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }

    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// The classic Honeywell/2GIG event byte, decoded.
///
/// The identical six bits appear in byte 5 of a 64-bit legacy frame and in byte 5
/// of a 96-bit keyed event *once un-keyed*, so they are decoded here, once. They
/// used to be decoded in two places from two hand-written copies of the same
/// masks — `decode_legacy64` and `fill_event_bits` — which is the shape a
/// polarity bug hides in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusBits {
    /// `0x80`. The DW21R's door contact.
    pub loop1: Contact,
    /// `0x40` — case opened.
    pub tamper: bool,
    /// `0x20`. The DW11's door contact; which loop is the real one is
    /// model-specific, so both are always available.
    pub loop2: Contact,
    /// `0x10`.
    pub alarm: bool,
    /// `0x08`.
    pub battery_low: bool,
    /// `0x04` — this transmission is the periodic supervisory frame.
    pub heartbeat: bool,
}

impl StatusBits {
    pub const fn from_byte(b: u8) -> Self {
        Self {
            loop1: Contact::from_loop_bit(b & 0x80 != 0),
            tamper: b & 0x40 != 0,
            loop2: Contact::from_loop_bit(b & 0x20 != 0),
            alarm: b & 0x10 != 0,
            battery_low: b & 0x08 != 0,
            heartbeat: b & 0x04 != 0,
        }
    }

    pub const fn battery(self) -> Battery {
        if self.battery_low { Battery::Low } else { Battery::Ok }
    }

    /// Render everything except loop-1 — see [`StatusBitsTail`].
    pub const fn without_loop1(self) -> StatusBitsTail {
        StatusBitsTail(self)
    }
}

/// Byte 5 of a `0x7x` event frame, which the sensor XORs with its per-device
/// keystream on the keyed subtypes.
///
/// The whole point of this type is that [`StatusBits`] cannot be read out of a
/// byte that is still ciphertext. The previous code decoded the bits eagerly in
/// `decode_7x` with the comment *"naive; the true bits come from
/// `Registry::apply_key`"*, and then handed that naive value to any consumer
/// that did not go on to un-key it — so a sensor with no configured seed
/// published a contact state derived from keystream. There is now no such value
/// to read: [`Status::Sealed`] holds only the raw byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// A keyed subtype (`0x7a`/`0x74`/`0x79`) whose device seed is not known.
    /// The byte is ciphertext; its bits mean nothing yet. **Remedy: a seed.**
    Sealed(u8),
    /// In the clear, but of uncharacterised layout: the unkeyed `0x7x` subtypes
    /// (`0x72` heartbeat, `0x73` seed-announce, `0x76`).
    ///
    /// We have never confirmed that byte 5 of these carries the Honeywell event
    /// byte, so decoding it as one would be a guess dressed as a fact — the
    /// exact mistake `Sealed` exists to prevent, one layer along. **Remedy:
    /// characterise the format.**
    Opaque(u8),
    /// A confirmed Honeywell event byte: a legacy frame's, or a keyed event's
    /// that [`crate::apply_key`] has un-keyed with the device's keystream.
    Plain { raw: u8, bits: StatusBits },
}

impl Status {
    /// Byte 5 exactly as it came off the air, readable or not.
    pub const fn raw(self) -> u8 {
        match self {
            Self::Sealed(raw) | Self::Opaque(raw) | Self::Plain { raw, .. } => raw,
        }
    }

    /// The decoded bits, or `None` when this byte is not known to hold them.
    pub const fn bits(self) -> Option<StatusBits> {
        match self {
            Self::Sealed(_) | Self::Opaque(_) => None,
            Self::Plain { bits, .. } => Some(bits),
        }
    }

    /// Encrypted, as opposed to merely un-characterised. The distinction matters
    /// when reporting *why* a frame yielded nothing: only this one is fixed by
    /// configuring a seed.
    pub const fn is_sealed(self) -> bool {
        matches!(self, Self::Sealed(_))
    }
}

/// Battery health.
///
/// One value replacing the old `battery_ok: Option<bool>` + `battery_level:
/// Option<u8>` pair, which were two fields describing one fact and could
/// therefore disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Battery {
    /// >= ~2.9 V.
    Ok,
    /// ~2.3-2.8 V.
    Low,
    /// <= ~2.2 V.
    Critical,
}

impl Battery {
    /// From the `0xd0` beacon's coarse gauge (byte 5 high nibble): `0x3` OK,
    /// `0x4` low, `0x5` critical. Confirmed by a bench voltage sweep.
    pub const fn from_gauge(gauge: u8) -> Self {
        match gauge {
            0..=0x3 => Self::Ok,
            0x4 => Self::Low,
            _ => Self::Critical,
        }
    }

    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// A 96-bit `0x7x` event frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// The subtype byte: `0x7a` contact, `0x74` motion, `0x72` heartbeat, ...
    pub subtype: u8,
    pub class: EventClass,
    /// 16-bit event counter. Advances once per open-**and**-close cycle, so one
    /// value is transmitted twice — see [`DecodedFrame::event_key`].
    pub counter: u16,
    pub status: Status,
}

/// A 96-bit `0xd0` power-on / supervisory beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Startup {
    /// Bytes 3-4. A per-session nonce, **not** a counter — it does not advance
    /// with events, so it must never be used as event identity.
    pub nonce: u16,
    pub battery: Battery,
    /// The raw 4-bit gauge the battery reading came from, kept for diagnostics.
    pub gauge: u8,
}

/// A 64-bit legacy Honeywell/2GIG frame (e.g. the 5718).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Legacy {
    /// Byte 2, whose high nibble is the channel and low nibble the id's top bits.
    pub type_byte: u8,
    pub channel: u8,
    /// Byte 5. Never keystreamed on this family, so always readable.
    pub status: StatusBits,
    /// Byte 5 as received.
    pub raw_status: u8,
}

/// What a frame actually says, with only the fields its family really carries.
///
/// This replaced a flat struct of nine `Option` fields whose validity was
/// governed by an untyped `family` tag. Nothing enforced the correspondence, so
/// every consumer re-derived it — `f.counter.unwrap_or(0)`, `f.legacy.map(..)`,
/// `f.battery_ok` on a family that never carries battery — and a wrong guess
/// produced a plausible-looking value rather than a compile error. Matching here
/// is exhaustive: a new family cannot be added without every consumer being told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    Event(Event),
    Startup(Startup),
    Legacy(Legacy),
}

/// Identity of one physical event, as produced by [`DecodedFrame::event_key`].
///
/// A named struct rather than a tuple on purpose. The MQTT bridge once compared
/// event identity by destructuring a `(u32, u8, u16, u8)` field by field, an
/// element was left out of the comparison, and every second state change was
/// silently swallowed. Comparing whole `EventKey` values makes that impossible:
/// a field added here is compared everywhere, with no call site to update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventKey {
    pub txid: u32,
    pub type_byte: u8,
    pub counter: u16,
    pub status: u8,
}

impl EventKey {
    /// Same device — i.e. this key would *replace* `other` in a per-device table
    /// rather than sit beside it.
    pub fn same_device(self, other: Self) -> bool {
        self.txid == other.txid
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    BadPrefix,
    BadLength,
    UnknownType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFrame {
    /// 20-bit TXID, matching the panel / decimal label (e.g. 0x63139 = 405817).
    pub txid: u32,
    pub crc_ok: bool,
    /// The family-specific payload. Match on it for anything the accessors below
    /// do not already answer.
    pub body: Body,
}

impl DecodedFrame {
    pub fn family(&self) -> Family {
        match self.body {
            Body::Event(_) => Family::Event7x,
            Body::Startup(_) => Family::StartupD0,
            Body::Legacy(_) => Family::Legacy64,
        }
    }

    /// The subtype/type byte, whatever the family calls it.
    pub fn type_byte(&self) -> u8 {
        match self.body {
            Body::Event(e) => e.subtype,
            Body::Startup(_) => 0xd0,
            Body::Legacy(l) => l.type_byte,
        }
    }

    pub fn event(&self) -> EventClass {
        match self.body {
            Body::Event(e) => e.class,
            Body::Startup(_) => EventClass::Startup,
            Body::Legacy(_) => EventClass::Legacy,
        }
    }

    /// The event counter, for families that have one.
    ///
    /// `None` for legacy frames (no counter at all) and for startup beacons,
    /// whose bytes 3-4 are a per-session *nonce*: it looks like a counter, does
    /// not behave like one, and reading it as one produces a stream of
    /// meaningless "new events". Reach for [`Startup::nonce`] deliberately if you
    /// really want it.
    pub fn counter(&self) -> Option<u16> {
        match self.body {
            Body::Event(e) => Some(e.counter),
            Body::Startup(_) | Body::Legacy(_) => None,
        }
    }

    /// Byte 5 as received, for families that have one.
    pub fn status_byte(&self) -> Option<u8> {
        match self.body {
            Body::Event(e) => Some(e.status.raw()),
            Body::Legacy(l) => Some(l.raw_status),
            Body::Startup(_) => None,
        }
    }

    /// The decoded event byte, where this frame has one that is readable.
    ///
    /// `None` for a startup beacon (no such byte) and for a keyed event whose
    /// seed is unknown — see [`Status::Sealed`].
    pub fn status_bits(&self) -> Option<StatusBits> {
        match self.body {
            Body::Event(e) => e.status.bits(),
            Body::Legacy(l) => Some(l.status),
            Body::Startup(_) => None,
        }
    }

    /// Door state, when this frame both *reports* one and can be read.
    ///
    /// The gate is the event class, not the byte: a `0x72` heartbeat's byte 5 is
    /// in the clear but says nothing about the door, and publishing loop-1 from
    /// it would make the contact entity flap on every supervisory frame.
    pub fn contact(&self) -> Option<Contact> {
        match self.body {
            Body::Event(e) => match e.class {
                EventClass::Contact | EventClass::Motion | EventClass::GlassBreak => {
                    e.status.bits().map(|b| b.loop1)
                }
                _ => None,
            },
            Body::Legacy(l) => Some(l.status.loop1),
            Body::Startup(_) => None,
        }
    }

    /// Battery health, where the frame carries it: the `0xd0` beacon and legacy
    /// frames. `0x7x` events never report battery.
    pub fn battery(&self) -> Option<Battery> {
        match self.body {
            Body::Startup(s) => Some(s.battery),
            Body::Legacy(l) => Some(l.status.battery()),
            Body::Event(_) => None,
        }
    }

    /// For a `0x73` seed-announce frame, the 16-bit seed the sensor broadcast in
    /// the clear (flash-value convention — the `^8` vs `_DAT_0230` is undone
    /// here). Feed it to [`crate::Registry::learn`].
    pub fn announced_seed(&self) -> Option<u16> {
        match self.body {
            Body::Event(Event { class: EventClass::SeedAnnounce { seed }, .. }) => Some(seed),
            _ => None,
        }
    }

    /// True for the keystreamed event subtypes whose status byte must be un-keyed
    /// and whose byte-10 nibble is the crackable MAC: `0x7a`/`0x74`/`0x79`. Other
    /// `0x7x` frames (heartbeat, seed-announce, `0x76`) are not keyed.
    pub fn is_keyed_event(&self) -> bool {
        matches!(self.body, Body::Event(e) if is_keyed_subtype(e.subtype))
    }

    /// A CRC pass that is *not* an artefact of degenerate input.
    ///
    /// The 64-bit legacy check is CRC-16 with a **zero init**, and a zero-init
    /// CRC over all-zero data is zero — so a buffer of `0x00` matches its own
    /// stored CRC and "decodes" as a legacy frame for device `0x00000`. An
    /// all-`0xff` buffer does the same once [`decode_body_auto`] inverts it.
    /// That matters as soon as a radio hands us raw bytes: silence, a mis-locked
    /// Manchester phase, or an empty FIFO all look like zeros.
    ///
    /// Real transmitters never use TXID 0, so requiring a non-zero id costs
    /// nothing and removes the whole degenerate class.
    pub fn is_plausible(&self) -> bool {
        self.txid != 0
    }

    /// CRC-valid **and** plausible — what a caller working from raw radio bytes
    /// should gate on. See [`is_plausible`](DecodedFrame::is_plausible).
    pub fn is_trustworthy(&self) -> bool {
        self.crc_ok && self.is_plausible()
    }

    /// Identity of the *event* this frame reports, for collapsing repeats.
    ///
    /// A sensor sends each event several times, so a consumer that acts on every
    /// frame acts many times per real-world change. Two frames describe the same
    /// event only if all of this matches.
    ///
    /// **The counter alone is not the identity.** It advances once per
    /// open-*and*-close cycle, so one counter value is transmitted twice — once
    /// in each contact state. Keying on `(txid, type, counter)` therefore
    /// collapses a genuine state change into its predecessor, and a consumer
    /// sees a stream of updates that never change value.
    ///
    /// The status byte is what separates them: for a given counter it differs
    /// between the two states, and it is identical across that event's repeats.
    pub fn event_key(&self) -> EventKey {
        EventKey {
            txid: self.txid,
            type_byte: self.type_byte(),
            counter: self.counter().unwrap_or(0),
            status: self.status_byte().unwrap_or(0),
        }
    }
}

/// True for the `0x7x` subtypes whose byte 5 is XOR-keystreamed with the device
/// key, and whose byte-10 nibble is the crackable MAC: `0x7a` (contact), `0x74`
/// (motion), `0x79` (glass-break).
///
/// The single source of truth for this list. It used to be written out in three
/// places — `decode_7x`, `DecodedFrame::is_keyed_event` and the CLI's own frame
/// parser — so adding a fourth keyed subtype meant finding all of them, and
/// missing one meant that subtype's ciphertext being published as a door state.
pub const fn is_keyed_subtype(subtype: u8) -> bool {
    matches!(subtype, 0x7a | 0x74 | 0x79)
}

/// The seed a `0x73` frame announces, from its bytes 3-4.
///
/// The firmware stores `_DAT_0230` there, which is the flash seed XOR 8, and
/// this project's convention everywhere else is the flash value — so the `^ 8`
/// is undone exactly here, once.
pub const fn announced_seed_from_field(field: u16) -> u16 {
    field ^ 0x0008
}

impl EventClass {
    /// Classify a `0x7x` subtype byte, given its bytes 3-4 field.
    pub const fn from_subtype(subtype: u8, field: u16) -> Self {
        match subtype {
            0x7a => Self::Contact,
            0x74 => Self::Motion,
            0x79 => Self::GlassBreak,
            0x72 => Self::Heartbeat,
            0x73 => Self::SeedAnnounce { seed: announced_seed_from_field(field) },
            _ => Self::UnknownEvent,
        }
    }

    /// Stable lower-case name, used in MQTT payloads and logs. Kept next to the
    /// enum so a new variant is a compile error here rather than a silent
    /// "unknown" somewhere downstream.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Motion => "motion",
            Self::GlassBreak => "glassbreak",
            Self::Heartbeat => "heartbeat",
            Self::SeedAnnounce { .. } => "seed",
            Self::Startup => "startup",
            Self::Legacy => "legacy",
            Self::UnknownEvent => "unknown",
        }
    }
}

impl core::fmt::Display for EventClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::fmt::Display for Contact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Closed => "closed",
        })
    }
}

impl core::fmt::Display for Battery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Ok => "ok",
            Self::Low => "low",
            Self::Critical => "critical",
        })
    }
}

/// Everything in a [`StatusBits`] except loop-1, as `loop2=… tamper …`.
///
/// Exists so a caller that has already named loop-1 something more meaningful —
/// `contact=open`, say — can print the rest without repeating it. Returned by
/// [`StatusBits::without_loop1`].
pub struct StatusBitsTail(StatusBits);

impl core::fmt::Display for StatusBitsTail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "loop2={}", self.0.loop2)?;
        for (on, label) in [
            (self.0.tamper, " tamper"),
            (self.0.alarm, " alarm"),
            (self.0.heartbeat, " heartbeat"),
        ] {
            if on {
                f.write_str(label)?;
            }
        }
        if self.0.battery_low {
            f.write_str(" battery=low")?;
        }
        Ok(())
    }
}

/// The classic Honeywell event-byte rendering shared by the firmware log, the
/// CLI's `decode` output and anything else that shows a status byte.
///
/// One implementation, so the two loops are labelled and polarised identically
/// everywhere; the CLI used to format these bits from its own copy of the masks
/// and could have drifted from the firmware without either noticing.
impl core::fmt::Display for StatusBits {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "loop1={} {}", self.loop1, self.without_loop1())
    }
}

/// One-line human summary, printing only the fields this frame's family carries.
impl core::fmt::Display for DecodedFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "id={:05x} event={}", self.txid, self.event())?;
        match self.body {
            Body::Event(e) => {
                write!(f, " counter={}", e.counter)?;
                match e.status {
                    // Worth distinguishing in the log: "this frame reports no
                    // contact state", "we could not decrypt it" and "we do not
                    // know this byte's layout" are three different problems, and
                    // only the second is fixed by configuring a seed.
                    Status::Sealed(raw) => write!(f, " status={raw:02x} (keyed, no seed)")?,
                    Status::Opaque(raw) => write!(f, " status={raw:02x}")?,
                    Status::Plain { bits, .. } => {
                        // `contact=` rather than `loop1=`: for a class that
                        // reports a door state, that is what loop-1 means, and
                        // printing both would be the same bit twice.
                        match self.contact() {
                            Some(c) => write!(f, " contact={c}")?,
                            None => write!(f, " loop1={}", bits.loop1)?,
                        }
                        write!(f, " {}", bits.without_loop1())?;
                    }
                }
            }
            Body::Startup(s) => write!(f, " nonce={} battery={}", s.nonce, s.battery)?,
            Body::Legacy(l) => {
                write!(f, " contact={} {}", l.status.loop1, l.status.without_loop1())?;
            }
        }
        if !self.crc_ok {
            f.write_str(" CRC-BAD")?;
        }
        Ok(())
    }
}

const POLY_8050: u16 = 0x8050;
const POLY_8005: u16 = 0x8005;

#[inline]
fn id20_from_be(b: &[u8]) -> u32 {
    // bytes 6..10 of a 96-bit frame, e.g. 03 86 31 39 -> 0x03863139 & 0xfffff
    (u32::from_be_bytes([b[6], b[7], b[8], b[9]])) & 0x000f_ffff
}

/// Decode a full `ff fe ...` frame. Length selects the family:
/// 8 bytes = legacy64, 12 bytes with `0xd0` = startup, 12 bytes with
/// `(type & 0xf0) == 0x70` = event.
pub fn decode(f: &[u8]) -> Result<DecodedFrame, DecodeError> {
    if f.len() < 2 || f[0] != 0xff || f[1] != 0xfe {
        return Err(DecodeError::BadPrefix);
    }
    match f.len() {
        8 => Ok(decode_legacy64(f)),
        12 if f[2] == 0xd0 => Ok(decode_d0(f)),
        12 if (f[2] & 0xf0) == 0x70 => Ok(decode_7x(f)),
        12 => Err(DecodeError::UnknownType),
        _ => Err(DecodeError::BadLength),
    }
}

/// The `0xff 0xfe` sync that opens every on-air frame. The CC1101 sync-word
/// engine strips it from the FIFO, so [`decode_body`] puts it back.
pub const SYNC: [u8; 2] = [0xff, 0xfe];

/// Body length (sync excluded) of the 96-bit families (`0x7x` events, `0xd0`).
pub const BODY_96: usize = 10;
/// Body length (sync excluded) of the 64-bit legacy family (e.g. the 5718).
pub const BODY_64: usize = 6;
/// Bytes the radio must collect to cover **both** families — a legacy frame is
/// shorter, so its tail is whatever follows on air and is simply ignored once
/// the 64-bit CRC validates. Use this as the CC1101 fixed `PKTLEN`.
pub const BODY_MAX: usize = BODY_96;

/// Extra bytes to capture past [`BODY_MAX`] so a frame that starts a few bits
/// late in the FIFO is still captured *whole*.
///
/// Hardware sync detection can fire early on these sensors: the preamble is a
/// run of 1s, which under Manchester is a symmetric chip stream, so the radio's
/// decoder can lock half a chip off and match the sync word one or more bits
/// before the true start of frame. The body then arrives **bit-shifted**, and
/// without slack its last bits fall off the end of a `BODY_MAX` read. Two bytes
/// covers any shift [`decode_body_aligned`] searches.
pub const BODY_SLACK: usize = 2;

/// Bytes the radio should actually collect: [`BODY_MAX`] plus [`BODY_SLACK`].
/// Use this as the CC1101 fixed `PKTLEN`.
pub const CAPTURE_MAX: usize = BODY_MAX + BODY_SLACK;

/// Decode a frame **body** — the bytes as they come out of the CC1101 RX FIFO,
/// with the `ff fe` sync word already consumed by the hardware sync engine.
///
/// Both on-air lengths are tried, longest first, and the first CRC-valid decode
/// wins: that is what lets a single radio configuration receive 96-bit
/// (5817-style `0x7x`/`0xd0`) **and** 64-bit legacy (5718-style) sensors at once.
/// A legacy frame read as [`BODY_MAX`] bytes simply carries 4 trailing bytes of
/// the next repeat, which the 64-bit CRC ignores.
///
/// Returns the CRC-valid frame, or — when neither length checks out — the
/// longest decode that at least parsed, so callers can log what arrived.
pub fn decode_body(body: &[u8]) -> Result<DecodedFrame, DecodeError> {
    let mut buf = [0u8; 2 + BODY_96];
    buf[..2].copy_from_slice(&SYNC);
    let mut fallback: Result<DecodedFrame, DecodeError> = Err(DecodeError::BadLength);
    for n in [BODY_96, BODY_64] {
        if body.len() < n {
            continue;
        }
        buf[2..2 + n].copy_from_slice(&body[..n]);
        match decode(&buf[..2 + n]) {
            Ok(f) if f.is_trustworthy() => return Ok(f),
            // Keep the first parse that got far enough to be worth reporting.
            other if fallback.is_err() => fallback = other,
            _ => {}
        }
    }
    fallback
}

/// [`decode_body`] over both bit polarities, so the OOK/Manchester inversion
/// that plagues these sensors needs no bench calibration: the CRC decides.
/// Returns the frame and whether the FIFO bytes had to be inverted (worth
/// logging once during bring-up — it should be stable for a given radio config).
pub fn decode_body_auto(body: &[u8]) -> Option<(DecodedFrame, bool)> {
    if let Ok(f) = decode_body(body)
        && f.is_trustworthy()
    {
        return Some((f, false));
    }
    let mut flipped = [0u8; 2 + BODY_96];
    let n = body.len().min(BODY_96);
    for i in 0..n {
        flipped[i] = !body[i];
    }
    match decode_body(&flipped[..n]) {
        Ok(f) if f.is_trustworthy() => Some((f, true)),
        _ => None,
    }
}

/// How the FIFO bytes had to be re-interpreted before a frame appeared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Alignment {
    /// The body was bit-inverted (OOK/Manchester polarity).
    pub inverted: bool,
    /// The frame started this many bits into the FIFO (0 = byte-aligned).
    /// Non-zero means hardware sync fired early — see [`BODY_SLACK`].
    pub bit_shift: u8,
}

/// Shift `src` left by `bits` (0..8), writing `out.len()` bytes.
/// Byte `i` of the result is `src[i] << bits | src[i+1] >> (8-bits)`.
fn shift_left(src: &[u8], bits: u8, out: &mut [u8]) {
    debug_assert!(bits < 8);
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = src.get(i).copied().unwrap_or(0);
        let lo = src.get(i + 1).copied().unwrap_or(0);
        *slot = if bits == 0 {
            hi
        } else {
            (hi << bits) | (lo >> (8 - bits))
        };
    }
}

/// [`decode_body_auto`] plus a **bit-alignment search**.
///
/// The CC1101's sync detector can fire a few bits early on these sensors (the
/// all-1s preamble is symmetric under Manchester, so the decoder may lock half a
/// chip off). The body then sits at a bit offset and every byte-aligned decode
/// fails, which looks exactly like "the radio is receiving garbage" even though
/// the frame is right there. This tries each of the 8 bit offsets, in both
/// polarities, and lets the CRC pick — so a shifted frame is recovered instead
/// of discarded.
///
/// Give it a [`CAPTURE_MAX`]-byte read so a shifted frame is complete. Returns
/// the frame and how it had to be interpreted; a consistently non-zero
/// `bit_shift` is worth logging, since it says the radio is mis-locking.
pub fn decode_body_aligned(body: &[u8]) -> Option<(DecodedFrame, Alignment)> {
    // Offset 0 first: the common case must stay cheap and must win ties.
    if let Some((f, inverted)) = decode_body_auto(body) {
        return Some((f, Alignment { inverted, bit_shift: 0 }));
    }
    let n = body.len().saturating_sub(1).min(BODY_MAX);
    if n < BODY_64 {
        return None;
    }
    let mut buf = [0u8; BODY_MAX];
    for bits in 1..8u8 {
        shift_left(body, bits, &mut buf[..n]);
        if let Some((f, inverted)) = decode_body_auto(&buf[..n]) {
            return Some((f, Alignment { inverted, bit_shift: bits }));
        }
    }
    None
}

fn decode_legacy64(f: &[u8]) -> DecodedFrame {
    let channel = f[2] >> 4;
    let poly = match channel {
        0x2 | 0x4 | 0x9 | 0xa | 0xc => POLY_8050,
        _ => POLY_8005,
    };
    let stored = u16::from_be_bytes([f[6], f[7]]);
    let raw_status = f[5];
    DecodedFrame {
        txid: ((f[2] as u32 & 0xf) << 16) | ((f[3] as u32) << 8) | f[4] as u32,
        crc_ok: crc16(&f[2..6], poly, 0) == stored,
        // Legacy frames are never keystreamed, so byte 5 is readable as it
        // stands — and battery rides in it (bit 0x08) rather than in a beacon.
        body: Body::Legacy(Legacy {
            type_byte: f[2],
            channel,
            status: StatusBits::from_byte(raw_status),
            raw_status,
        }),
    }
}

fn decode_d0(f: &[u8]) -> DecodedFrame {
    let stored = u16::from_be_bytes([f[10], f[11]]);
    // b3 (f[5]) high nibble is a coarse battery gauge; low nibble + f[4] (0x0f)
    // are constant, f[3] is a per-session nonce (not a counter). This beacon is
    // sent at power-on and re-sent ~hourly as the supervisory frame, so it is
    // where the panel (and we) learn battery status.
    let gauge = f[5] >> 4;
    DecodedFrame {
        txid: id20_from_be(f),
        crc_ok: crc16_8050(&f[2..10]) == stored,
        body: Body::Startup(Startup {
            nonce: u16::from_be_bytes([f[3], f[4]]),
            battery: Battery::from_gauge(gauge),
            gauge,
        }),
    }
}

fn decode_7x(f: &[u8]) -> DecodedFrame {
    // Packed 12-bit check: high nibble of byte 10 is payload (CRC'd with the low
    // nibble zeroed); low nibble of byte 10 + byte 11 store the top 12 CRC bits.
    let mut input = [0u8; 9];
    input[..8].copy_from_slice(&f[2..10]);
    input[8] = f[10] & 0xf0;
    let calc12 = crc16_8050(&input) >> 4;
    let stored12 = (((f[10] & 0x0f) as u16) << 8) | f[11] as u16;
    let raw_status = f[5];
    let counter = u16::from_be_bytes([f[3], f[4]]);
    let subtype = f[2];
    let class = EventClass::from_subtype(subtype, counter);
    // On the keyed subtypes byte 5 is XORed with this device's keystream, so it
    // stays Sealed until `Registry::apply_key` un-keys it. Nothing can read
    // contact bits out of ciphertext; the old code decoded them here anyway and
    // any consumer that did not go on to un-key the frame published the result.
    let status = if is_keyed_subtype(subtype) {
        Status::Sealed(raw_status)
    } else {
        // Unkeyed, but not therefore understood: no capture has established that
        // these subtypes use the Honeywell event-byte layout.
        Status::Opaque(raw_status)
    };
    DecodedFrame {
        txid: id20_from_be(f),
        crc_ok: calc12 == stored12,
        body: Body::Event(Event { subtype, class, counter, status }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> [u8; 12] {
        let mut out = [0u8; 12];
        let bytes = s.as_bytes();
        for i in 0..(s.len() / 2) {
            let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    #[test]
    fn decode_body_handles_both_families_from_one_radio_config() {
        // What the CC1101 FIFO holds after its sync engine eats `ff fe`.
        // 96-bit 5817 contact event: exactly BODY_96 body bytes.
        let full = hx("fffe7a0019d803863139a8f8");
        let d = decode_body(&full[2..]).unwrap();
        assert!(d.crc_ok);
        assert_eq!(d.family(), Family::Event7x);
        assert_eq!(d.txid, 0x63139);

        // 64-bit legacy 5718: only 6 body bytes are real. In fixed-length mode
        // the radio hands us BODY_MAX, so pad with the junk that would follow
        // on air — the 64-bit CRC must still validate.
        let legacy = hx("fffea630d6801f10");
        let mut body = [0xa5u8; BODY_MAX];
        body[..BODY_64].copy_from_slice(&legacy[2..8]);
        let d = decode_body(&body).unwrap();
        assert!(d.crc_ok, "legacy frame must validate despite trailing junk");
        assert_eq!(d.family(), Family::Legacy64);
        assert_eq!(d.txid, 0x630d6);
        assert_eq!(d.contact(), Some(Contact::Open));
    }

    #[test]
    fn decode_body_rejects_noise() {
        let noise = [0x5au8; BODY_MAX];
        // Either it fails to parse, or it parses with a bad CRC — never a
        // silently "valid" frame.
        assert!(!decode_body(&noise).is_ok_and(|f| f.is_trustworthy()));
    }

    #[test]
    fn all_zero_input_does_not_masquerade_as_a_frame() {
        // The 64-bit legacy check is CRC-16 with a zero init, and a zero-init
        // CRC over zero data is zero — so an empty FIFO literally matches its
        // own stored CRC and used to decode as legacy device 0x00000. On real
        // hardware that turns radio silence into a flood of phantom events.
        let zeros = [0u8; BODY_MAX];
        let decoded = decode_body(&zeros);
        if let Ok(f) = decoded {
            assert!(f.crc_ok, "sanity: this is exactly why crc_ok is not enough");
            assert_eq!(f.txid, 0);
            assert!(!f.is_plausible(), "TXID 0 must not be considered plausible");
            assert!(!f.is_trustworthy());
        }
        assert!(decode_body_auto(&zeros).is_none(), "must not report a frame");

        // Same story for an all-ones buffer, which the auto-polarity pass
        // inverts into all zeros.
        assert!(decode_body_auto(&[0xffu8; BODY_MAX]).is_none());
    }

    #[test]
    fn real_frames_are_still_trustworthy() {
        // The guard must not cost us any genuine frame.
        for h in [
            "fffe7a0019d803863139a8f8", // 5817 contact
            "fffed03a0f4003863139d6d0", // 5817 startup
            "fffe7239ab02038631394bdd", // 5817 heartbeat
        ] {
            let f = decode(&hx(h)).unwrap();
            assert!(f.is_trustworthy(), "{h}");
        }
        let legacy = hx("fffea630d6801f10");
        assert!(decode(&legacy[..8]).unwrap().is_trustworthy());
    }

    #[test]
    fn decode_body_auto_recovers_inverted_bytes() {
        let full = hx("fffe7a0019d803863139a8f8");
        let body = &full[2..];

        let (d, inverted) = decode_body_auto(body).unwrap();
        assert!(!inverted);
        assert_eq!(d.txid, 0x63139);

        // Same frame with the OOK polarity flipped: no bench calibration needed.
        let mut flipped = [0u8; BODY_96];
        for (o, b) in flipped.iter_mut().zip(body) {
            *o = !*b;
        }
        let (d, inverted) = decode_body_auto(&flipped).unwrap();
        assert!(inverted, "inverted bytes must be recognised");
        assert!(d.crc_ok);
        assert_eq!(d.txid, 0x63139);
        // A bare 0x7a decode reports no contact: byte 5 is still keystreamed.
        // See `keyed_events_report_no_contact_until_un_keyed`.
        assert_eq!(d.contact(), None);

        assert!(decode_body_auto(&[0x5au8; BODY_MAX]).is_none());
    }

    #[test]
    fn event_key_separates_the_two_contact_states_of_one_counter() {
        // The counter advances once per open-and-close cycle, so the same value
        // is transmitted in both states. Verified on hardware: a log with 18
        // distinct counters carried 31 distinct events.
        //
        // A key that ignores the status byte collapses those pairs, and a
        // consumer deduplicating on it publishes the same state forever.
        let open = decode(&hx("fffe7a0019d803863139a8f8")).unwrap();
        let mut closed = open;
        // Flip the contact bit in byte 5. The sum type makes this reach into the
        // Event variant, which is the point: there is no top-level `status` field
        // to poke on a frame family that has no such byte.
        let Body::Event(e) = &mut closed.body else { panic!("0x7a is an event") };
        e.status = Status::Sealed(e.status.raw() ^ 0x80); // other contact state

        assert_eq!(open.counter(), closed.counter(), "same counter, by construction");
        assert_ne!(
            open.event_key(),
            closed.event_key(),
            "the two states of one counter must be different events"
        );

        // ...while a genuine repeat of the same event is identical.
        let repeat = decode(&hx("fffe7a0019d803863139a8f8")).unwrap();
        assert_eq!(open.event_key(), repeat.event_key());
    }

    #[test]
    fn event_key_separates_devices_and_frame_types() {
        let a = decode(&hx("fffe7a0019d803863139a8f8")).unwrap();
        let legacy = decode(&hx("fffea630d6801f10")[..8]).unwrap();
        assert_ne!(a.event_key(), legacy.event_key(), "different devices");
    }

    #[test]
    fn published_golden_vector_decodes() {
        // An independently published capture of a V-DW21R-345, from outside this
        // project. Pre-inversion it is `00 01 85 FF BD EF FE C8 41 25 BA C3`;
        // after the inversion the rtl_433 decoder performs it becomes the frame
        // below. Its documented fields are subtype 0x7A, counter 0x0042, status
        // 0x10, id 0x0137BEDA, integrity 0x453C with a 12-bit check of 0x53C.
        //
        // Valuable precisely because nothing about it came from this codebase:
        // if our framing, field map, or CRC drifted, this breaks.
        let f = decode(&hx("fffe7a004210 0137beda453c".replace(' ', "").as_str()))
            .expect("published vector decodes");
        assert_eq!(f.type_byte(), 0x7a);
        assert_eq!(f.counter(), Some(0x0042));
        // The 20-bit TXID is the low bits of the 32-bit id field.
        assert_eq!(f.txid, 0x0137_beda & 0x000f_ffff);
        assert_eq!(f.txid, 507_610);
        assert!(f.crc_ok, "the 0x8050 12-bit check must validate");
        assert!(f.is_trustworthy());
    }

    #[test]
    fn decode_body_aligned_recovers_a_bit_shifted_frame() {
        // Reproduce the hardware failure: the CC1101's sync fired `bits` early,
        // so the body sits at a bit offset in the FIFO. Byte-aligned decoding
        // sees only garbage; the alignment search must find the frame.
        let full = hx("fffe7a0019d803863139a8f8");
        let body = &full[2..];

        for bits in 1..8u8 {
            // Build what the FIFO would hold: the frame pushed `bits` later,
            // with arbitrary preceding bits. CAPTURE_MAX gives the slack that
            // keeps the tail from falling off the end.
            let mut fifo = [0u8; CAPTURE_MAX];
            for (i, slot) in fifo.iter_mut().enumerate() {
                let hi = if i == 0 { 0xff } else { body.get(i - 1).copied().unwrap_or(0) };
                let lo = body.get(i).copied().unwrap_or(0);
                // right-shift the frame by `bits` == the radio latching early
                *slot = (hi << (8 - bits)) | (lo >> bits);
            }

            // Byte-aligned decoding cannot see it...
            assert!(
                decode_body_auto(&fifo[..BODY_MAX]).is_none(),
                "shift {bits} should defeat byte-aligned decode"
            );
            // ...but the alignment search recovers it exactly.
            let (d, a) = decode_body_aligned(&fifo)
                .unwrap_or_else(|| panic!("shift {bits} not recovered"));
            assert_eq!(a.bit_shift, bits, "reported shift");
            assert!(!a.inverted);
            assert_eq!(d.txid, 0x63139);
            assert!(d.crc_ok);
        }
    }

    #[test]
    fn decode_body_aligned_prefers_the_unshifted_reading() {
        // A clean capture must report shift 0 rather than some coincidental
        // offset, so a non-zero shift in the logs really means "radio mis-locked".
        let full = hx("fffe7a0019d803863139a8f8");
        let mut fifo = [0u8; CAPTURE_MAX];
        fifo[..BODY_96].copy_from_slice(&full[2..]);
        let (d, a) = decode_body_aligned(&fifo).unwrap();
        assert_eq!(a, Alignment { inverted: false, bit_shift: 0 });
        assert_eq!(d.txid, 0x63139);
    }

    #[test]
    fn decode_body_aligned_still_rejects_noise() {
        // Eight offsets x two polarities is a lot of chances to get lucky; the
        // CRC must still keep static out.
        assert!(decode_body_aligned(&[0x5au8; CAPTURE_MAX]).is_none());
        assert!(decode_body_aligned(&[0x00u8; CAPTURE_MAX]).is_none());
        assert!(decode_body_aligned(&[0xffu8; CAPTURE_MAX]).is_none());
    }

    #[test]
    fn legacy_open_closed() {
        let c = hx("fffea630d600af20");
        let d = decode(&c[..8]).unwrap();
        assert_eq!(d.family(), Family::Legacy64);
        assert_eq!(d.txid, 0x630d6);
        assert_eq!(d.contact(), Some(Contact::Closed));
        assert!(d.crc_ok);

        let o = hx("fffea630d6801f10");
        let d = decode(&o[..8]).unwrap();
        assert_eq!(d.contact(), Some(Contact::Open));
        assert!(d.crc_ok);
        assert!(!d.status_bits().unwrap().heartbeat);
    }

    #[test]
    fn d0_startup_both_sensors() {
        let a = hx("fffed0520f40038630d6e7b0");
        let d = decode(&a).unwrap();
        assert_eq!(d.family(), Family::StartupD0);
        assert_eq!(d.txid, 0x630d6); // 405718
        assert_eq!(d.event(), EventClass::Startup);
        assert!(d.crc_ok);

        let b = hx("fffed03a0f4003863139d6d0");
        let d = decode(&b).unwrap();
        assert_eq!(d.txid, 0x63139); // 405817
        assert!(d.crc_ok);
    }

    #[test]
    fn d0_battery_gauge_from_b3() {
        // Real CRC-valid 0xd0 beacons captured across a bench voltage sweep.
        // b3 high nibble: 0x3 = OK (>=~2.9 V), 0x4 = low, 0x5 = critical.
        for (h, lvl, batt) in [
            ("fffed0f30f300386313978b0", 0x3, Battery::Ok),       // ~3.0 V
            ("fffed03a0f4003863139d6d0", 0x4, Battery::Low),      // ~2.3-2.8 V
            ("fffed0a50f5003863139aef0", 0x5, Battery::Critical), // <=~2.2 V
        ] {
            let d = decode(&hx(h)).unwrap();
            assert!(d.crc_ok, "{h}: crc");
            let Body::Startup(st) = d.body else { panic!("{h}: 0xd0 is a startup beacon") };
            assert_eq!(st.gauge, lvl, "{h}: gauge");
            assert_eq!(st.battery, batt, "{h}: battery");
            assert_eq!(d.battery(), Some(batt), "{h}: accessor agrees");
        }
        // 0x7x events do not carry battery — and now cannot: the Event variant
        // has no battery field to leave unset.
        let c = decode(&hx("fffe7a0019d803863139a8f8")).unwrap();
        assert_eq!(c.battery(), None);
    }

    #[test]
    fn event_7a_contact() {
        let closed = hx("fffe7a00195803863139a3cb");
        let d = decode(&closed).unwrap();
        assert_eq!(d.family(), Family::Event7x);
        assert_eq!(d.event(), EventClass::Contact);
        assert_eq!(d.txid, 0x63139);
        assert_eq!(d.counter(), Some(0x0019));
        assert!(d.crc_ok);

        let open = hx("fffe7a0019d803863139a8f8");
        let d = decode(&open).unwrap();
        assert!(d.crc_ok);
    }

    #[test]
    fn keyed_events_report_no_contact_until_un_keyed() {
        // These two frames are the same device's counter 25 in its two contact
        // states. Byte 5 differs — but on a keyed subtype byte 5 is XORed with
        // the device keystream, so neither byte says anything about the door
        // until `Registry::apply_key` opens it with that device's seed.
        //
        // The old flat struct decoded loop-1 straight out of the ciphertext and
        // stored it in `contact_open`, with a comment admitting it was "naive".
        // Any consumer that did not go on to un-key the frame — a sensor with no
        // configured seed, most obviously — published that value as a door state.
        //
        // `Status::Sealed` holds only the raw byte, so there is no longer a
        // contact value to read out of it.
        for h in ["fffe7a0019d803863139a8f8", "fffe7a00195803863139a3cb"] {
            let d = decode(&hx(h)).unwrap();
            assert!(d.crc_ok, "{h}");
            let Body::Event(e) = d.body else { panic!("{h}: 0x7a is an event") };
            assert!(e.status.is_sealed(), "{h}: keyed byte must stay sealed");
            assert_eq!(d.contact(), None, "{h}");
            assert_eq!(d.status_bits(), None, "{h}");
            // The raw byte is still there for anyone who needs it (the cracker
            // does), it just is not dressed up as decoded fields.
            assert_eq!(d.status_byte(), Some(e.status.raw()), "{h}");
        }

        // A heartbeat's byte 5 is *not* keystreamed — but we have never
        // established that it carries the Honeywell event byte either, so it is
        // Opaque, not Plain. Both yield no bits; they differ in what would fix
        // that, which is what the log line reports.
        let hb = decode(&hx("fffe7239ab02038631394bdd")).unwrap();
        let Body::Event(e) = hb.body else { panic!("0x72 is an event") };
        assert!(!e.status.is_sealed(), "a heartbeat byte is not encrypted");
        assert_eq!(e.status, Status::Opaque(hb.status_byte().unwrap()));
        assert_eq!(hb.status_bits(), None);
        assert_eq!(hb.contact(), None);
    }

    #[test]
    fn event_72_is_heartbeat() {
        // Heartbeat is not a keyed contact event: contact stays None (its
        // status byte is not un-keyed the way a 0x7a/0x74/0x79 event is).
        let h5817 = hx("fffe7239ab02038631394bdd");
        let d = decode(&h5817).unwrap();
        assert_eq!(d.event(), EventClass::Heartbeat);
        assert_eq!(d.txid, 0x63139);
        assert_eq!(d.contact(), None);
        assert!(!d.is_keyed_event());
        assert!(d.crc_ok);

        let h5718 = hx("fffe7238fab2038630d63385");
        let d = decode(&h5718).unwrap();
        assert_eq!(d.event(), EventClass::Heartbeat);
        assert_eq!(d.txid, 0x630d6);
        assert!(d.crc_ok);
    }

    #[test]
    fn event_74_is_motion() {
        // 0x74 is a PIR2 motion event (keyed), not an uncharacterised subtype.
        let f = hx("fffe74e13474038d165c8ad6");
        let d = decode(&f).unwrap();
        assert_eq!(d.family(), Family::Event7x);
        assert_eq!(d.event(), EventClass::Motion);
        assert!(d.is_keyed_event());
        assert_eq!(d.txid, 0xd165c);
        assert!(d.crc_ok);
    }

    #[test]
    fn bad_crc_detected() {
        // one-bit change in the final byte of a known-good 7a frame
        let f = hx("fffe7a01d364038631393a4a");
        let d = decode(&f).unwrap();
        assert!(!d.crc_ok);
    }

    #[test]
    fn rejects_bad_prefix_and_length() {
        assert_eq!(decode(&[0x00, 0x00, 0x00]), Err(DecodeError::BadPrefix));
        assert_eq!(decode(&[0xff, 0xfe, 0x7a]), Err(DecodeError::BadLength));
        let unknown = hx("fffe99000000000000000000");
        assert_eq!(decode(&unknown), Err(DecodeError::UnknownType));
    }
}
