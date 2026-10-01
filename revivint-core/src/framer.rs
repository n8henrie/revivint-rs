//! Find the `0xFFFE` sync in a data-bit run and hand whole frames to [`decode`].
//!
//! Used by the software-decode firmware after [`crate::manchester::decode`].
//! The hardware-assisted firmware usually lets the CC1101 sync-word engine do
//! this, but the same logic is a useful fallback / cross-check.

use crate::bits::pack_msb_first;
use crate::frame::{decode, DecodedFrame};

/// `0xFFFE` as 16 bits, MSB-first: fifteen ones then a zero.
pub const SYNC_FFFE: [bool; 16] = [
    true, true, true, true, true, true, true, true, // 0xff
    true, true, true, true, true, true, true, false, // 0xfe
];

fn matches_sync(data: &[bool], at: usize) -> bool {
    if at + SYNC_FFFE.len() > data.len() {
        return false;
    }
    data[at..at + SYNC_FFFE.len()] == SYNC_FFFE
}

/// Scan `data` for sync words and invoke `cb` for every frame whose CRC/check
/// validates. Tries the 96-bit family first, then 64-bit; on a valid frame the
/// cursor advances past it (no duplicate hits), otherwise it steps one bit.
///
/// `cb` receives only CRC-valid frames — the false-positive rate on noise is
/// therefore that of the underlying check (negligible for the 96-bit families).
pub fn for_each_frame<F: FnMut(&DecodedFrame)>(data: &[bool], mut cb: F) {
    for_each_frame_at(data, |f, _| cb(f));
}

/// [`for_each_frame`], also reporting the **bit offset** each frame's sync was
/// found at. Used to tell whether a radio's own sync detection landed correctly.
pub fn for_each_frame_at<F: FnMut(&DecodedFrame, usize)>(data: &[bool], mut cb: F) {
    let mut i = 0;
    while i + SYNC_FFFE.len() <= data.len() {
        if !matches_sync(data, i) {
            i += 1;
            continue;
        }
        let mut advanced = false;
        // 96-bit (12 bytes) then 64-bit (8 bytes); the sync is part of the frame.
        for &nbits in &[96usize, 64] {
            if i + nbits > data.len() {
                continue;
            }
            let mut bytes = [0u8; 12];
            let n = pack_msb_first(&data[i..i + nbits], &mut bytes);
            if let Ok(frame) = decode(&bytes[..n]) {
                // `is_trustworthy`, not just `crc_ok`: a run of zero data bits
                // passes the zero-init legacy CRC as device 0. See
                // `DecodedFrame::is_plausible`.
                if frame.is_trustworthy() {
                    cb(&frame, i);
                    i += nbits;
                    advanced = true;
                    break;
                }
            }
        }
        if !advanced {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::bits::{unpack_msb_first, BitBuf};
    use crate::frame::{EventClass, Family};

    fn bits_from(bytes: &[u8]) -> BitBuf {
        let mut bb = BitBuf::new();
        unpack_msb_first(bytes, &mut bb);
        bb
    }

    #[test]
    fn finds_single_96bit_frame_with_leading_noise() {
        let frame = [
            0xff, 0xfe, 0x7a, 0x00, 0x19, 0xd8, 0x03, 0x86, 0x31, 0x39, 0xa8, 0xf8,
        ];
        // prepend some junk data bits that are not a valid sync+frame
        let mut data = BitBuf::new();
        for b in [false, true, false, true, true, false] {
            data.push(b);
        }
        for &b in bits_from(&frame).as_slice() {
            data.push(b);
        }

        let mut found = std::vec::Vec::new();
        for_each_frame(data.as_slice(), |f| found.push(*f));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].family(), Family::Event7x);
        assert_eq!(found[0].event(), EventClass::Contact);
        // No contact state: the framer does not hold seeds, so this frame's
        // byte 5 is still sealed. Recovering the door state is `Registry`'s job.
        assert_eq!(found[0].contact(), None);
        assert_eq!(found[0].txid, 0x63139);
    }

    #[test]
    fn finds_two_back_to_back_frames() {
        let f1 = [0xff, 0xfe, 0xa6, 0x30, 0xd6, 0x00, 0xaf, 0x20]; // legacy closed
        let f2 = [
            0xff, 0xfe, 0xd0, 0x3a, 0x0f, 0x40, 0x03, 0x86, 0x31, 0x39, 0xd6, 0xd0,
        ]; // d0 startup
        let mut data = BitBuf::new();
        for &b in bits_from(&f1).as_slice() {
            data.push(b);
        }
        for &b in bits_from(&f2).as_slice() {
            data.push(b);
        }

        let mut found = std::vec::Vec::new();
        for_each_frame(data.as_slice(), |f| found.push(*f));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].family(), Family::Legacy64);
        assert_eq!(found[0].contact(), Some(crate::Contact::Closed));
        assert_eq!(found[1].family(), Family::StartupD0);
        assert_eq!(found[1].txid, 0x63139);
    }

    #[test]
    fn a_run_of_zero_bits_after_a_sync_is_not_a_frame() {
        // A sync followed by silence: the zero-init legacy CRC over zero data is
        // zero, so this used to be reported as a contact event for device 0.
        let mut data = bits_from(&[0xff, 0xfe]);
        for _ in 0..96 {
            data.push(false);
        }
        let mut found = std::vec::Vec::new();
        for_each_frame(data.as_slice(), |f| found.push(*f));
        assert!(found.is_empty(), "phantom frames: {found:?}");
    }

    #[test]
    fn corrupt_frame_is_not_reported() {
        let mut frame = [
            0xff, 0xfe, 0x7a, 0x00, 0x19, 0xd8, 0x03, 0x86, 0x31, 0x39, 0xa8, 0xf8,
        ];
        frame[11] ^= 0x01; // break the check
        let data = bits_from(&frame);
        let mut found = std::vec::Vec::new();
        for_each_frame(data.as_slice(), |f| found.push(*f));
        assert!(found.is_empty());
    }
}

/// Decode one coherent Manchester run, whether or not it contains the sync word.
///
/// [`for_each_frame`] searches for `0xFFFE` and therefore only finds frames whose
/// **preamble was captured**. On a real receiver that is often not the case: the
/// AGC is still settling while the preamble goes by, so the slicer output is
/// fragmented and the first clean run begins at (or just after) the start of
/// frame. The run then holds exactly the 80-bit body of a 96-bit frame — a
/// perfectly good frame that a sync search can never match.
///
/// This tries the sync search first, then falls back to treating the run as a
/// bare body at each bit offset, prepending the sync and letting the CRC decide.
/// Both on-air lengths are covered (80-bit body for the 96-bit families, 48-bit
/// for the 64-bit legacy one).
///
/// Returns the number of frames reported.
/// [`for_each_frame_in_run_vetted`] with **no** gate on the sync-less fallback.
///
/// Named for what it is. The old name for this was `for_each_frame_in_run`, and
/// `decode_chip_capture` called it — so the hardware path ran its rescue
/// fallback wide open while the code around it discussed vetting. Anything
/// reporting frames to a user wants [`for_each_frame_in_run_vetted`] with a real
/// [`crate::Policy`]; this exists for tests and for callers that have their own
/// corroboration.
pub fn for_each_frame_in_run_unvetted<F: FnMut(&DecodedFrame, Recovery)>(
    bits: &[bool],
    cb: F,
) -> usize {
    for_each_frame_in_run_vetted(bits, |_| true, cb)
}

/// [`for_each_frame_in_run_unvetted`] with a guard on the sync-less fallback.
///
/// The fallback is far weaker evidence than a sync match, and it must be
/// treated that way. A `0x7x` frame carries only a **12-bit** check, and sliding
/// over 16 bit offsets x 2 frame lengths gives noise many chances to land on a
/// passing one — roughly a 1-in-100 shot per run rather than 1-in-4096. A frame
/// found that way has nothing corroborating it: no preamble, no sync, and a
/// TXID that could be anything.
///
/// `is_known` decides which TXIDs may be accepted from a bare body. Pass a
/// predicate matching your configured/learned devices, so a coincidental CRC hit
/// on noise cannot invent a sensor, publish a false open/closed, or — worst —
/// get a bogus seed learned from a fabricated `0x73` announce. Frames found via
/// a real sync match are not gated, because the sync is the corroboration.
pub fn for_each_frame_in_run_vetted<F: FnMut(&DecodedFrame, Recovery), K: Fn(&DecodedFrame) -> bool>(
    bits: &[bool],
    accepts: K,
    mut cb: F,
) -> usize {
    let mut n = 0;
    for_each_frame(bits, |f| {
        n += 1;
        // Found by its own in-band `ff fe`: the strongest evidence there is.
        cb(f, Recovery::default());
    });
    if n > 0 {
        return n;
    }
    // No sync in this run: it may *be* the body. Slide over a few bit offsets,
    // since the run's start is set by wherever the slicer became reliable.
    const BODY_96_BITS: usize = 80;
    const BODY_64_BITS: usize = 48;
    let mut bytes = [0u8; crate::BODY_96];
    for &nbits in &[BODY_96_BITS, BODY_64_BITS] {
        if bits.len() < nbits {
            continue;
        }
        let span = bits.len() - nbits;
        for start in 0..=span.min(16) {
            let want = nbits / 8;
            let got = pack_msb_first(&bits[start..start + nbits], &mut bytes[..want]);
            if got != want {
                continue;
            }
            if let Ok(f) = crate::decode_body(&bytes[..want])
                && f.is_trustworthy()
                // A seed-announce found without a sync is not trustworthy
                // enough to key a device with; require a real sync for that.
                && f.announced_seed().is_none()
                && accepts(&f)
            {
                cb(&f, Recovery { bit_offset: start, via_fallback: true, ..Default::default() });
                return 1;
            }
        }
    }
    0
}

/// Decode a **chip-level** FIFO capture: bytes of Manchester chips, sync already
/// consumed by the radio.
///
/// The companion to `cc1101::config::profile_hardware_chips`. The radio matched
/// the chip-encoded sync and filled its FIFO with raw chips, so the body starts
/// at chip 0 — but that is the only thing assumed. Manchester decoding runs here
/// with the same phase search and glitch recovery as the software path, then the
/// result is decoded as a frame body.
///
/// Both chip polarities are tried, since which one the slicer produces is not
/// knowable in advance.
/// Chip offsets searched by [`decode_chip_capture`]; covers the slack in
/// `cc1101::config::CAPTURE_CHIP_BYTES`.
pub const CHIP_START_SEARCH: usize = 16;

pub fn decode_chip_capture<K: Fn(&DecodedFrame) -> bool>(
    chips_bytes: &[u8],
    expect_inverted: bool,
    accepts: &K,
) -> Option<(DecodedFrame, Recovery)> {
    let mut chips = crate::bits::BitBuf::new();
    crate::bits::unpack_msb_first(chips_bytes, &mut chips);
    let all = chips.as_slice();
    // Slide the start explicitly rather than relying on run-breaking to find it.
    // Two things defeat that: a stream shifted by one chip is still *locally
    // valid* Manchester (every pair decodes, just to the wrong bits, so the
    // decoder never stumbles), and after a break the +1 resume can settle into
    // the wrong phase and stay there. Only the CRC distinguishes them.
    //
    // The capture carries slack for exactly this, so trying every offset within
    // it is both cheap (a Manchester pass over ~170 chips) and complete.
    for phase in 0..CHIP_START_SEARCH {
        if all.len() <= phase {
            continue;
        }
        // Expected polarity first: it is the one that works on a healthy link,
        // so the other pass is only paid for by frames that actually need it.
        for invert in [expect_inverted, !expect_inverted] {
            let mut found = None;
            crate::manchester::for_each_run(&all[phase..], invert, |bits| {
                if found.is_none() {
                    for_each_frame_in_run_vetted(bits, accepts, |f, r| found = Some((*f, r)));
                }
            });
            if let Some((f, r)) = found {
                let rec = Recovery {
                    chip_phase: phase,
                    inverted: invert != expect_inverted,
                    ..r
                };
                return Some((f, rec));
            }
        }
    }
    None
}

/// What the decoder had to do to recover a frame — the receive-quality signal.
///
/// Every field is zero/false when the signal arrived exactly as expected, so
/// [`Recovery::is_clean`] is "nothing needed correcting". Counting clean against
/// corrected frames is how you tell a receiver that is comfortably locked from
/// one that is scraping frames out of a marginal signal at the same yield —
/// both report 100% of events, and only this distinguishes them.
///
/// The fields are in the order the pipeline applies them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Chips into the capture where the sync word matched. Non-zero means the
    /// radio's packet engine triggered **early** — a bit error in the all-ones
    /// preamble matched the sync pattern — and the real frame was found by
    /// scanning forward. This is the measurement that says how much slack
    /// `CAPTURE_CHIP_BYTES` actually needs.
    pub sync_at: usize,
    /// Manchester chip phase that decoded. Non-zero means the chip stream was
    /// offset: a one-chip shift is still *locally valid* Manchester (every pair
    /// decodes, just to the wrong bits), so only the CRC catches it.
    pub chip_phase: usize,
    /// The chip polarity differed from the one the sync word implies.
    ///
    /// **Deviation, not absolute polarity.** Which polarity is "normal" is a
    /// property of the radio's slicer, derived from the configured sync word by
    /// [`crate::manchester::chips_need_inverting`] — for the CC1101 with
    /// `SYNC_WORD_CHIPS` (`0x5556`), the normal case is inverted chips. An
    /// earlier version reported the raw polarity instead, so a perfectly locked
    /// receiver logged `0/228 clean` and warned about its own working
    /// configuration.
    ///
    /// Non-zero here means individual frames are arriving in the *other*
    /// polarity from the rest, which is a slicer sitting on its decision
    /// boundary — a real signal-quality problem.
    pub inverted: bool,
    /// Bit offset the body was found at within its run. Non-zero means the frame
    /// did not start on a byte boundary where one was expected.
    pub bit_offset: usize,
    /// The frame was recovered by the sync-less sliding search rather than by
    /// matching `ff fe` in-band.
    ///
    /// **Informational, not a fault, on the chip path**: the CC1101 consumes the
    /// sync word itself, so a bare body is what it delivers by design and this is
    /// always true there. It is a real quality signal in the software path, where
    /// a run that carried its own sync is stronger evidence than one that did not.
    pub via_fallback: bool,
}

impl Recovery {
    /// Nothing had to be corrected: the radio triggered on the frame itself, the
    /// chips decoded at the delivered phase and polarity, and the body sat
    /// exactly where it was expected.
    ///
    /// [`Recovery::via_fallback`] is deliberately excluded — see its docs.
    pub const fn is_clean(&self) -> bool {
        self.sync_at == 0 && self.chip_phase == 0 && !self.inverted && self.bit_offset == 0
    }
}

/// Bytes of Manchester chips below which a capture cannot possibly hold a frame.
///
/// One chip-byte carries 8 chips = 4 data bits, and the shortest body the packet
/// engine ever delivers is a 64-bit legacy frame's [`crate::frame::BODY_64`]
/// bytes. Anything shorter is arithmetically undecodable, not merely unlucky.
pub const MIN_CHIP_BYTES: usize = crate::frame::BODY_64 * 2;

/// A FIFO capture long enough to be worth decoding.
///
/// This exists because of a specific, recurring confusion: a short FIFO read is
/// not a decode *failure*, it is a capture that never had enough bits to try. The
/// radio re-arms mid-burst and re-syncs on the tail of a packet it has already
/// delivered, so the FIFO holds five or ten bytes of preamble and stops. Treating
/// those as "undecodable bytes" filled the log with warnings for a receiver that
/// was working perfectly.
///
/// The invariant is enforced at construction, so a caller cannot ask for a decode
/// of something too short and then report the refusal as an error — there is no
/// value of this type for which that is possible.
#[derive(Debug, Clone, Copy)]
pub struct ChipCapture<'a>(&'a [u8]);

impl<'a> ChipCapture<'a> {
    /// `None` when `chips` is shorter than [`MIN_CHIP_BYTES`] — a late false
    /// trigger, which callers should count separately rather than warn about.
    pub fn new(chips: &'a [u8]) -> Option<Self> {
        (chips.len() >= MIN_CHIP_BYTES).then_some(Self(chips))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        false // by construction: len() >= MIN_CHIP_BYTES > 0
    }
}

/// Scan a long chip capture for the true chip-level sync and decode after it.
///
/// [`decode_chip_capture`] assumes the body starts within a few chips of the
/// capture. That holds for a production-length capture, but a diagnostic one is
/// deliberately long so that a frame is still present after an *early false
/// trigger* — and then the true sync can be tens or hundreds of chips in.
///
/// Returns the frame and the chip offset its sync was found at. A consistently
/// non-zero offset measures how early the radio is triggering, which is the
/// number needed before shortening the production capture.
///
/// `accepts` is **not optional**, and passing `|_| true` is a bug rather than a
/// relaxation. Both of these functions used to call the unvetted
/// [`for_each_frame_in_run_unvetted`], which is `for_each_frame_in_run_vetted(.., |_| true, ..)`
/// — so the sync-less sliding fallback ran with its known-TXID gate disabled.
/// Measured against valid-Manchester traffic that is not one of our frames
/// (a neighbour's 345 MHz sensor, say), that fabricated a frame from **0.106%**
/// of bursts, each with a fresh random TXID. Auto-discovery then announced every
/// one as a new Home Assistant device, with a retained config that outlives the
/// firmware that published it.
pub fn scan_chip_capture<K: Fn(&DecodedFrame) -> bool>(
    capture: ChipCapture<'_>,
    sync: u16,
    accepts: &K,
) -> Option<(DecodedFrame, Recovery)> {
    let mut chips = crate::bits::BitBuf::new();
    crate::bits::unpack_msb_first(capture.as_bytes(), &mut chips);
    let all = chips.as_slice();
    let want: [bool; 16] = core::array::from_fn(|i| (sync >> (15 - i)) & 1 == 1);
    // Which polarity this radio delivers, from the sync word itself — so the
    // quality statistics measure deviation from *this* radio's normal, not from
    // an assumed convention.
    let expect_inverted = crate::manchester::chips_need_inverting(sync);

    let mut i = 0;
    while i + want.len() < all.len() {
        if all[i..i + want.len()] == want {
            // Body chips begin just past the sync.
            let start = i + want.len();
            let mut body = [0u8; 24];
            let n = pack_msb_first(&all[start..], &mut body);
            if n > 0
                && let Some((f, r)) = decode_chip_capture(&body[..n], expect_inverted, accepts)
            {
                return Some((f, Recovery { sync_at: i, ..r }));
            }
        }
        i += 1;
    }
    // No embedded sync: fall back to treating the capture as starting at the body.
    decode_chip_capture(capture.as_bytes(), expect_inverted, accepts)
}

/// Where a frame was found inside a capture, and how it had to be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameSite {
    /// Bit position of the frame's sync within the capture. `0` = the radio's
    /// own sync detection was exactly right.
    pub bit_offset: usize,
    /// The capture had to be bit-inverted to decode.
    pub inverted: bool,
}

/// Search **CC1101 FIFO bytes** for frames, in both bit polarities.
///
/// The hardware-assisted path cannot trust where the radio thinks the frame
/// starts. These sensors open with a long run of `1` bits, and a single bit
/// error in that preamble produces a `…1110…` pattern indistinguishable from the
/// real `0xFFFE` sync — so the CC1101's sync detector fires *early, inside the
/// preamble*, and the FIFO fills with preamble while the true frame begins tens
/// of bits later. Captured payloads in that state are ~93% ones at the head with
/// the real sync sitting at bit offset 30-60.
///
/// The cure is to stop believing the radio's sync position and re-find it here:
/// hardware still does the expensive work (OOK slicing, Manchester decode), and
/// this walks the captured bits for a sync that is followed by a **CRC-valid**
/// frame. Give it a generous capture (see `cc1101::config::CAPTURE_BYTES`) so a
/// whole frame follows the early trigger.
///
/// `cb` receives a [`FrameSite`] saying **where** in the capture the frame was
/// found. That is the measurement that says whether the radio's own sync
/// detector can be trusted: a `bit_offset` of 0 means hardware sync landed
/// exactly on the frame and the software search was not needed; a consistently
/// non-zero offset means the radio is still triggering early and the search is
/// carrying the receiver.
///
/// Returns the number of frames reported; `cb` may fire more than once when the
/// capture spans a sensor's repeat.
pub fn for_each_frame_bytes<F: FnMut(&DecodedFrame, FrameSite)>(bytes: &[u8], mut cb: F) -> usize {
    let mut n = 0;
    for invert in [false, true] {
        let mut bits = crate::bits::BitBuf::new();
        for &b in bytes {
            for k in (0..8).rev() {
                let bit = (b >> k) & 1 == 1;
                if !bits.push(bit != invert) {
                    break;
                }
            }
        }
        for_each_frame_at(bits.as_slice(), |f, bit| {
            n += 1;
            cb(f, FrameSite { bit_offset: bit, inverted: invert });
        });
        // The right polarity yields frames; the wrong one yields nothing, so
        // stop rather than double-reporting the same burst.
        if n > 0 {
            break;
        }
    }
    n
}

#[cfg(test)]
mod byte_framer_tests {
    /// The devices these tests are configured for. Deliberately a real set
    /// rather than `|_| true`: the sync-less fallback is only allowed to invent
    /// a 96-bit frame for a TXID the operator has declared, and a test that
    /// blanket-allows everything would not notice that gate being removed again.
    const KNOWN: fn(&crate::DecodedFrame) -> bool =
        |f| matches!(f.txid, 0x63139 | 0x630d6 | 0xd165c);

    use super::*;

    fn hx(s: &str) -> std::vec::Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn finds_a_frame_after_an_early_sync_inside_the_preamble() {
        // Exactly the observed hardware failure: the radio triggered early, so
        // the capture is preamble ones, then the true sync, then the frame.
        // Byte-aligned decoding of the capture start sees only 0xff.
        let frame = hx("fffe7a0019d803863139a8f8");
        for lead in [3usize, 5, 7] {
            let mut capture = std::vec![0xffu8; lead];
            capture.extend_from_slice(&frame);
            capture.extend_from_slice(&[0xff; 4]);

            let mut found = std::vec::Vec::new();
            let n = for_each_frame_bytes(&capture, |f, _| found.push((f.txid, f.crc_ok)));
            assert!(n >= 1, "lead {lead}: no frame recovered");
            assert!(
                found.iter().any(|&(id, ok)| id == 0x63139 && ok),
                "lead {lead}: got {found:?}"
            );
        }
    }

    #[test]
    fn finds_a_frame_at_a_non_byte_aligned_offset() {
        // Shift the whole capture by 3 bits: the sync no longer starts on a byte
        // boundary, which is the case a byte-wise search would miss entirely.
        let frame = hx("fffe7a0019d803863139a8f8");
        let mut bits = std::vec::Vec::new();
        bits.extend(core::iter::repeat_n(true, 3 + 24)); // odd lead-in of preamble
        for b in &frame {
            for k in (0..8).rev() {
                bits.push((b >> k) & 1 == 1);
            }
        }
        bits.extend(core::iter::repeat_n(true, 8));
        let mut capture = std::vec![0u8; bits.len().div_ceil(8)];
        for (i, bit) in bits.iter().enumerate() {
            if *bit {
                capture[i / 8] |= 0x80 >> (i % 8);
            }
        }
        let mut ids = std::vec::Vec::new();
        for_each_frame_bytes(&capture, |f, _| ids.push(f.txid));
        assert!(ids.contains(&0x63139), "got {ids:?}");
    }

    #[test]
    fn inverted_capture_is_handled() {
        let frame = hx("fffe7a0019d803863139a8f8");
        let mut capture = std::vec![0xffu8; 4];
        capture.extend_from_slice(&frame);
        let inverted: std::vec::Vec<u8> = capture.iter().map(|b| !b).collect();
        let mut ids = std::vec::Vec::new();
        for_each_frame_bytes(&inverted, |f, _| ids.push(f.txid));
        assert!(ids.contains(&0x63139), "got {ids:?}");
    }

    #[test]
    fn decodes_a_run_that_contains_only_the_body() {
        // Measured on hardware: the AGC is still settling through the preamble,
        // so the first coherent Manchester run begins at the start of frame and
        // holds exactly the 80-bit body — no sync. A sync search finds nothing,
        // yet the frame is perfect (type byte and TXID matched bit-for-bit on
        // the bench). This is the case that made the software path look dead.
        let full = hx("fffe7a0019d803863139a8f8");
        let bits: std::vec::Vec<bool> = full[2..]
            .iter()
            .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
            .collect();
        assert_eq!(bits.len(), 80, "a 96-bit frame carries an 80-bit body");

        let mut n = 0;
        for_each_frame(&bits, |_| n += 1);
        assert_eq!(n, 0, "premise: a sync search cannot see a bare body");

        let mut ids = std::vec::Vec::new();
        assert_eq!(for_each_frame_in_run_unvetted(&bits, |f, _| ids.push(f.txid)), 1);
        assert_eq!(ids, std::vec![0x63139]);
    }

    #[test]
    fn still_decodes_a_run_that_does_contain_the_sync() {
        let full = hx("fffe7a0019d803863139a8f8");
        let bits: std::vec::Vec<bool> = full
            .iter()
            .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
            .collect();
        let mut ids = std::vec::Vec::new();
        assert_eq!(for_each_frame_in_run_unvetted(&bits, |f, _| ids.push(f.txid)), 1);
        assert_eq!(ids, std::vec![0x63139]);
    }

    #[test]
    fn a_body_run_with_a_leading_offset_still_decodes() {
        // The run starts wherever the slicer became reliable, which need not be
        // exactly the first bit of the body.
        let full = hx("fffe7a0019d803863139a8f8");
        for lead in [1usize, 3, 7] {
            let mut bits: std::vec::Vec<bool> = std::vec![true; lead];
            bits.extend(
                full[2..]
                    .iter()
                    .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1)),
            );
            let mut ids = std::vec::Vec::new();
            for_each_frame_in_run_unvetted(&bits, |f, _| ids.push(f.txid));
            assert!(ids.contains(&0x63139), "lead {lead}: got {ids:?}");
        }
    }

    #[test]
    fn a_bare_body_from_an_unknown_device_is_not_accepted() {
        // A sync-less match is weak evidence: the 0x7x check is only 12 bits and
        // the fallback slides over many offsets, so noise gets many attempts.
        // Without a sync to corroborate it, only a device we already know may be
        // accepted — otherwise a chance hit invents a sensor.
        let full = hx("fffe7a0019d803863139a8f8");
        let bits: std::vec::Vec<bool> = full[2..]
            .iter()
            .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
            .collect();

        // Known device: accepted.
        let mut n = 0;
        assert_eq!(
            for_each_frame_in_run_vetted(&bits, |f| f.txid == 0x63139, |_, _| n += 1),
            1
        );
        assert_eq!(n, 1);

        // Unknown device: rejected, even though the CRC passes.
        let mut n = 0;
        assert_eq!(for_each_frame_in_run_vetted(&bits, |_| false, |_, _| n += 1), 0);
        assert_eq!(n, 0);

        // But a *sync-bearing* frame is corroborated and needs no vetting.
        let with_sync: std::vec::Vec<bool> = full
            .iter()
            .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
            .collect();
        let mut n = 0;
        assert_eq!(
            for_each_frame_in_run_vetted(&with_sync, |_| false, |_, _| n += 1),
            1,
            "a real sync match must not be gated"
        );
    }

    #[test]
    fn a_legacy_sender_decodes_through_the_chip_path() {
        // The 5718-family sensor: 64-bit frame = FF FE + a 48-bit body. It uses
        // no keystream, so it carries no seed — but "needs no seed" and "needs
        // no declaring" are different claims, and treating them as one is what
        // let a neighbour's traffic fabricate devices. It is declared here with
        // a bare `VIVINT_KEYS` entry and decodes with no seed at all.
        let full = hx("fffea630d6801f10");
        assert_eq!(full.len() * 8, 64);

        let body: std::vec::Vec<bool> = full[2..]
            .iter()
            .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
            .collect();
        assert_eq!(body.len(), 48, "a legacy body is 48 bits");
        assert!(
            body.len() >= crate::manchester::MIN_RUN_BITS,
            "MIN_RUN_BITS must admit the shortest body, not the shortest frame"
        );

        // A legacy sensor needs no *seed*, but it does need to be *declared*.
        // Those are different things, and conflating them is what let a
        // neighbour's 345 MHz traffic fabricate devices: see `crate::Policy`.
        let declared = crate::Policy::from_map(&crate::cipher::parse_keys_for_test("405718"));
        let mut ids = std::vec::Vec::new();
        assert_eq!(
            for_each_frame_in_run_vetted(&body, |f| declared.accepts_bare(f), |f, _| ids.push(f.txid)),
            1,
            "a declared legacy body must decode with no seed configured"
        );

        // Undeclared, default policy: refused, because the sync-less fallback's
        // ~1000 CRC trials make a lone 16-bit check worth about 1 in 60.
        let strict = crate::Policy::from_map(&crate::cipher::parse_keys_for_test("405817=0c5e"));
        assert_eq!(
            for_each_frame_in_run_vetted(&body, |f| strict.accepts_bare(f), |_, _| {}),
            0,
            "an undeclared legacy sender must not be invented out of a CRC hit"
        );

        // ...unless the operator opted in with `+legacy`.
        let open = crate::Policy::from_map(&crate::cipher::parse_keys_for_test("405817=0c5e,+legacy"));
        assert_eq!(
            for_each_frame_in_run_vetted(&body, |f| open.accepts_bare(f), |_, _| {}),
            1,
            "`+legacy` must re-admit undeclared legacy senders"
        );
        assert_eq!(ids, std::vec![0x630d6]);

        // And through the chip capture the radio actually delivers.
        let mut chips = crate::bits::BitBuf::new();
        crate::manchester::encode(&body, &mut chips);
        let mut bytes = [0u8; 24];
        let n = crate::bits::pack_msb_first(chips.as_slice(), &mut bytes);
        let (f, _) = decode_chip_capture(&bytes[..n], false, &KNOWN).expect("legacy chip capture decodes");
        assert_eq!(f.txid, 0x630d6);
        assert_eq!(f.family(), crate::Family::Legacy64);
    }

    #[test]
    fn two_senders_of_different_families_both_decode() {
        // The point of the whole exercise: one radio, one configuration, both
        // sensor families. A keyed 5817 (96-bit, 12-bit check) and an unkeyed
        // 5718 (64-bit, full CRC) must both come through.
        let keyed = hx("fffe7a0019d803863139a8f8");
        let legacy = hx("fffea630d6801f10");

        let mut got = std::vec::Vec::new();
        for full in [&keyed, &legacy] {
            let body: std::vec::Vec<bool> = full[2..]
                .iter()
                .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
                .collect();
            let mut chips = crate::bits::BitBuf::new();
            crate::manchester::encode(&body, &mut chips);
            let mut bytes = [0u8; 24];
            let n = crate::bits::pack_msb_first(chips.as_slice(), &mut bytes);
            if let Some((f, _)) = decode_chip_capture(&bytes[..n], false, &KNOWN) {
                got.push(f.txid);
            }
        }
        assert_eq!(got, std::vec![0x63139, 0x630d6], "both senders must decode");
    }

    #[test]
    fn a_body_run_of_noise_is_still_rejected() {
        // Sliding over offsets and prepending a sync is a lot of chances to get
        // lucky; the CRC must still say no.
        let bits: std::vec::Vec<bool> = (0..96).map(|i| i % 3 == 0).collect();
        assert_eq!(for_each_frame_in_run_unvetted(&bits, |_, _| {}), 0);
        let zeros = std::vec![false; 96];
        assert_eq!(for_each_frame_in_run_unvetted(&zeros, |_, _| {}), 0);
        let ones = std::vec![true; 96];
        assert_eq!(for_each_frame_in_run_unvetted(&ones, |_, _| {}), 0);
    }

    #[test]
    fn chip_level_capture_decodes_end_to_end() {
        // What `profile_hardware_chips` delivers: the radio matched the
        // chip-encoded sync (0xAAA9) and filled the FIFO with the body's raw
        // chips. 80 data bits -> 160 chips -> 20 bytes.
        let full = hx("fffe7a0019d803863139a8f8");
        let body = &full[2..];
        let databits: std::vec::Vec<bool> = body
            .iter()
            .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
            .collect();
        let mut chips = crate::bits::BitBuf::new();
        crate::manchester::encode(&databits, &mut chips);
        assert_eq!(chips.len(), 160, "80 data bits Manchester to 160 chips");

        let mut bytes = [0u8; 20];
        crate::bits::pack_msb_first(chips.as_slice(), &mut bytes);
        let (f, _) = decode_chip_capture(&bytes, false, &KNOWN).expect("chip capture decodes");
        assert_eq!(f.txid, 0x63139);
        assert!(f.crc_ok);

        // The inverted-polarity capture must work too.
        let inv: std::vec::Vec<u8> = bytes.iter().map(|b| !b).collect();
        let (f, _) = decode_chip_capture(&inv, false, &KNOWN).expect("inverted chip capture decodes");
        assert_eq!(f.txid, 0x63139);
    }

    #[test]
    fn chip_level_capture_survives_a_shifted_start() {
        // The radio's sync could land a chip early or late; Manchester phase
        // search must absorb that. This is precisely the tolerance the CC1101's
        // own Manchester decoder does not have.
        let full = hx("fffe7a0019d803863139a8f8");
        let databits: std::vec::Vec<bool> = full[2..]
            .iter()
            .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
            .collect();
        let mut chips = crate::bits::BitBuf::new();
        crate::manchester::encode(&databits, &mut chips);

        for lead in [1usize, 2, 3] {
            let mut shifted: std::vec::Vec<bool> = std::vec![true; lead];
            shifted.extend(chips.as_slice());
            // Pad to a whole number of bytes: the radio captures
            // CAPTURE_CHIP_BYTES regardless, and the point of its slack is that
            // a shifted body is still captured whole.
            while shifted.len() % 8 != 0 {
                shifted.push(true);
            }
            let mut bytes = [0u8; 24];
            let n = crate::bits::pack_msb_first(&shifted, &mut bytes);
            assert!(
                decode_chip_capture(&bytes[..n], false, &KNOWN).is_some_and(|(f, _)| f.txid == 0x63139),
                "lead of {lead} chip(s) not recovered"
            );
        }
    }

    #[test]
    fn scan_finds_a_true_sync_after_an_early_false_trigger() {
        // The diagnostic capture is long precisely so that a frame is still
        // present after an early trigger. The scan must find the true 0xAAA9 and
        // report how far in it was — that offset is the measurement needed
        // before shortening the production capture.
        let full = hx("fffe7a0019d803863139a8f8");
        let databits: std::vec::Vec<bool> = full[2..]
            .iter()
            .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
            .collect();
        let mut body = crate::bits::BitBuf::new();
        crate::manchester::encode(&databits, &mut body);

        // `SYNC_WORD_CHIPS` is the *slicer-inverted* spelling, so a real capture
        // carries the body in that same polarity. Building the sync inverted and
        // the body logical — which this test used to do — is a capture no radio
        // can produce, and it made the polarity statistic look wrong when it was
        // the fixture that was wrong.
        let sync = crate::cc1101::config::SYNC_WORD_CHIPS;
        let body_chips: std::vec::Vec<bool> =
            if crate::manchester::chips_need_inverting(sync) {
                body.as_slice().iter().map(|c| !c).collect()
            } else {
                body.as_slice().to_vec()
            };

        for lead_chips in [0usize, 24, 96] {
            // preamble chips (alternating 1,0 = encoded ones), then the sync,
            // then the body — i.e. what an early trigger leaves in the FIFO.
            let mut all: std::vec::Vec<bool> = (0..lead_chips).map(|i| i % 2 == 0).collect();
            all.extend((0..16).map(|i| (sync >> (15 - i)) & 1 == 1));
            all.extend(&body_chips);
            let mut bytes = [0u8; 48];
            let n = crate::bits::pack_msb_first(&all, &mut bytes);

            let (f, rec) = scan_chip_capture(ChipCapture::new(&bytes[..n]).unwrap(), sync, &KNOWN)
                .unwrap_or_else(|| panic!("lead {lead_chips}: not found"));
            assert_eq!(f.txid, 0x63139, "lead {lead_chips}");
            assert_eq!(rec.sync_at, lead_chips, "reported sync offset");
            // A perfectly-triggered capture is the only one that reads clean;
            // a lead means the radio fired early inside the preamble.
            assert_eq!(rec.is_clean(), lead_chips == 0, "clean iff no lead");
        }
    }

    #[test]
    fn scan_rejects_noise() {
        let sync = crate::cc1101::config::SYNC_WORD_CHIPS;
        assert!(scan_chip_capture(ChipCapture::new(&[0xaa; 44]).unwrap(), sync, &KNOWN).is_none());
        assert!(scan_chip_capture(ChipCapture::new(&[0x00; 44]).unwrap(), sync, &KNOWN).is_none());
        assert!(scan_chip_capture(ChipCapture::new(&[0xff; 44]).unwrap(), sync, &KNOWN).is_none());
    }

    #[test]
    fn late_false_syncs_are_rejected_before_they_look_like_failures() {
        // Verbatim from a hardware run whose event yield was 100%: the radio
        // re-armed inside a burst, matched the sync word on the tail of a packet
        // it had already delivered, and the FIFO stopped a few bytes later. Each
        // of these was logged as "undecodable bytes" — an error message for a
        // receiver with nothing wrong with it.
        //
        // They are all shorter than any body, so there is no value of
        // `ChipCapture` to decode and no failure to report.
        for tail in [
            &[0x95, 0x66, 0xaa, 0xaa, 0xa9][..],
            &[0x95, 0x66, 0xaa, 0xaa, 0xa9, 0x5a, 0x96][..],
            &[0x95, 0x66, 0xaa, 0xaa, 0xa6, 0xaa, 0x56, 0x9a][..],
            &[0x95, 0x66, 0xaa, 0xaa, 0xa9, 0x56, 0x9a, 0x6a, 0xaa][..],
            &[0x95, 0x66, 0xaa, 0xaa, 0xa9, 0x56, 0x5a, 0x6a, 0xaa, 0xa5][..],
        ] {
            assert!(
                tail.len() < MIN_CHIP_BYTES,
                "{} bytes = {} data bits, under the {}-bit minimum body",
                tail.len(),
                tail.len() * 4,
                crate::frame::BODY_64 * 8,
            );
            assert!(ChipCapture::new(tail).is_none());
        }

        // A full-length capture that decodes to nothing is a different thing and
        // must still reach the caller as a genuine failure.
        let noise = [0x50u8; 22];
        let cap = ChipCapture::new(&noise).expect("full length");
        assert!(scan_chip_capture(cap, 0x5556, &KNOWN).is_none());
    }

    #[test]
    fn chip_level_capture_rejects_noise() {
        assert!(decode_chip_capture(&[0xff; 20], false, &KNOWN).is_none());
        assert!(decode_chip_capture(&[0x00; 20], false, &KNOWN).is_none());
        assert!(decode_chip_capture(&[0xaa; 20], false, &KNOWN).is_none());
        assert!(decode_chip_capture(&[0x5a; 20], false, &KNOWN).is_none());
    }

    #[test]
    fn the_chip_sync_word_is_the_manchester_encoding_of_the_frame_start() {
        // 0xFE is the last 8 data bits before the body (seven 1s then a 0).
        // Manchester: 1 -> 10, 0 -> 01, so 0xFE -> 1010101010101001 = 0xAAA9.
        let bits: std::vec::Vec<bool> = (0..8).rev().map(|k| (0xFEu8 >> k) & 1 == 1).collect();
        let mut chips = crate::bits::BitBuf::new();
        crate::manchester::encode(&bits, &mut chips);
        let mut out = [0u8; 2];
        crate::bits::pack_msb_first(chips.as_slice(), &mut out);
        let word = u16::from_be_bytes(out);
        // The derivation gives the LOGICAL convention...
        assert_eq!(word, crate::cc1101::config::SYNC_WORD_CHIPS_LOGICAL);
        // ...and the CC1101's slicer emits its inverse, which is what we program.
        // Measured: 0x5556 decodes 100% of events, 0xAAA9 decodes zero.
        assert_eq!(!word, crate::cc1101::config::SYNC_WORD_CHIPS);
    }

    #[test]
    fn reports_where_the_frame_was_found() {
        let frame = hx("fffe7a0019d803863139a8f8");

        // The radio's sync landed exactly on the frame: offset 0. This is the
        // case that, if it dominates on hardware, lets the capture shrink back
        // to one frame and the software search be retired.
        let mut sites = std::vec::Vec::new();
        for_each_frame_bytes(&frame, |_, s| sites.push(s));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0], FrameSite { bit_offset: 0, inverted: false });

        // The radio triggered 3 bytes early: the offset says so.
        let mut capture = std::vec![0xffu8; 3];
        capture.extend_from_slice(&frame);
        let mut sites = std::vec::Vec::new();
        for_each_frame_bytes(&capture, |_, s| sites.push(s));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].bit_offset, 24);
        assert!(!sites[0].inverted);
    }

    #[test]
    fn preamble_and_noise_alone_yield_nothing() {
        // All-ones (pure preamble), all-zeros (dead FIFO), and the real captures
        // from the bench that contained *no* complete frame must stay silent.
        assert_eq!(for_each_frame_bytes(&[0xff; 40], |_, _| {}), 0);
        assert_eq!(for_each_frame_bytes(&[0x00; 40], |_, _| {}), 0);
        let observed = hx("7fffffffffd7ffffbe8235f6");
        assert_eq!(for_each_frame_bytes(&observed, |_, _| {}), 0);
    }
}
