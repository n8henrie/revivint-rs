//! OOK Manchester (de)coding for the software-decode firmware.
//!
//! The CC1101 in async/transparent mode hands us the raw OOK *chip* stream
//! (RF on/off sampled at the ~133 µs half-bit). This module turns chips into
//! data bits and back. We use rtl_433's zero-bit convention, matching the
//! repo's proven `decoder.py`:
//!
//! * data bit `0` -> chips `[0, 1]`  (low→high transition)
//! * data bit `1` -> chips `[1, 0]`  (high→low transition)
//!
//! `invert` flips the chip polarity before decoding (rtl_433 inverts the
//! demodulated buffer; the right setting is a one-line calibration on real
//! hardware, so it is a parameter here and covered by tests both ways).
//!
//! # Where the timing comes from
//!
//! **Measured from this project's own raw I/Q captures**, not copied from a
//! datasheet or a generic decoder. Envelope-detecting `closed-heartbeat-*.complex16s`
//! (250 kHz sample rate) finds six identical 52 ms bursts — the sensor repeating
//! one frame — whose edge widths cluster at ~133 µs and ~269 µs. Halving the
//! two-chip cluster gives **134.5 µs**, and the repo's capture command
//! (`capture.sh`, `-X '…s=133,l=133,r=500…'`) has decoded 640k rows at exactly
//! 96 and 64 bits with `s=133`.
//!
//! rtl_433's generic `honeywell.c` declares `short_width = 156` and this code
//! previously copied that. It is **15% too slow for this transmitter**, which is
//! enough to break both receive paths: the software path quantises pulses into
//! the wrong number of chips, and the hardware path programs the CC1101 bit
//! synchroniser at the wrong rate, so it drifts and corrupts roughly one bit per
//! byte — visible as a preamble of `fb 7f df` instead of a clean run of `ff`.

use crate::bits::BitBuf;

/// Manchester half-bit (one chip) in microseconds. Measured: see module docs.
pub const CHIP_US: u32 = 133;

/// Chips per second — the CC1101 "data rate" for this signal, since with
/// hardware Manchester the programmed baud is the *chip* rate and the decoded
/// data-bit rate is half of it.
///
/// **Derived** from [`CHIP_US`] rather than hand-maintained: the two were
/// independently written constants that silently disagreed with the measured
/// timing, and nothing could catch that.
pub const CHIP_BAUD: u32 = 1_000_000 / CHIP_US;

/// Inter-packet gap that resets the slicer (rtl_433 `reset_limit`, and the
/// `r=500` of the proven capture command). Comfortably above the longest
/// legitimate Manchester run of two chips.
pub const RESET_US: u32 = 500;

/// Encode data bits to a chip stream (test/helper; inverse of [`decode`]).
pub fn encode(data: &[bool], out: &mut BitBuf) {
    out.clear();
    for &bit in data {
        if bit {
            out.push(true);
            out.push(false);
        } else {
            out.push(false);
            out.push(true);
        }
    }
}

/// Decode a chip stream to data bits, starting at chip `start`.
///
/// Stops at the first invalid Manchester pair (`00`/`11`), which marks the end of
/// a coherent run; returns the number of chips consumed **from `start`** so a
/// caller can resume past a glitch. See [`for_each_run`], which is what callers
/// working from real radio captures should use.
pub fn decode_from(chips: &[bool], start: usize, invert: bool, out: &mut BitBuf) -> usize {
    out.clear();
    let mut i = start;
    while i + 1 < chips.len() {
        let (a, b) = if invert {
            (!chips[i], !chips[i + 1])
        } else {
            (chips[i], chips[i + 1])
        };
        match (a, b) {
            (true, false) => {
                out.push(true);
            }
            (false, true) => {
                out.push(false);
            }
            _ => break, // 00 or 11: not Manchester, end of run
        }
        i += 2;
    }
    i - start
}

/// Decode a chip stream to data bits from chip 0. Thin wrapper over
/// [`decode_from`]; prefer [`for_each_run`] for real captures.
pub fn decode(chips: &[bool], invert: bool, out: &mut BitBuf) -> usize {
    decode_from(chips, 0, invert, out)
}

/// A run shorter than this cannot hold anything decodable.
///
/// Sized to the **shortest** body, not the shortest full frame: a 64-bit legacy
/// frame is `FF FE` plus a 48-bit body, and on a real receiver the preamble and
/// sync are usually lost while the AGC settles, so what arrives is the bare
/// body. A 64-bit threshold silently discarded every legacy sender — they never
/// reached the decoder at all.
pub const MIN_RUN_BITS: usize = 48;

/// Decode **every** coherent Manchester run in a chip stream, recovering both
/// chip phase and glitches, and hand each run's data bits to `cb`.
///
/// Two things make a single [`decode`] call from chip 0 useless on real radio
/// captures:
///
/// * **Phase.** Manchester pairs chips, so a capture that begins one chip late
///   pairs `(c1,c2) (c3,c4)…` instead of `(c0,c1) (c2,c3)…` and every pair is
///   invalid. Polarity is a *different* problem — inverting `00` gives `11`,
///   which is equally invalid — so trying both polarities does not fix phase.
/// * **Glitches.** The OOK slicer emits occasional runt pulses, and this
///   protocol is documented to carry a non-Manchester prefix. Stopping at the
///   first invalid pair therefore abandons a whole burst because of one bad chip
///   near its start.
///
/// Resuming at `start + used + 1` after an invalid pair skips the offending chip
/// *and* flips the phase, so both problems are handled by the same walk: if the
/// stream is phase-1, the pair at chip 0 fails immediately and the next attempt
/// begins at chip 1, already aligned.
pub fn for_each_run<F: FnMut(&[bool])>(chips: &[bool], invert: bool, mut cb: F) {
    let mut buf = BitBuf::new();
    let mut i = 0;
    while i + 1 < chips.len() {
        let used = decode_from(chips, i, invert, &mut buf);
        if buf.len() >= MIN_RUN_BITS {
            cb(buf.as_slice());
        }
        // +1 past the invalid pair: skips the bad chip and flips phase.
        i += used + 1;
    }
}

/// Shortest pulse worth believing, as a symbol.
///
/// Half a chip.
///
/// The receiver's OOK slicer is threshold-skewed, so a legitimate one-chip pulse
/// on the short (low) side is well under a full chip: measured across runs it
/// ranges 84-118 us, i.e. down to ~63% of a chip. Glitches measure 16-50 us.
/// Half a chip (66 us) sits in that gap with real margin on both sides.
///
/// A tighter threshold is a trap: 79 us was tried, sitting only 5 us below the
/// shortest real pulse seen at the time, and it dropped genuine chips mid-frame
/// on the next run — which fragments the burst into runs too short to contain a
/// frame, and looks exactly like "the decoder stopped working".
///
/// A pulse below this still contributes its **duration** to the running clock in
/// [`pulses_to_chips`] — only its level is discarded — so filtering a glitch
/// merges the pulses either side of it instead of shifting the phase.
pub const MIN_PULSE_US: u32 = CHIP_US / 2;

/// A low gap at least this long ends the burst.
///
/// Must sit **above the longest legitimate Manchester run**, which is two chips
/// (266 us). [`RESET_US`] clears that comfortably now the chip width is right —
/// with the old 156 us chip it did not, which is why this used to need its own
/// larger value.
pub const BURST_GAP_US: u32 = RESET_US;

/// Convert a pulse list (level, duration_µs) — e.g. from the C3 RMT peripheral —
/// into a chip stream by rounding each pulse to a whole number of [`CHIP_US`]
/// chips. Pulses shorter than [`MIN_PULSE_US`] are dropped as glitches. A gap
/// (`level == false`) at least [`BURST_GAP_US`] long is treated as the end of the
/// burst and stops expansion.
pub fn pulses_to_chips(pulses: &[(bool, u32)], out: &mut BitBuf) {
    out.clear();
    for &(level, dur) in pulses {
        if !level && dur >= BURST_GAP_US {
            break;
        }
        // Glitches are dropped outright rather than rounded up to a whole chip.
        if dur < MIN_PULSE_US {
            continue;
        }
        // Round each pulse **independently**.
        //
        // A cumulative chip clock was tried here and is worse, because it turns
        // a tiny rate error into a guaranteed failure: the transmitter measures
        // 133.5 us against a 133 us constant (+0.38%), which sounds harmless but
        // accumulates to a whole extra chip by chip ~133 — and a frame is 192
        // chips, so every frame breaks in its second half. Independent rounding
        // cannot accumulate, and the margins are large: the 1-vs-2 chip boundary
        // is 200 us while measured pulses cluster at 84-186 and 219-316.
        let n = ((dur + CHIP_US / 2) / CHIP_US).max(1) as usize;
        out.push_n(level, n);
    }
}


/// Whether a chip stream that matched `sync` has to be **inverted** before
/// Manchester decoding — i.e. which polarity this radio's slicer delivers.
///
/// Derived, not assumed. The sync word *is* the Manchester encoding of the
/// frame's `0xFE`, so decoding it each way and seeing which yields `0xFE`
/// settles the question for any sync word, including one a user configured.
///
/// This exists because getting it wrong is invisible: the decoder searches both
/// polarities and succeeds either way, so the *only* symptom is a quality
/// statistic reporting that every single frame needed a correction. Which is
/// exactly what shipped — the CC1101's `SYNC_WORD_CHIPS` (`0x5556`) is the inverted spelling,
/// so `invert = true` is this radio's **normal** case, and counting it as work
/// done made a perfectly locked receiver read 0% clean.
pub const fn chips_need_inverting(sync: u16) -> bool {
    let mut byte: u8 = 0;
    let mut i = 0;
    while i < 8 {
        // Same pair convention as `manchester::decode_from` with `invert=true`:
        // (1,0) -> 1, (0,1) -> 0, taken after inverting both chips.
        let a = (sync >> (15 - 2 * i)) & 1 == 0; // !chip
        let b = (sync >> (14 - 2 * i)) & 1 == 0; // !chip
        let bit = match (a, b) {
            (true, false) => 1u8,
            (false, true) => 0u8,
            _ => return false, // not Manchester inverted; assume as-delivered
        };
        byte = (byte << 1) | bit;
        i += 1;
    }
    byte == 0xfe
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bits::{pack_msb_first, unpack_msb_first};

    fn data_bits_of(bytes: &[u8]) -> BitBuf {
        let mut bb = BitBuf::new();
        unpack_msb_first(bytes, &mut bb);
        bb
    }

    #[test]
    fn encode_decode_roundtrip_noninverted() {
        let frame = [0xff, 0xfe, 0x7a, 0x01, 0xd3, 0x64];
        let data = data_bits_of(&frame);
        let mut chips = BitBuf::new();
        encode(data.as_slice(), &mut chips);
        assert_eq!(chips.len(), data.len() * 2);

        let mut back = BitBuf::new();
        let consumed = decode(chips.as_slice(), false, &mut back);
        assert_eq!(consumed, chips.len());
        assert_eq!(back.len(), data.len());

        let mut out = [0u8; 6];
        pack_msb_first(back.as_slice(), &mut out);
        assert_eq!(out, frame);
    }

    #[test]
    fn inverted_chips_decode_with_invert_flag() {
        let frame = [0xff, 0xfe, 0xd0];
        let data = data_bits_of(&frame);
        let mut chips = BitBuf::new();
        encode(data.as_slice(), &mut chips);

        // physically invert the chip stream
        let inverted: BitBuf = {
            let mut b = BitBuf::new();
            for &c in chips.as_slice() {
                b.push(!c);
            }
            b
        };

        let mut wrong = BitBuf::new();
        decode(inverted.as_slice(), false, &mut wrong); // wrong polarity
        let mut right = BitBuf::new();
        decode(inverted.as_slice(), true, &mut right); // corrected

        let mut out = [0u8; 3];
        pack_msb_first(right.as_slice(), &mut out);
        assert_eq!(out, frame);
        // the wrong-polarity decode must NOT reproduce the frame
        let mut wout = [0u8; 3];
        pack_msb_first(wrong.as_slice(), &mut wout);
        assert_ne!(wout, frame);
    }

    #[test]
    fn decode_stops_at_invalid_pair() {
        // valid "10","01" then an invalid "11"
        let chips = [true, false, false, true, true, true];
        let mut out = BitBuf::new();
        let consumed = decode(&chips, false, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(consumed, 4);
        assert_eq!(out.as_slice(), &[true, false]);
    }

    #[test]
    fn pulses_round_to_chips() {
        // one long high pulse of ~3 chips, then short low of 1 chip, then big gap
        let pulses = [
            (true, CHIP_US * 3 + 10),
            (false, CHIP_US),
            (false, RESET_US * 3), // burst end
            (true, CHIP_US),       // ignored, after gap
        ];
        let mut chips = BitBuf::new();
        pulses_to_chips(&pulses, &mut chips);
        assert_eq!(chips.as_slice(), &[true, true, true, false]);
    }

    #[test]
    fn pulses_then_manchester_recovers_frame() {
        // full SW pipeline: frame -> chips -> run-length pulses -> chips -> data
        let frame = [0xff, 0xfe, 0x7a, 0x00, 0x19, 0x58];
        let data = data_bits_of(&frame);
        let mut chips = BitBuf::new();
        encode(data.as_slice(), &mut chips);

        // build pulses by run-length encoding the chips at CHIP_US each
        let mut pulses = std::vec::Vec::new();
        let s = chips.as_slice();
        let mut i = 0;
        while i < s.len() {
            let level = s[i];
            let mut run = 0u32;
            while i < s.len() && s[i] == level {
                run += 1;
                i += 1;
            }
            pulses.push((level, run * CHIP_US));
        }

        let mut chips2 = BitBuf::new();
        pulses_to_chips(&pulses, &mut chips2);
        let mut back = BitBuf::new();
        decode(chips2.as_slice(), false, &mut back);
        let mut out = [0u8; 6];
        pack_msb_first(back.as_slice(), &mut out);
        assert_eq!(out, frame);
    }

    /// A real captured 5817 contact frame: 96 bits, so a decoded run clears
    /// [`MIN_RUN_BITS`] the way an on-air frame does.
    const REAL_FRAME: [u8; 12] = [
        0xff, 0xfe, 0x7a, 0x00, 0x19, 0xd8, 0x03, 0x86, 0x31, 0x39, 0xa8, 0xf8,
    ];

    /// Build the (level, duration) pulse list a radio would produce for `frame`.
    fn pulses_for(frame: &[u8], lead_chips: usize) -> std::vec::Vec<(bool, u32)> {
        let data = data_bits_of(frame);
        let mut chips = BitBuf::new();
        encode(data.as_slice(), &mut chips);
        let mut s = std::vec::Vec::new();
        s.extend(core::iter::repeat_n(true, lead_chips)); // preamble-ish lead-in
        s.extend(chips.as_slice().iter().copied());
        let mut pulses = std::vec::Vec::new();
        let mut i = 0;
        while i < s.len() {
            let level = s[i];
            let mut run = 0u32;
            while i < s.len() && s[i] == level {
                run += 1;
                i += 1;
            }
            pulses.push((level, run * CHIP_US));
        }
        pulses
    }

    fn recovers(pulses: &[(bool, u32)], frame: &[u8]) -> bool {
        let mut chips = BitBuf::new();
        pulses_to_chips(pulses, &mut chips);
        let want = data_bits_of(frame);
        for invert in [false, true] {
            let mut hit = false;
            for_each_run(chips.as_slice(), invert, |bits| {
                if bits.windows(want.len()).any(|w| w == want.as_slice()) {
                    hit = true;
                }
            });
            if hit {
                return true;
            }
        }
        false
    }

    #[test]
    fn recovers_a_frame_that_starts_on_an_odd_chip() {
        // Phase, not polarity: a capture beginning one chip late pairs every
        // chip wrongly, and inverting cannot fix it (inverting 00 gives 11).
        // This is the defect that produced bursts-but-no-frames on hardware.
        let frame = REAL_FRAME;
        for lead in [0usize, 1, 2, 3] {
            assert!(
                recovers(&pulses_for(&frame, lead), &frame),
                "lead of {lead} chip(s) not recovered"
            );
        }
    }

    #[test]
    fn a_runt_glitch_does_not_destroy_the_burst() {
        // A 1 us slicer glitch used to become a whole chip via `.max(1)`,
        // shifting the phase of everything after it; and decoding stopped at the
        // first invalid pair, so one glitch cost the entire capture.
        let frame = REAL_FRAME;
        let mut pulses = pulses_for(&frame, 0);
        pulses.insert(1, (false, 1)); // runt, far below a chip
        pulses.insert(2, (true, 2));
        assert!(recovers(&pulses, &frame), "glitch destroyed the burst");
    }

    #[test]
    fn a_non_manchester_prefix_is_skipped() {
        // The protocol is documented to carry a prefix that is not valid
        // Manchester; decoding must resume past it rather than give up.
        let frame = REAL_FRAME;
        let mut pulses = std::vec![(true, CHIP_US * 2), (false, CHIP_US * 2), (true, CHIP_US * 2)];
        pulses.extend(pulses_for(&frame, 0));
        assert!(recovers(&pulses, &frame), "prefix stopped the decoder");
    }

    #[test]
    fn jittered_pulses_still_decode() {
        // Real captures never land exactly on CHIP_US.
        let frame = REAL_FRAME;
        let mut pulses = pulses_for(&frame, 0);
        for (i, p) in pulses.iter_mut().enumerate() {
            let d = if i % 3 == 0 { 12 } else { 0 };
            p.1 = if i % 2 == 0 { p.1 + d } else { p.1.saturating_sub(d) };
        }
        assert!(recovers(&pulses, &frame), "jitter broke decoding");
    }

    #[test]
    fn burst_gap_exceeds_the_longest_legitimate_run() {
        // Manchester runs reach two chips; a burst-end threshold at or below
        // that truncates ordinary data mid-frame.
        const { assert!(BURST_GAP_US > 2 * CHIP_US) };
    }

    #[test]
    fn timing_matches_the_measured_transmitter() {
        // Measured from the repo's raw I/Q: 52 ms bursts whose edges cluster at
        // ~133 us and ~269 us (the two-chip run), i.e. a 134.5 us chip. The old
        // 156 us — copied from rtl_433's generic honeywell.c — was 15% slow and
        // broke both receive paths. Pin it so it cannot drift back.
        assert!(
            (130..=138).contains(&CHIP_US),
            "chip width {CHIP_US} us is outside the measured 133-135 us"
        );
        // The radio's baud must be the chip rate, derived from the same number.
        assert_eq!(CHIP_BAUD, 1_000_000 / CHIP_US);
        assert!((7_300..=7_700).contains(&CHIP_BAUD), "baud {CHIP_BAUD}");
    }

    /// Render chips as pulses with the **measured** duty-cycle skew of the real
    /// receiver: a one-chip HIGH is ~122% of a chip, a one-chip LOW ~78%, and a
    /// high+low pair sums to two chips.
    fn pulses_skewed(frame: &[u8], lead_chips: usize) -> std::vec::Vec<(bool, u32)> {
        let data = data_bits_of(frame);
        let mut chips = BitBuf::new();
        encode(data.as_slice(), &mut chips);
        let mut all = std::vec::Vec::new();
        all.extend(core::iter::repeat_n(true, lead_chips));
        all.extend(chips.as_slice().iter().copied());

        let mut pulses = std::vec::Vec::new();
        let mut i = 0;
        while i < all.len() {
            let level = all[i];
            let mut run = 0u32;
            while i < all.len() && all[i] == level {
                run += 1;
                i += 1;
            }
            // The slicer's threshold offset is a fixed shift, not a scaling:
            // measured, a 1-chip high is 164 us (134+30) and a 2-chip high is
            // ~295 us (268+30), while lows are short by the same ~30 us.
            let ideal = run * CHIP_US;
            let d = if level { ideal + 30 } else { ideal - 30 };
            pulses.push((level, d));
        }
        pulses
    }

    #[test]
    fn decodes_with_the_measured_duty_cycle_skew() {
        // The receiver's OOK slicer stretches highs and shortens lows. Rounding
        // each pulse independently lets that bias accumulate across a frame;
        // anchoring to a cumulative chip clock cancels it every pair. This is
        // the real-hardware shape, so it must decode.
        let frame = REAL_FRAME;
        for lead in [0usize, 1, 2] {
            assert!(
                recovers(&pulses_skewed(&frame, lead), &frame),
                "skewed duty cycle, lead {lead}, not recovered"
            );
        }
    }

    #[test]
    fn a_glitch_keeps_its_time_but_loses_its_level() {
        // Dropping a glitch's duration as well as its level would shift the chip
        // clock; only the level may be discarded. Splitting one real pulse into
        // (real, glitch, real) must therefore still decode.
        let frame = REAL_FRAME;
        let base = pulses_skewed(&frame, 0);
        let mut pulses = std::vec::Vec::new();
        for (i, &(lvl, dur)) in base.iter().enumerate() {
            if i == 6 && dur > 140 {
                // A realistic glitch: a brief spurious transition near the end
                // of a pulse, leaving the bulk of it intact. Total duration is
                // unchanged, so the chip clock must not move.
                pulses.push((lvl, dur - 60));
                pulses.push((!lvl, 25));
                pulses.push((lvl, 35));
            } else {
                pulses.push((lvl, dur));
            }
        }
        assert!(recovers(&pulses, &frame), "glitch shifted the chip clock");
    }

    #[test]
    fn glitch_threshold_sits_between_measured_glitches_and_real_pulses() {
        // Measured across hardware runs: glitches 16-50 us, real one-chip lows
        // 84-118 us (the slicer skew makes the short side ~63% of a chip).
        const { assert!(MIN_PULSE_US > 50, "would keep measured glitches") };
        const {
            assert!(
                MIN_PULSE_US < 84,
                "would drop real one-chip pulses; the short side of the duty \
                 cycle reaches 63% of a chip"
            )
        };
    }

    #[test]
    fn a_small_rate_error_does_not_accumulate_across_a_frame() {
        // The transmitter is never exactly CHIP_US. Measured runs give 133.1,
        // 133.5 and 134.6 us against a 133 us constant — up to +1.2%. Rounding
        // each pulse on its own cannot accumulate that; a cumulative chip clock
        // can, and did: +0.38% is a whole extra chip by chip 133, which corrupts
        // the second half of every 192-chip frame while looking like a clean
        // decoder from the outside.
        let frame = REAL_FRAME;
        for pct in [-12i64, -4, 4, 12] {
            let data = data_bits_of(&frame);
            let mut chips = BitBuf::new();
            encode(data.as_slice(), &mut chips);
            let all: std::vec::Vec<bool> = chips.as_slice().to_vec();
            let mut pulses = std::vec::Vec::new();
            let mut i = 0;
            while i < all.len() {
                let level = all[i];
                let mut run = 0u32;
                while i < all.len() && all[i] == level {
                    run += 1;
                    i += 1;
                }
                // real chip = CHIP_US * (1 + pct/1000)
                let d = (i64::from(run * CHIP_US) * (1000 + pct) / 1000) as u32;
                pulses.push((level, d));
            }
            assert!(
                recovers(&pulses, &frame),
                "a {:+.1}% rate error broke the frame",
                pct as f64 / 10.0
            );
        }
    }

    #[test]
    fn decodes_when_the_short_side_of_the_duty_cycle_is_extreme() {
        // Pin the margin that the 79 us threshold lost: a low of 55% of a chip
        // (73 us) is still a real symbol and must survive filtering. Highs take
        // the remainder so a pair still sums to two chips.
        let frame = REAL_FRAME;
        let data = data_bits_of(&frame);
        let mut chips = BitBuf::new();
        encode(data.as_slice(), &mut chips);

        let short = CHIP_US * 55 / 100;
        let long = 2 * CHIP_US - short;
        let mut pulses = std::vec::Vec::new();
        let all: std::vec::Vec<bool> = chips.as_slice().to_vec();
        let mut i = 0;
        while i < all.len() {
            let level = all[i];
            let mut run = 0u32;
            while i < all.len() && all[i] == level {
                run += 1;
                i += 1;
            }
            let per = if level { long } else { short };
            pulses.push((level, (run - 1) * CHIP_US + per));
        }
        assert!(
            recovers(&pulses, &frame),
            "a 55%-of-a-chip low must not be filtered as a glitch"
        );
    }
}
