//! `Recovery` must report what actually happened, not a constant.
//!
//! The counter this replaces (`HW_SYNC_EXACT`) was incremented unconditionally
//! and then reported as "N direct, M rescued" with `M = frames - N`, so every
//! log ever produced said "all direct, none rescued". A statistic that cannot
//! distinguish its two cases is worse than none, so each field here is exercised
//! against an input constructed to need exactly that correction.

use revivint_core::{ChipCapture, DecodedFrame, bits, cc1101, manchester, scan_chip_capture};

const KNOWN: fn(&DecodedFrame) -> bool = |f| f.txid == 0x63139;
const FRAME: &[u8] = &[0xff, 0xfe, 0x7a, 0x00, 0x19, 0xd8, 0x03, 0x86, 0x31, 0x39, 0xa8, 0xf8];

/// The body's Manchester chips **as this radio's slicer delivers them**.
///
/// `SYNC_WORD_CHIPS` is the inverted spelling, so the whole capture — sync and
/// body alike — arrives inverted relative to `manchester::encode`'s logical
/// convention. Getting this wrong produces a capture no radio can emit, and then
/// every polarity assertion measures the fixture instead of the code.
fn body_chips() -> Vec<bool> {
    let databits: Vec<bool> = FRAME[2..]
        .iter()
        .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
        .collect();
    let mut chips = bits::BitBuf::new();
    manchester::encode(&databits, &mut chips);
    let slicer_inverts = cc1101::config::chips_need_inverting(cc1101::config::SYNC_WORD_CHIPS);
    chips
        .as_slice()
        .iter()
        .map(|c| if slicer_inverts { !c } else { *c })
        .collect()
}

fn pack(chips: &[bool]) -> Vec<u8> {
    let mut bytes = [0u8; 48];
    let n = bits::pack_msb_first(chips, &mut bytes);
    bytes[..n].to_vec()
}

fn recover(chips: &[bool]) -> Option<revivint_core::Recovery> {
    let bytes = pack(chips);
    let cc = ChipCapture::new(&bytes)?;
    scan_chip_capture(cc, cc1101::config::SYNC_WORD_CHIPS, &KNOWN).map(|(f, r)| {
        assert_eq!(f.txid, 0x63139, "wrong frame recovered");
        r
    })
}

/// A capture as the radio delivers it when it triggers exactly on the frame:
/// the chip-level sync word, then the body.
fn synced(lead_chips: usize) -> Vec<bool> {
    let sync = cc1101::config::SYNC_WORD_CHIPS;
    let mut all: Vec<bool> = (0..lead_chips).map(|i| i % 2 == 0).collect(); // preamble
    all.extend((0..16).map(|i| (sync >> (15 - i)) & 1 == 1));
    all.extend(body_chips());
    all
}

#[test]
fn a_perfect_capture_reports_clean() {
    let r = recover(&synced(0)).expect("decodes");
    assert!(r.is_clean(), "a perfectly triggered capture must read clean: {r:?}");
    assert_eq!(r.sync_at, 0);
    assert_eq!(r.chip_phase, 0);
    assert!(!r.inverted);
}

#[test]
fn an_early_trigger_is_reported_with_its_offset() {
    // A preamble bit error matched the sync pattern this many chips early.
    for lead in [24usize, 96] {
        let r = recover(&synced(lead)).expect("decodes");
        assert!(!r.is_clean(), "an early trigger is not clean");
        assert_eq!(r.sync_at, lead, "must report how early, not just that it was");
    }
}

#[test]
fn a_chip_stream_in_the_wrong_polarity_is_reported() {
    // Inverting the *body* only — the sync still matches, so the radio still
    // triggers, but this frame arrived in the opposite polarity from the one
    // that sync word implies. That is a slicer on its decision boundary, and the
    // only case `inverted` should ever count.
    let mut wrong = synced(0);
    for c in wrong[16..].iter_mut() {
        *c = !*c;
    }
    let r = recover(&wrong).expect("decodes in the other polarity");
    assert!(r.inverted, "an off-polarity frame must be reported: {r:?}");
    assert!(!r.is_clean());
}

#[test]
fn a_chip_shifted_capture_still_decodes() {
    // One extra chip before the body. `manchester::for_each_run` breaks on the
    // resulting invalid pair and resumes, so the body is recovered as its own
    // run and this can legitimately report *clean* — the shift was absorbed
    // before the frame decoder ever saw it.
    //
    // So the property worth pinning is robustness, not a particular label: a
    // one-chip slip must not cost the frame. Asserting it had to be "corrected"
    // would be asserting an implementation detail of run-splitting.
    let mut shifted = vec![true];
    shifted.extend(body_chips());
    while shifted.len() % 8 != 0 {
        shifted.push(true);
    }
    let r = recover(&shifted).expect("a one-chip slip must not cost the frame");
    // Whatever it reports, it must be self-consistent.
    assert_eq!(
        r.is_clean(),
        r.sync_at == 0 && r.chip_phase == 0 && !r.inverted && r.bit_offset == 0,
        "is_clean must agree with its own fields: {r:?}"
    );
}

#[test]
fn the_statistic_actually_varies() {
    // The point of the whole exercise: clean and corrected must be *different*
    // outcomes. The counter this replaced could not produce two values.
    let clean = recover(&synced(0)).unwrap();
    let corrected = recover(&synced(96)).unwrap();
    assert_ne!(clean, corrected);
    assert!(clean.is_clean() && !corrected.is_clean());
}

#[test]
fn a_healthy_link_reads_100_percent_clean() {
    // The regression this file exists for. On real hardware this reported
    // `0/228 clean (0%)` with `228 polarity` and a warning telling the user to
    // invert a sync word that was already correct — because `inverted` was
    // reporting the radio's *normal* polarity rather than deviation from it.
    //
    // A run of perfectly-triggered captures must now read 100% clean.
    let (mut clean, total) = (0usize, 50usize);
    for _ in 0..total {
        let r = recover(&synced(0)).expect("decodes");
        if r.is_clean() {
            clean += 1;
        }
    }
    assert_eq!(clean, total, "a healthy link must read 100% clean, got {clean}/{total}");
}
