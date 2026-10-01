//! The declaration gate, measured rather than asserted.
//!
//! Background: with the sync-less fallback ungated, unrelated 345 MHz traffic —
//! a neighbour's sensor, which is ordinary on a shared band — fabricated frames
//! carrying *fresh random TXIDs*. With Home Assistant auto-discovery on, each
//! became a new device whose retained config outlived the firmware that
//! published it, and the device list filled with strangers.
//!
//! The cause was trial count, not a weak CRC. A 64-bit legacy frame's 16-bit CRC
//! is a 1-in-65536 filter for **one** check; `decode_chip_capture` slides over
//! ~1000 (16 phases x 2 polarities x ~34 bit offsets), which makes it about
//! 1-in-60.
//!
//! This test pins the gate by measuring it, because the failure mode is
//! statistical: a version that "mostly works" is exactly what shipped.

use revivint_core::{ChipCapture, Policy, bits, cipher, manchester, scan_chip_capture};

/// Valid-Manchester chips carrying data that is not one of our frames — what an
/// unrelated transmitter looks like to us. Random *bytes* mostly fail Manchester
/// outright and so under-test this badly; these decode cleanly to wrong bits.
fn unrelated_burst(rng: &mut impl FnMut() -> u64) -> [u8; 22] {
    let databits: Vec<bool> = (0..88).map(|_| rng() & 1 == 1).collect();
    let mut chips = bits::BitBuf::new();
    manchester::encode(&databits, &mut chips);
    let mut bytes = [0u8; 24];
    let n = bits::pack_msb_first(chips.as_slice(), &mut bytes);
    let mut out = [0u8; 22];
    let take = n.min(22);
    out[..take].copy_from_slice(&bytes[..take]);
    out
}

fn phantom_count(keys: &str, trials: usize) -> (usize, usize) {
    let policy = Policy::from_map(&cipher::parse_keys_for_test(keys));
    let accepts = |f: &revivint_core::DecodedFrame| policy.accepts_bare(f);
    let mut s: u64 = 0xdead_beef_cafe_1234;
    let mut rng = || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    let mut ids = std::collections::BTreeSet::new();
    let mut hits = 0;
    for _ in 0..trials {
        let cap = unrelated_burst(&mut rng);
        let Some(cc) = ChipCapture::new(&cap) else { continue };
        if let Some((f, _)) = scan_chip_capture(cc, 0x5556, &accepts) {
            ids.insert(f.txid);
            hits += 1;
        }
    }
    (hits, ids.len())
}

#[test]
fn declared_only_invents_no_devices() {
    let (hits, distinct) = phantom_count("405817=0c5e,405718", 20_000);
    assert_eq!(
        hits, 0,
        "unrelated traffic fabricated {hits} frames across {distinct} phantom TXIDs; \
         the sync-less fallback's declaration gate is not holding"
    );
}

#[test]
fn plus_legacy_is_documented_as_the_permissive_setting() {
    // `+legacy` deliberately re-opens this: the operator asked to hear legacy
    // senders they did not list. It is not free, and this test records the
    // price rather than pretending otherwise — which is why the firmware pairs
    // it with corroboration-by-repetition (`revivint_esp::hw::LegacyGate`)
    // instead of using this verdict directly.
    let (hits, distinct) = phantom_count("405817=0c5e,+legacy", 20_000);
    assert!(hits > 0, "premise: +legacy admits undeclared legacy frames");
    // Every phantom is a one-off. That is the property corroboration relies on:
    // a real sensor repeats each event ~6x, a fabricated one never comes back.
    assert_eq!(
        hits, distinct,
        "phantoms repeated a TXID ({hits} frames, {distinct} distinct) — \
         corroboration-by-repetition would admit them"
    );
}
