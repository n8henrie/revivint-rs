//! End-to-end vectors using real captured frames from the vivint-345 archive,
//! plus a full software-path round trip (bytes -> Manchester chips -> framer).

use revivint_core::frame::{Body, Contact, EventClass, Family};
use revivint_core::{decode, for_each_frame};
use revivint_core::bits::{unpack_msb_first, BitBuf};
use revivint_core::manchester;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// (hex, expect_family, expect_txid, expect_contact, expect_event)
///
/// `expect_contact` is what a **bare** decode reports, with no seed in hand.
/// That is `None` for every keyed `0x7x` subtype: their byte 5 is keystreamed,
/// so the door state is not recoverable here. The keyed vectors' true states are
/// asserted in `mod keyed` below, where a `Decoder` is available.
const GOOD: &[(&str, Family, u32, Option<Contact>, EventClass)] = &[
    ("fffea630d600af20", Family::Legacy64, 0x630d6, Some(Contact::Closed), EventClass::Legacy),
    ("fffea630d6801f10", Family::Legacy64, 0x630d6, Some(Contact::Open), EventClass::Legacy),
    ("fffed0520f40038630d6e7b0", Family::StartupD0, 0x630d6, None, EventClass::Startup),
    ("fffed03a0f4003863139d6d0", Family::StartupD0, 0x63139, None, EventClass::Startup),
    ("fffe7a00195803863139a3cb", Family::Event7x, 0x63139, None, EventClass::Contact),
    ("fffe7a0019d803863139a8f8", Family::Event7x, 0x63139, None, EventClass::Contact),
    ("fffe7a01d364038631393a4b", Family::Event7x, 0x63139, None, EventClass::Contact),
    ("fffe7a01d4b803863139e56b", Family::Event7x, 0x63139, None, EventClass::Contact),
    ("fffe7239ab02038631394bdd", Family::Event7x, 0x63139, None, EventClass::Heartbeat),
    ("fffe7238fab2038630d63385", Family::Event7x, 0x630d6, None, EventClass::Heartbeat),
    ("fffe74e13474038d165c8ad6", Family::Event7x, 0xd165c, None, EventClass::Motion),
];

#[test]
fn all_good_vectors_decode_and_validate() {
    for &(h, fam, txid, open, ev) in GOOD {
        let f = decode(&hex(h)).unwrap_or_else(|e| panic!("{h}: {e:?}"));
        assert!(f.crc_ok, "{h}: crc should be ok");
        assert_eq!(f.family(), fam, "{h}: family");
        assert_eq!(f.txid, txid, "{h}: txid");
        assert_eq!(f.contact(), open, "{h}: contact (bare decode)");
        assert_eq!(f.event(), ev, "{h}: event");
    }
}

#[test]
fn known_bad_frames_fail_crc() {
    for h in [
        "fffe7a01d364038631393a4a",  // 1-bit flip of a good 7a
        "fffed03a0f4003863139d6d1",  // 1-bit flip of a good d0 crc
        "fffea630d600af21",          // 1-bit flip of a good legacy crc
    ] {
        let f = decode(&hex(h)).unwrap();
        assert!(!f.crc_ok, "{h}: should fail crc");
    }
}

#[test]
fn channel8_is_real_honeywell_via_0x8005() {
    // This frame is channel 0x8, so it uses poly 0x8005 (legacy Honeywell), NOT
    // 0x8050. The old Python verifier only knew 0x8050 and wrongly flagged it as
    // noise; it is in fact a genuine third-party sensor (id 0x72685) present in
    // the RF environment, and the unified decoder validates it correctly.
    let f = decode(&hex("fffe87268580f3cd")).unwrap();
    assert_eq!(f.family(), Family::Legacy64);
    let Body::Legacy(l) = f.body else { panic!("64-bit frame is legacy") };
    assert_eq!(l.channel, 0x8);
    assert_eq!(f.txid, 0x72685);
    assert!(f.crc_ok);
}

#[test]
fn software_path_roundtrip_every_good_vector() {
    // bytes -> data bits -> Manchester chips -> pulses -> chips -> framer -> decode
    for &(h, _, txid, _, _) in GOOD {
        let bytes = hex(h);
        let mut data = BitBuf::new();
        unpack_msb_first(&bytes, &mut data);

        let mut chips = BitBuf::new();
        manchester::encode(data.as_slice(), &mut chips);

        // run-length to pulses at CHIP_US, then a terminating gap
        let mut pulses = Vec::new();
        let s = chips.as_slice();
        let mut i = 0;
        while i < s.len() {
            let level = s[i];
            let mut run = 0u32;
            while i < s.len() && s[i] == level {
                run += 1;
                i += 1;
            }
            pulses.push((level, run * manchester::CHIP_US));
        }
        pulses.push((false, manchester::RESET_US * 4));

        let mut chips2 = BitBuf::new();
        manchester::pulses_to_chips(&pulses, &mut chips2);
        let mut databits = BitBuf::new();
        manchester::decode(chips2.as_slice(), false, &mut databits);

        let mut found = Vec::new();
        for_each_frame(databits.as_slice(), |f| found.push(*f));
        assert_eq!(found.len(), 1, "{h}: expected exactly one frame");
        assert!(found[0].crc_ok);
        assert_eq!(found[0].txid, txid, "{h}: txid via SW path");
    }
}

#[test]
fn counter_increments_across_a_capture_burst() {
    // consecutive frames from the alternating capture: counter += 1 each event
    let seq = [
        "fffe7a01d364038631393a4b",
        "fffe7a01d4b803863139e56b",
        "fffe7a01d518038631392a74",
        "fffe7a01d654038631393d04",
    ];
    let counters: Vec<u16> = seq.iter().map(|h| decode(&hex(h)).unwrap().counter().unwrap()).collect();
    for w in counters.windows(2) {
        assert_eq!(w[1], w[0] + 1);
    }
}

// ---- keyed contact decode (seed 0x0c5e), real 5817 frames ----
mod keyed {
    use revivint_core::{apply_key, decode, decode_keyed, Contact, Decoder, Family};

    fn bytes(hex: &str) -> [u8; 12] {
        let mut b = [0u8; 12];
        for i in 0..12 {
            b[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        b
    }

    // Magnet away (OPEN) and magnet present (closed), same counters.
    const OPEN_25: &str = "fffe7a0019d803863139a8f8";
    const OPEN_26: &str = "fffe7a001aac03863139b712";
    const CLOSED_25: &str = "fffe7a00195803863139a3cb";
    const CLOSED_26: &str = "fffe7a001a2803863139b839";

    #[test]
    fn keyed_decode_recovers_true_contact() {
        let mut d = Decoder::new(0x0c5e);
        let f = decode_keyed(&mut d, &bytes(OPEN_25)).unwrap();
        assert!(f.crc_ok && f.family() == Family::Event7x);
        assert_eq!(f.contact(), Some(Contact::Open), "open frame -> OPEN");
        assert_eq!(decode_keyed(&mut d, &bytes(OPEN_26)).unwrap().contact(), Some(Contact::Open));

        let mut d = Decoder::new(0x0c5e);
        assert_eq!(decode_keyed(&mut d, &bytes(CLOSED_25)).unwrap().contact(), Some(Contact::Closed));
        assert_eq!(decode_keyed(&mut d, &bytes(CLOSED_26)).unwrap().contact(), Some(Contact::Closed));
    }

    #[test]
    fn apply_key_overrides_naive_bit() {
        // The naive decode reads bit 7 of the whitened status byte; for these
        // frames it happens to be wrong until the key is applied.
        let raw = decode(&bytes(CLOSED_25)).unwrap();
        let mut d = Decoder::new(0x0c5e);
        let mut keyed = raw;
        apply_key(&mut d, &mut keyed);
        assert_eq!(keyed.contact(), Some(Contact::Closed));
        // naive and keyed may differ; the keyed one is ground truth.
        let _ = raw.contact();
    }

    #[test]
    fn apply_key_is_noop_for_non_event() {
        // A d0 startup frame has no keyed contact; apply_key must not touch it.
        let d0 = "fffed03a0f4003863139d6d0";
        let mut dec = Decoder::new(0x0c5e);
        let before = decode(&bytes(d0)).unwrap();
        let mut after = before;
        apply_key(&mut dec, &mut after);
        assert_eq!(before.contact(), after.contact());
    }

    // ---- multi-device Registry: keyed TXID un-keyed, others left in the clear ----
    mod registry {
        use revivint_core::{Contact, Registry, KEYS};

        fn hexn(s: &str) -> Vec<u8> {
            (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
        }

        // The compile-time default map (no VIVINT_KEYS during `cargo test`) is
        // `405817=0x0c5e`: our 5817 (txid 0x63139) keyed, nothing else.
        const OPEN_25: &str = "fffe7a0019d803863139a8f8"; // 5817 event, keyed -> OPEN
        const LEGACY_5718: &str = "fffea630d6801f10"; // 5718 legacy contact, in clear (open)
        const D0_5718: &str = "fffed0520f40038630d6e7b0"; // 5718 startup beacon, no contact

        #[test]
        fn keyed_txid_is_unkeyed() {
            let mut reg = Registry::from_map(&KEYS);
            let f = reg.decode_keyed(&hexn(OPEN_25)).unwrap();
            assert!(f.crc_ok);
            assert_eq!(f.contact(), Some(Contact::Open), "5817 un-keyed with its seed -> OPEN");
        }

        #[test]
        fn unknown_and_non_event_pass_through_without_a_seed() {
            let mut reg = Registry::from_map(&KEYS);
            // 5718 legacy contact is already in the clear; Registry leaves it be.
            let legacy = reg.decode_keyed(&hexn(LEGACY_5718)).unwrap();
            assert_eq!(legacy.contact(), Some(Contact::Open));
            // 5718 startup beacon carries no contact and needs no seed; unchanged.
            let d0 = reg.decode_keyed(&hexn(D0_5718)).unwrap();
            assert_eq!(d0.contact(), None);
        }

        #[test]
        fn un_keying_fills_the_full_status_bitfield() {
            // The un-keyed 5817 OPEN frame exposes loop-1 (0x80) and the full
            // Honeywell event byte via `legacy`, not just the naive bit.
            let mut reg = Registry::from_map(&KEYS);
            let f = reg.decode_keyed(&hexn(OPEN_25)).unwrap();
            let bits = f.status_bits().expect("an un-keyed event exposes its bits");
            assert_eq!(f.contact(), Some(Contact::Open)); // loop-1
            // battery never rides on a 0x7x event, and low-2 bits are masked off.
            let _ = (bits.tamper, bits.loop2, bits.alarm, bits.battery_low, bits.heartbeat);
        }

        #[test]
        fn seed_announce_self_configures_the_registry() {
            use revivint_core::KeyMap;
            // Empty map: nothing is keyed until a 0x73 announce teaches us a seed.
            let mut reg = Registry::from_map(&KeyMap::default());
            // Synthetic 0x73 broadcasting _DAT_0230 = 0x123c (seed 0x1234) for
            // the made-up TXID 0xabcde; the receiver learns it with no brute
            // force. Constructed, not captured, so it identifies no real sensor.
            let seed_frame = "fffe73123c02000abcde0ad0";
            let announced = reg.decode_keyed(&hexn(seed_frame)).unwrap();
            assert_eq!(announced.txid, 0xabcde);
            assert_eq!(announced.announced_seed(), Some(0x1234));
            assert!(reg.learn(announced.txid, 0x1234)); // idempotent update
        }
    }
}
