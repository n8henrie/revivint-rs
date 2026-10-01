//! Format-agnostic extraction of Vivint 0x7x event frames from `rtl_433` output.
//!
//! `rtl_433` JSON (`-F json:-`), CSV (`data` column), the `codes` array
//! (`{96}fffe...`), and plain hex-per-line captures all embed the frame as a hex
//! run. Two on-air layouts are accepted:
//!
//!   * **synced 12-byte** — `fffe` + the 10-byte event core (the older `-X …`
//!     output). Depending on the receiver's OOK polarity the whole frame may be
//!     bit-inverted, so the sync arrives as `0001` (`fffe ^ ffff`); both accepted.
//!   * **bare 10-byte core** — `7a00…` with the sync stripped (`rtl_433`'s newer
//!     output for this device). Also accepted in either polarity.
//!
//! Only CRC-valid 0x7x event frames are yielded; the 12-bit packed check is what
//! distinguishes a real frame from arbitrary hex.

/// A CRC-valid 0x7x event frame, with the fields cracking and decoding need.
pub(crate) struct Frame {
    pub(crate) subtype: u8, // core[0]: 0x7a contact, 0x72 heartbeat, ...
    pub(crate) counter: u16,
    pub(crate) status: u8, // core[3], keystreamed (XOR c1)
    byte10: u8,            // core[8] high nibble carries (c3 ^ 0x10)
    id: [u8; 4],           // core[4..8]
}

impl Frame {
    /// The on-air observation used for cracking: (counter, byte10 high nibble).
    pub(crate) fn observation(&self) -> (u16, u8) {
        (self.counter, self.byte10 & 0xf0)
    }

    /// Identity of the event this frame reports, for collapsing repeats.
    ///
    /// Deliberately [`revivint_core::EventKey`] rather than a local tuple. The
    /// MQTT bridge had this exact bug — it collapsed on `(txid, type, counter)`,
    /// and since the counter advances once per open-*and*-close cycle, one
    /// value is transmitted in both contact states and every second state change
    /// was silently dropped. `decode` here had the same `(subtype, counter)` key
    /// and the same defect: a capture of ten toggles printed five.
    ///
    /// Sharing the type means the rule is stated once. The status byte is what
    /// separates the pair: it differs between the two states of a counter and is
    /// identical across that event's repeats.
    pub(crate) fn event_key(&self) -> revivint_core::EventKey {
        revivint_core::EventKey {
            txid: u32::from_be_bytes(self.id) & 0x000f_ffff,
            type_byte: self.subtype,
            counter: self.counter,
            status: self.status,
        }
    }

    /// True for the **keystreamed event** subtypes, whose status byte is `XORed`
    /// with the keystream and whose byte-10 nibble is the crackable MAC. Other
    /// 0x7x frames are not keyed and must not feed the crack.
    ///
    /// The list itself lives in `revivint_core`, so the cracker and the decoders
    /// cannot come to disagree about which subtypes are encrypted.
    pub(crate) fn is_keyed_event(&self) -> bool {
        revivint_core::is_keyed_subtype(self.subtype)
    }

    /// If this is a 0x73 seed-announce frame, the seed the sensor broadcast in
    /// the clear. The `_DAT_0230` -> flash-seed conversion is core's, so the CLI
    /// and the firmware cannot disagree about the seed convention by one XOR.
    pub(crate) fn announced_seed(&self) -> Option<u16> {
        (self.subtype == 0x73)
            .then(|| revivint_core::announced_seed_from_field(self.counter))
    }

    /// The printed device label, e.g. "XXXX-XXX-XXXX", from the id bytes.
    pub(crate) fn txid(&self) -> String {
        let p1 = (u32::from(self.id[0]) << 4) | (u32::from(self.id[1]) >> 4);
        let p2 = (u32::from(self.id[1] & 0x0f) << 16)
            | (u32::from(self.id[2]) << 8)
            | u32::from(self.id[3]);
        format!("{:04}-{:03}-{:04}", p1, p2 / 10000, p2 % 10000)
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// First `N` bytes decoded from the front of `hex`, or None if too short/invalid.
fn hex_bytes<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let b = hex.as_bytes();
    if b.len() < 2 * N {
        return None;
    }
    let mut raw = [0u8; N];
    for i in 0..N {
        raw[i] = (hex_val(b[2 * i])? << 4) | hex_val(b[2 * i + 1])?;
    }
    Some(raw)
}

/// Parse the 10-byte 0x7x event core (subtype, counter, status, id, packed
/// check) if `b[0]` is a 0x7x type and the 12-bit check validates.
fn parse_core(b: &[u8; 10]) -> Option<Frame> {
    if b[0] & 0xf0 != 0x70 {
        return None;
    }
    // 0x7x 12-bit packed check: CRC over bytes 0..8 + (byte8 & 0xf0), top 12 bits.
    let mut crc_input = [0u8; 9];
    crc_input[..8].copy_from_slice(&b[0..8]);
    crc_input[8] = b[8] & 0xf0;
    let calc12 = revivint_core::crc::crc16_8050(&crc_input) >> 4;
    let stored12 = (u16::from(b[8] & 0x0f) << 8) | u16::from(b[9]);
    if calc12 != stored12 {
        return None; // only surface CRC-valid frames
    }
    Some(Frame {
        subtype: b[0],
        counter: (u16::from(b[1]) << 8) | u16::from(b[2]),
        status: b[3],
        byte10: b[8],
        id: [b[4], b[5], b[6], b[7]],
    })
}

/// The first CRC-valid 0x7x frame anchored in one maximal hex run. Tries the
/// synced 12-byte layout (locate `fffe`/`0001`, either polarity) first; if that
/// finds nothing, slides the bare 10-byte core layout across the run (either
/// polarity). Bare frames whose bytes happen to contain an `fffe`/`0001`
/// substring still parse, because the failed synced attempt falls through here.
fn frame_in_run(run: &str) -> Option<Frame> {
    // Synced 12-byte: fffe (direct) or 0001 (inverted) + the 10-byte core.
    let hit = run
        .find("fffe")
        .or_else(|| run.find("FFFE"))
        .map(|p| (p, false))
        .or_else(|| run.find("0001").map(|p| (p, true)));
    if let Some((pos, inverted)) = hit
        && let Some(mut raw) = hex_bytes::<12>(&run[pos..])
    {
        if inverted {
            for byte in &mut raw {
                *byte ^= 0xff;
            }
        }
        if raw[0] == 0xff && raw[1] == 0xfe {
            let core: [u8; 10] = raw[2..12].try_into().unwrap();
            if let Some(f) = parse_core(&core) {
                return Some(f);
            }
        }
    }

    // Bare 10-byte core: no sync to anchor on, so slide and let the CRC decide.
    let len = run.len();
    let mut start = 0;
    while start + 20 <= len {
        if let Some(core) = hex_bytes::<10>(&run[start..]) {
            if let Some(f) = parse_core(&core) {
                return Some(f);
            }
            let inv: [u8; 10] = std::array::from_fn(|i| core[i] ^ 0xff);
            if let Some(f) = parse_core(&inv) {
                return Some(f);
            }
        }
        start += 1;
    }
    None
}

/// Every CRC-valid 0x7x event frame in a line (one per hex run), in order.
pub(crate) fn frames_in_line(line: &str) -> Vec<Frame> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if hex_val(b[i]).is_none() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && hex_val(b[i]).is_some() {
            i += 1;
        }
        if let Some(f) = frame_in_run(&line[start..i]) {
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public rtl_433 #1504 frame, both polarities (fffe… direct, 0001… inverted).
    const DIRECT: &str = "fffe7a001bec0137bedadb5d"; // counter 27, byte10 0xdb
    const INVERTED: &str = "000185ffe413fec8412524a2"; // == DIRECT ^ 0xff
    // Newer sync-stripped 10-byte core (same device family, counter 29).
    const BARE: &str = "7a001d5403863139a665";

    #[test]
    fn parses_valid_and_rejects_bad() {
        let f = &frames_in_line(DIRECT)[0];
        assert_eq!(f.counter, 27);
        assert_eq!(f.byte10, 0xdb);
        assert_eq!(f.subtype, 0x7a);
        // flipped last byte -> CRC fails; d0 startup -> not a 0x7x
        assert!(frames_in_line("fffe7a001bec0137bedadb5e").is_empty());
        assert!(frames_in_line("fffed0000000000000000000").is_empty());
    }

    #[test]
    fn extracts_from_json_csv_plain() {
        assert_eq!(
            frames_in_line(&format!(r#"{{"rows":[{{"data":"{DIRECT}"}}]}}"#))[0].counter,
            27
        );
        assert_eq!(
            frames_in_line(&format!("2,1768243657.59,96,{DIRECT},0.08,false,6"))[0].counter,
            27
        );
        assert!(frames_in_line("rtl_433 startup, no frame here").is_empty());
    }

    #[test]
    fn accepts_bit_inverted_frames() {
        // Opposite OOK polarity: `0001…` = `fffe…` ^ 0xff (github rtl_433 #1504).
        let f = &frames_in_line(&format!("{{96}}{INVERTED}"))[0];
        assert_eq!(f.subtype, 0x7a);
        assert_eq!(f.counter, 27);
    }

    #[test]
    fn recognizes_seed_announce_and_keyed_events() {
        // Synthetic 0x73 seed-announce: made-up TXID 0xabcde broadcasting
        // _DAT_0230 = 0x123c, i.e. seed 0x1234. Constructed, not captured, so
        // it identifies no real sensor.
        let f = &frames_in_line("fffe73123c02000abcde0ad0")[0];
        assert_eq!(f.subtype, 0x73);
        assert!(!f.is_keyed_event());
        assert_eq!(f.announced_seed(), Some(0x1234)); // 0x123c ^ 8 (our seed convention)
        // A 0x7a event is a keyed event and announces no seed.
        let e = &frames_in_line(DIRECT)[0];
        assert!(e.is_keyed_event());
        assert_eq!(e.announced_seed(), None);
    }

    #[test]
    fn accepts_bare_sync_stripped_core() {
        // Newer rtl_433 output: the 10-byte 0x7x core with no fffe sync.
        let f = &frames_in_line(BARE)[0];
        assert_eq!(f.subtype, 0x7a);
        assert_eq!(f.counter, 29);
        assert_eq!(f.byte10, 0xa6);
        assert_eq!(f.status, 0x54);
        // Works with a length prefix and inside a CSV data column too.
        assert_eq!(frames_in_line(&format!("{{80}}{BARE}"))[0].counter, 29);
        assert_eq!(
            frames_in_line(&format!("2,1768243657.59,80,{BARE},0.08,false,6"))[0].counter,
            29
        );
        // A one-char corruption breaks the CRC and yields nothing.
        assert!(frames_in_line("7a001d5403863139a666").is_empty());
    }
}

