//! Recover and use the secret seed of a Vivint/Honeywell 345 MHz door sensor,
//! working only from `rtl_433` captures. No firmware, no key at runtime.
//!
//!   revivint crack  [captures...]              # recover the 16-bit seed
//!   revivint decode <seed|map> [captures...]   # interpret packets with it/them
//!
//! Captures are `rtl_433` output (JSON / CSV / codes / plain hex), given as files
//! (concatenated) or on stdin when no files are named. Every frame carries its
//! transmitter id in the clear, so observations are grouped **per TXID** and each
//! device is cracked independently — a second nearby sensor can't poison the
//! brute force. `crack` recovers **every** device present: `cat *.json | revivint
//! crack` cracks all of them at once. When reading a live stdin stream, it re-attempts
//! the brute force as frames arrive, announces each device's seed the moment it is
//! pinned, and prints a combined `TXID=seed,TXID=seed,…` mapping covering all of them.
//!
//! `decode` matches: give it a single seed to un-key one device, or a comma-separated
//! `TXID=seed` mapping (exactly what `crack` prints — and the same mapping the
//! firmware bakes in via `VIVINT_KEYS`) to un-key a whole house at once: each frame
//! is decoded with its own transmitter's seed.

mod frame;

use revivint_core::cipher;

use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::BufRead;
use std::path::PathBuf;

/// Lowest-counter frames used for the brute force (24 * 4 bits = 96 >> 16).
const WINDOW: usize = 24;
/// Above this start counter the replay-from-entry brute force gets slow.
const SLOW_MIN_COUNTER: u16 = 64;
/// While streaming stdin, re-attempt the brute force after this many new lines.
/// Optimistic: a clean power-on burst reaches enough distinct low counters
/// within a batch or two.
const STREAM_BATCH: usize = 12;
/// Don't sweep a device below this many distinct counters — it can't yet be
/// unique, so a full 65536-seed sweep would only waste time.
const MIN_DISTINCT: usize = 8;

#[derive(Parser)]
#[command(
    name = "revivint",
    about = "Recover and use the secret seed of a Vivint 345 MHz door sensor from rtl_433 captures"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Brute-force the 16-bit seed from captured frames (files, or stdin).
    Crack {
        /// Capture files to concatenate; omit to read (and stream) stdin.
        captures: Vec<PathBuf>,
    },
    /// Interpret packets with known seed(s) (files, or stdin).
    Decode {
        /// One seed (hex `0x....` or decimal), or a `TXID=seed,TXID=seed`
        /// mapping for several devices — the same thing `crack` prints. Each
        /// frame is decoded with its own transmitter's seed.
        seed: String,
        /// Capture files to concatenate; omit to read stdin.
        captures: Vec<PathBuf>,
    },
}

fn main() {
    std::process::exit(match Cli::parse().cmd {
        Cmd::Crack { captures } => crack(&captures),
        Cmd::Decode { seed, captures } => match parse_seeds(&seed) {
            Ok(seeds) => decode(&seeds, &captures),
            Err(e) => {
                eprintln!("{e}");
                2
            }
        },
    });
}

fn parse_seed(s: &str) -> Option<u16> {
    let s = s.trim();
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => s.parse().ok()?,
    };
    u16::try_from(v).ok()
}

/// Parse a seed value from a mapping entry. These come from `crack`'s printed
/// mapping, where seeds are bare 4-digit hex (`05c9`) — so hex is the default
/// here; a `0x` prefix is also accepted.
fn parse_mapped_seed(s: &str) -> Option<u16> {
    let s = s.trim();
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u16::from_str_radix(hex, 16).ok()
}

/// Seeds to decode with: either one seed for every transmitter (back-compat), or
/// a per-TXID mapping keyed by the canonical id spelling (see [`canonical_txid`]).
#[derive(Debug, PartialEq)]
enum Seeds {
    One(u16),
    Map(HashMap<String, u16>),
}

impl Seeds {
    /// The seed to use for `id` (already in [`canonical_txid`] form), if known.
    fn get(&self, id: &str) -> Option<u16> {
        match self {
            Seeds::One(s) => Some(*s),
            Seeds::Map(m) => m.get(id).copied(),
        }
    }
}

/// Parse the `decode` seed argument: a lone seed (hex `0x....` or decimal) applied
/// to every device, or a comma-separated `TXID=seed` mapping. TXIDs are accepted
/// in either "PPPP-QQQ-RRRR" or the compact "PPPP-QQQRRRR" spelling.
///
/// `:` is accepted alongside `=` and costs nothing to keep; `crack` prints `=`,
/// mirroring `rtl_433`.
fn parse_seeds(arg: &str) -> Result<Seeds, String> {
    let body = arg.trim();
    if !body.contains(':') && !body.contains('=') {
        return parse_seed(body).map(Seeds::One).ok_or_else(|| {
            format!("invalid seed {body:?} (expected hex 0x.... or a decimal 0..65535)")
        });
    }
    let mut map = HashMap::new();
    for pair in body.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        // A bare entry declares a seedless device for the *firmware*; `decode`
        // has nothing to do for one, so skip it rather than rejecting a mapping
        // that `VIVINT_KEYS` would accept. It still has to *look* like a TXID —
        // otherwise a typo'd entry would be silently ignored rather than
        // reported, which is the worst of both behaviours.
        if !pair.contains(':') && !pair.contains('=') {
            let looks_like_txid = pair.starts_with("0x")
                || (pair.chars().any(|c| c.is_ascii_digit())
                    && pair.chars().all(|c| c.is_ascii_digit() || c == '-'));
            if looks_like_txid {
                continue;
            }
            return Err(format!(
                "bad mapping entry {pair:?} (expected TXID=seed, or a bare TXID)"
            ));
        }
        let (id, seed) = pair
            .split_once([':', '='])
            .ok_or_else(|| format!("bad mapping entry {pair:?} (expected TXID=seed)"))?;
        let seed = parse_mapped_seed(seed)
            .ok_or_else(|| format!("invalid seed {:?} for txid {}", seed.trim(), id.trim()))?;
        map.insert(canonical_txid(id.trim()), seed);
    }
    if map.is_empty() {
        return Err("empty seed mapping".to_string());
    }
    Ok(Seeds::Map(map))
}

/// Read every line of the named files (concatenated) into memory.
fn file_lines(captures: &[PathBuf]) -> Vec<String> {
    let mut all = Vec::new();
    for p in captures {
        match std::fs::read_to_string(p) {
            Ok(text) => all.extend(text.lines().map(str::to_string)),
            Err(e) => eprintln!("skipping {}: {e}", p.display()),
        }
    }
    all
}

/// Yield input lines from the named files (concatenated) or stdin if none given.
/// Used by `decode`, which processes the whole stream the same way either way.
fn input_lines(captures: &[PathBuf]) -> Box<dyn Iterator<Item = String>> {
    if captures.is_empty() {
        Box::new(std::io::stdin().lock().lines().map_while(Result::ok))
    } else {
        Box::new(file_lines(captures).into_iter())
    }
}

/// Accumulated on-air observations for a single transmitter (TXID).
#[derive(Default)]
struct Device {
    by_counter: BTreeMap<u16, u8>, // counter -> byte10 high nibble
    packets: usize,                // frames seen, including repeats
    dirty: bool,                   // gained a distinct counter since last sweep
}

impl Device {
    fn record(&mut self, counter: u16, byte10_hi: u8) {
        self.packets += 1;
        if self.by_counter.insert(counter, byte10_hi).is_none() {
            self.dirty = true; // a new distinct counter — worth re-cracking
        }
    }

    fn distinct(&self) -> usize {
        self.by_counter.len()
    }

    fn min_counter(&self) -> Option<u16> {
        self.by_counter.keys().next().copied()
    }

    /// Every seed consistent with this device's lowest-counter observations.
    fn seeds(&self) -> Vec<u16> {
        let used: Vec<(u16, u8)> = self
            .by_counter
            .iter()
            .take(WINDOW)
            .map(|(&c, &h)| (c, h))
            .collect();
        cipher::crack(&used)
    }
}

/// Fold every frame in `line` into `devices`, keyed by TXID. Only keystreamed
/// event frames (0x7a/0x74/0x79) carry the crackable byte-10 MAC — heartbeats,
/// seed-announce, and other 0x7x frames would poison the search, so we skip them.
fn ingest(line: &str, devices: &mut HashMap<String, Device>) {
    for f in frame::frames_in_line(line) {
        if !f.is_keyed_event() {
            continue;
        }
        let (counter, byte10_hi) = f.observation();
        devices
            .entry(f.txid())
            .or_default()
            .record(counter, byte10_hi);
    }
}

/// Canonical form of a "PPPP-QQQ-RRRR" TXID label for use as a map key: the
/// middle hyphen dropped ("PPPP-QQQRRRR"), so the label and compact spellings of
/// the same device resolve to one key.
fn canonical_txid(txid: &str) -> String {
    match txid.split_once('-') {
        Some((p1, rest)) => format!("{p1}-{}", rest.replace('-', "")),
        None => txid.to_string(),
    }
}

/// A `VIVINT_KEYS`-ready mapping entry for one device, e.g. `0056-040-5817=0c5e`.
/// Pastes straight into `revivint decode` and the firmware's `VIVINT_KEYS`.
///
/// `=` mirrors `rtl_433`'s own `txid=seed` spelling. Nested inside a quoted
/// environment assignment it is unambiguous to the shell, so
/// `VIVINT_KEYS='405817=0c5e'` exports fine.
fn keys_entry(txid: &str, seed: u16) -> String {
    format!("{txid}={seed:04x}")
}

/// One mapping covering *every* solved device at once, e.g.
/// `0019-050-7743=dda9,0056-040-5817=0c5e` — a single value keys a whole house.
fn keys_all(solved: &BTreeMap<String, u16>) -> String {
    solved
        .iter()
        .map(|(txid, seed)| keys_entry(txid, *seed))
        .collect::<Vec<_>>()
        .join(",")
}

/// Print the combined mapping for all solved devices. Only worth showing once two
/// or more devices are known — for a single device the per-device line already has
/// the same mapping.
fn print_combined(solved: &BTreeMap<String, u16>) {
    if solved.len() < 2 {
        return;
    }
    println!("all {} devices    keys: {}", solved.len(), keys_all(solved));
}

/// Print a recovered seed. The `recovered seed: 0x....` token is kept first and
/// whitespace-delimited so callers can grep it and feed it straight to `decode`;
/// the ready-to-paste `VIVINT_KEYS` mapping follows on the same line.
fn report_hit(txid: &str, seed: u16, dev: &Device) {
    println!("recovered seed: {seed:#06x}    keys: {}", keys_entry(txid, seed));
    println!(
        "  txid {txid} — {} packets analyzed, {} distinct counters, earliest counter {}",
        dev.packets,
        dev.distinct(),
        dev.min_counter().unwrap_or(0),
    );
}

/// Sweep every dirty, not-yet-solved device with at least `min_distinct` counters.
/// Each device that pins to a single seed is announced and recorded in `solved`;
/// the sweep does not stop at the first — a whole house of sensors resolves in one
/// pass. When `diag` is `Some(tag)`, ambiguous / no-match devices get a progress
/// note on stderr under that tag (kept quiet at EOF). Each ready device is cracked
/// exactly once. Returns true if any *new* device was solved this call.
fn sweep(
    devices: &mut HashMap<String, Device>,
    min_distinct: usize,
    solved: &mut BTreeMap<String, u16>,
    diag: Option<&str>,
) -> bool {
    let mut txids: Vec<String> = devices.keys().cloned().collect();
    txids.sort();
    let mut progress = false;
    for txid in txids {
        if solved.contains_key(&txid) {
            continue; // already pinned — leave it alone
        }
        let dev = devices.get_mut(&txid).unwrap();
        let distinct = dev.distinct();
        if !dev.dirty || distinct < min_distinct {
            continue;
        }
        dev.dirty = false; // don't re-sweep the same observations until a new counter arrives
        match dev.seeds().as_slice() {
            [seed] => {
                report_hit(&txid, *seed, dev);
                solved.insert(txid, *seed);
                progress = true;
            }
            [] => {
                if let Some(tag) = diag {
                    eprintln!(
                        "{tag} txid {txid}: {distinct} counters but no seed matches — corrupt frames or wrong device?"
                    );
                }
            }
            many => {
                if let Some(tag) = diag {
                    eprintln!(
                        "{tag} txid {txid}: {distinct} counters, {} candidate seeds — capture more low counters",
                        many.len()
                    );
                }
            }
        }
    }
    progress
}

fn crack(captures: &[PathBuf]) -> i32 {
    if captures.is_empty() {
        crack_stream()
    } else {
        crack_files(captures)
    }
}

/// Stream stdin: accumulate observations and re-attempt the brute force every
/// `STREAM_BATCH` lines. Each device is announced the moment it is pinned; a
/// combined `-R` mapping is (re)printed whenever a new device joins the set, and
/// once more at EOF. Runs until the stream ends — every device gets cracked.
fn crack_stream() -> i32 {
    let mut devices: HashMap<String, Device> = HashMap::new();
    let mut solved: BTreeMap<String, u16> = BTreeMap::new();
    let mut lines = 0usize;
    let mut since = 0usize;
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        ingest(&line, &mut devices);
        lines += 1;
        since += 1;
        if since < STREAM_BATCH {
            continue;
        }
        since = 0;
        if stream_checkpoint(lines, &mut devices, &mut solved) {
            print_combined(&solved); // a new device joined — refresh the combined arg
        }
    }
    // EOF: one last attempt, lowering the bar to include short-lived devices.
    for dev in devices.values_mut() {
        dev.dirty = true;
    }
    sweep(&mut devices, 2, &mut solved, None);
    if solved.is_empty() {
        report_no_seed(&devices);
        return 1;
    }
    print_combined(&solved); // authoritative final mapping for everything solved
    0
}

/// One streaming checkpoint: print collection status to stderr, then sweep every
/// ready device into `solved`. Returns true if a new device was solved this call.
fn stream_checkpoint(
    lines: usize,
    devices: &mut HashMap<String, Device>,
    solved: &mut BTreeMap<String, u16>,
) -> bool {
    let frames: usize = devices.values().map(|d| d.packets).sum();
    let tag = format!("[{lines} lines, {frames} frames, {} solved]", solved.len());
    if devices.is_empty() {
        eprintln!(
            "{tag} no frame hex parsed yet — is rtl_433 emitting the raw frame? \
             (its JSON needs a data/codes hex field)"
        );
        return false;
    }
    // Cheap per-device progress for anything still short of the crack threshold
    // (no brute force here). Devices at/above the threshold are handled by sweep(),
    // which cracks each exactly once and reports ambiguous/no-match cases via `diag`.
    let mut txids: Vec<String> = devices.keys().cloned().collect();
    txids.sort();
    for txid in &txids {
        if solved.contains_key(txid) {
            continue;
        }
        let dev = &devices[txid];
        let distinct = dev.distinct();
        if distinct < MIN_DISTINCT {
            eprintln!(
                "{tag} txid {txid}: {distinct}/{MIN_DISTINCT} distinct counters (min {:?}) — \
                 toggle the reed for more distinct low counters",
                dev.min_counter()
            );
        }
    }
    sweep(devices, MIN_DISTINCT, solved, Some(&tag))
}

/// Crack a finite set of files: group by TXID, then report every device.
fn crack_files(captures: &[PathBuf]) -> i32 {
    let mut devices: HashMap<String, Device> = HashMap::new();
    for line in file_lines(captures) {
        ingest(&line, &mut devices);
    }
    if devices.is_empty() {
        eprintln!("no CRC-valid 0x7x event frames found in input");
        return 1;
    }
    let mut txids: Vec<&String> = devices.keys().collect();
    txids.sort();
    let mut solved: BTreeMap<String, u16> = BTreeMap::new();
    for txid in txids {
        let dev = &devices[txid];
        if let Some(m) = dev.min_counter()
            && m > SLOW_MIN_COUNTER
        {
            eprintln!(
                "txid {txid}: lowest counter is {m}; the brute force replays from counter 24, so\n  \
                 this is slow. Power-cycle the sensor (battery pull) to restart counters near 24."
            );
        }
        match dev.seeds().as_slice() {
            [seed] => {
                report_hit(txid, *seed, dev);
                solved.insert(txid.clone(), *seed);
            }
            [] => println!(
                "txid {txid}: no seed matches ({} distinct counters) — wrong device or corrupt frames?",
                dev.distinct()
            ),
            many => {
                let list: Vec<String> = many.iter().map(|s| format!("{s:#06x}")).collect();
                println!(
                    "txid {txid}: {} candidate seeds — capture more low-counter frames: [{}]",
                    many.len(),
                    list.join(", ")
                );
            }
        }
    }
    print_combined(&solved); // one arg mapping every device that resolved
    i32::from(solved.is_empty())
}

/// No device resolved to a single seed; summarize what we have and how to help.
fn report_no_seed(devices: &HashMap<String, Device>) {
    if devices.is_empty() {
        eprintln!("no CRC-valid 0x7x event frames seen on stdin");
        return;
    }
    eprintln!("no unique seed recovered yet:");
    let mut txids: Vec<&String> = devices.keys().collect();
    txids.sort();
    for txid in txids {
        let dev = &devices[txid];
        eprintln!(
            "  txid {txid}: {} distinct counters (min {:?}), {} packets",
            dev.distinct(),
            dev.min_counter(),
            dev.packets,
        );
    }
    eprintln!(
        "Capture more frames at distinct low counters. Power-cycle the sensor \
         (battery pull) so its counter restarts near 24."
    );
}

/// Render the un-keyed status byte as the classic Honeywell event-byte fields.
///
/// The bit masks and the open/closed polarity live in
/// [`revivint_core::StatusBits`], not here. This used to be a second, hand-written
/// copy of them — the CLI said `loop1=open` while the firmware said
/// `loop1=Some(true)` for the same byte, and either could have drifted from the
/// sensor without the other noticing. Now both render one shared type.
fn format_status(plain: u8) -> String {
    let bits = revivint_core::StatusBits::from_byte(plain);
    format!("status={:02x} {bits}", plain & 0xfc)
}

fn decode(seeds: &Seeds, captures: &[PathBuf]) -> i32 {
    // One stateful decoder per transmitter, built lazily from that device's seed.
    let mut decoders: HashMap<String, cipher::Decoder> = HashMap::new();
    let mut last: HashMap<String, revivint_core::EventKey> = HashMap::new(); // per-txid repeat collapse
    let mut unknown: HashSet<String> = HashSet::new(); // warned-about TXIDs with no seed
    let mut n = 0usize;
    for line in input_lines(captures) {
        for f in frame::frames_in_line(&line) {
            let id = canonical_txid(&f.txid());
            // Whole-key comparison, not a field-by-field one: see
            // `Frame::event_key`. A key that omits the status byte merges the two
            // contact states of a single counter and halves the event count.
            let key = f.event_key();
            if last.get(&id) == Some(&key) {
                continue; // collapse consecutive repeats of the same frame per device
            }
            last.insert(id.clone(), key);

            if let Some(announced) = f.announced_seed() {
                println!(
                    "txid={} type={:02x} seed={announced:#06x} (announced in the clear)",
                    f.txid(),
                    f.subtype,
                );
                n += 1;
                continue;
            }
            if !f.is_keyed_event() {
                // heartbeat / other 0x7x: counter is real, status is not keyed.
                println!(
                    "txid={} counter={:05} type={:02x} (not a keyed event)",
                    f.txid(),
                    f.counter,
                    f.subtype,
                );
                continue;
            }
            // Keyed event: needs this transmitter's seed. Build its decoder once.
            if !decoders.contains_key(&id) {
                let Some(s) = seeds.get(&id) else {
                    if unknown.insert(id.clone()) {
                        eprintln!(
                            "txid {} ({id}): no seed provided — skipping its keyed events",
                            f.txid(),
                        );
                    }
                    continue;
                };
                decoders.insert(id.clone(), cipher::Decoder::new(s));
            }
            let dec = decoders.get_mut(&id).unwrap();
            match dec.plain_status(f.counter, f.status) {
                Some(plain) => {
                    println!(
                        "txid={} counter={:05} type={:02x} {}",
                        f.txid(),
                        f.counter,
                        f.subtype,
                        format_status(plain),
                    );
                    n += 1;
                }
                None => eprintln!(
                    "counter {} unreachable from event entry (sensor power-cycled mid-capture?)",
                    f.counter
                ),
            }
        }
    }
    eprintln!("decoded {n} event(s)");
    i32::from(n == 0)
}

#[cfg(test)]
mod tests {
    use super::{BTreeMap, HashMap, Seeds, canonical_txid, keys_all, keys_entry, parse_seeds};

    #[test]
    fn repeat_collapse_keeps_both_contact_states_of_one_counter() {
        // The counter advances once per open-AND-close cycle, so these two
        // frames are the same device's counter 25 in its two states. Collapsing
        // on `(subtype, counter)` — which this did — merged them and printed
        // half the events. The status byte is what separates them.
        let open = crate::frame::frames_in_line("fffe7a0019d803863139a8f8");
        let closed = crate::frame::frames_in_line("fffe7a00195803863139a3cb");
        let (o, c) = (open[0].event_key(), closed[0].event_key());

        assert_eq!(o.counter, c.counter, "premise: one counter, two states");
        assert!(o.same_device(c));
        assert_ne!(o, c, "the two states must not collapse into one event");

        // ...and a genuine repeat still does collapse.
        assert_eq!(o, crate::frame::frames_in_line("fffe7a0019d803863139a8f8")[0].event_key());
    }

    #[test]
    fn canonical_txid_drops_the_inner_hyphens_only() {
        // "PPPP-QQQ-RRRR" -> "PPPP-QQQRRRR": first hyphen stays, the rest go.
        assert_eq!(canonical_txid("0019-050-7743"), "0019-0507743");
        assert_eq!(canonical_txid("0056-040-5817"), "0056-0405817");
        // no hyphens / single segment: passed through untouched
        assert_eq!(canonical_txid("abcdef"), "abcdef");
    }

    #[test]
    fn single_device_mapping() {
        // The label spelling is printed as-is, so it reads like the device sticker
        // and pastes straight into VIVINT_KEYS.
        assert_eq!(keys_entry("0056-040-5817", 0x0c5e), "0056-040-5817=0c5e");
    }

    #[test]
    fn combined_mapping_joins_all_devices_with_commas() {
        let solved: BTreeMap<String, u16> = [
            ("0019-050-7610".to_string(), 0x05c9u16),
            ("0019-050-7743".to_string(), 0xdda9u16),
        ]
        .into_iter()
        .collect();
        // BTreeMap keeps TXID order deterministic for a stable, paste-able mapping.
        assert_eq!(
            keys_all(&solved),
            "0019-050-7610=05c9,0019-050-7743=dda9"
        );
    }

    #[test]
    fn parse_single_seed_hex_or_decimal() {
        assert_eq!(parse_seeds("0x05c9").unwrap(), Seeds::One(0x05c9));
        assert_eq!(parse_seeds(" 1481 ").unwrap(), Seeds::One(1481));
    }

    #[test]
    fn parse_mapping_normalizes_txids() {
        // Mixed spellings on input; both normalize to the compact "PPPP-QQQRRRR".
        let got = parse_seeds("0019-0507610=05c9,0019-050-7743=dda9").unwrap();
        let want: HashMap<String, u16> = [
            ("0019-0507610".to_string(), 0x05c9u16),
            ("0019-0507743".to_string(), 0xdda9u16),
        ]
        .into_iter()
        .collect();
        assert_eq!(got, Seeds::Map(want));
    }

    #[test]
    fn parse_accepts_a_pasted_crack_mapping() {
        // Exactly what `crack` prints (label form, comma-separated) pastes back in.
        let got = parse_seeds("0019-050-7610=05c9,0019-050-7743=dda9").unwrap();
        let want: HashMap<String, u16> = [
            ("0019-0507610".to_string(), 0x05c9u16),
            ("0019-0507743".to_string(), 0xdda9u16),
        ]
        .into_iter()
        .collect();
        assert_eq!(got, Seeds::Map(want));
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse_seeds("0019-0507610=zzzz").is_err()); // non-hex seed
        assert!(parse_seeds("0019-0507610").is_err()); // no '=' and not a number
        assert!(parse_seeds("0019-0507610=1,broken").is_err()); // second pair missing '='
    }
}
