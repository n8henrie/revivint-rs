//! Drives the actual binary the way a user runs it. Uses the public inverted
//! frames from github `merbanan/rtl_433` issue #1504 (not a real user's device).
//! No seed value is hardcoded — the decode test cracks the seed first, then uses
//! whatever crack recovered.

use std::io::Write;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_revivint");

// Public rtl_433 #1504 captures (bit-inverted `0001…` polarity).
const FRAMES: &[&str] = &[
    "{96}000185ffe413fec8412524a2",
    "{96}000185ffe303fec84125ed61",
    "{96}000185ffe2f3fec841255aa3",
    "{96}000185ffe1affec84125aff5",
    "{96}000185ffe0c7fec841259852",
    "{96}000185ffe043fec841259779",
    "{96}000185ffdf2bfec84125fd4e",
    "{96}000185ffdee3fec841253b35",
    "{96}000185ffde67fec84125341e",
    "{96}000185ffdddffec84125ae77",
    "{96}000185ffdd5ffec84125a544",
    "{96}000185ffdc9ffec84125a98f",
    "{96}000185ffdc1ffec84125a2bc",
    "{96}000185ffdb93fec841251d22",
];

fn run_stdin(args: &[&str], input: &str) -> (bool, String) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn recovered_seed() -> String {
    let (ok, stdout) = run_stdin(&["crack"], &FRAMES.join("\n"));
    assert!(ok, "crack should succeed on the #1504 frames");
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("recovered seed: "))
        .and_then(|rest| rest.split_whitespace().next()) // token, before the keys mapping
        .expect("crack printed a recovered seed")
        .to_string()
}

#[test]
fn crack_recovers_a_unique_seed_from_stdin() {
    let (ok, stdout) = run_stdin(&["crack"], &FRAMES.join("\n"));
    assert!(ok);
    assert!(stdout.contains("recovered seed: 0x"), "stdout: {stdout}");
    // The same line offers a ready-to-paste VIVINT_KEYS mapping (no rtl_433 syntax).
    assert!(stdout.contains("keys: "), "stdout: {stdout}");
    assert!(!stdout.contains("-R 342:"), "no rtl_433 -R syntax: {stdout}");
    // `txid=seed`, mirroring rtl_433 — and what VIVINT_KEYS documents.
    let keys = stdout.split("keys: ").nth(1).expect("a keys: line").trim();
    let entry = keys.lines().next().unwrap();
    assert!(entry.contains('='), "mapping is txid=seed: {entry}");
}

#[test]
fn crack_reads_positional_capture_files() {
    let path = std::env::temp_dir().join("vivint_keystream_cli.txt");
    std::fs::write(&path, FRAMES.join("\n")).unwrap();
    let out = Command::new(BIN)
        .args(["crack", path.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("recovered seed: 0x"));
}

#[test]
fn decode_uses_the_recovered_seed() {
    let seed = recovered_seed(); // never hardcoded — comes from crack at test time
    let (ok, stdout) = run_stdin(&["decode", &seed], &FRAMES.join("\n"));
    assert!(ok, "decode should emit events");
    // Full Honeywell-style status bitfield, both loops surfaced.
    assert!(stdout.contains("loop1="), "decode output: {stdout}");
    assert!(stdout.contains("loop2="), "decode output: {stdout}");
    assert!(stdout.contains("txid="), "decode output: {stdout}");
}

#[test]
fn help_and_bad_usage() {
    assert!(
        Command::new(BIN)
            .arg("--help")
            .output()
            .unwrap()
            .status
            .success()
    );
    // a bad subcommand is a clap usage error (nonzero exit)
    assert!(
        !Command::new(BIN)
            .arg("frobnicate")
            .output()
            .unwrap()
            .status
            .success()
    );
}
