# revivint

Recover and use the **16-bit secret seed** of a Vivint/Honeywell 345 MHz door sensor, working only from rtl_433 captures.
The seed is the sensor's only root entropy; recover it once and you can interpret the sensor's transmissions.

**No firmware.**
The cipher is a clean-room native reimplementation, validated byte-exact against an emulator oracle over 150+ seeds; nothing is embedded and no key is handled beyond the seed you pass in.

## Install

```sh
cargo install revivint
# or, without installing anything:
nix run github:n8henrie/revivint-rs -- --help
```

## Use

```sh
cargo build --release
bin=./target/release/revivint

# recover the seed(s) — from capture files (concatenated). Every device in the
# input is cracked; each hit prints a ready-to-paste `txid=seed` mapping:
$bin crack capture1.json capture2.json
#   recovered seed: 0x....    keys: XXXX-XXX-XXXX=....
#     txid XXXX-XXX-XXXX — 34 packets analyzed, 14 distinct counters, earliest counter 24
#   all 2 devices    keys: XXXX-XXX-XXXX=....,YYYY-YYY-YYYY=....

# ...or live off stdin: it re-cracks as frames arrive, announces each device's
# seed the moment it is pinned, and keeps going until the stream ends — just
# power-cycle the sensor and toggle the reed:
rtl_433 -f 345M -X 'n=v,m=OOK_MC_ZEROBIT,s=133,l=133,r=500,invert' -F json:- | $bin crack

# interpret packets with that seed — files or stdin:
$bin decode 0x.... capture.json
#   txid=XXXX-XXX-XXXX counter=00025 type=7a status=80 loop1=open loop2=closed
#   txid=XXXX-XXX-XXXX type=73 seed=0x.... (announced in the clear)

# decode a whole house at once: hand it the comma-separated TXID=seed mapping that
# crack prints (the same mapping the firmware bakes in via VIVINT_KEYS). Each frame
# is decoded with its own transmitter's seed:
$bin decode XXXX-XXX-XXXX=....,YYYY-YYY-YYYY=.... capture.json
rtl_433 ... -F json:- | $bin decode 0x....
```

`decode` un-keys the status byte into the full Honeywell event byte.
**Which loop is the door contact is model-specific:** the DW21R reports on `loop1` (0x80), the DW11 on `loop2` (0x20) — both are shown.
A `0x73` frame is the sensor broadcasting its own seed in the clear at power-up (so `crack` isn't even needed if you catch one).

Input is format-agnostic — each line is scanned for a frame and CRC-checked, so rtl_433 JSON/CSV/codes/plain hex all work, live or saved.
Two on-air layouts are recognized automatically, each in either OOK polarity:

* **synced 12-byte** — `fffe…` (or bit-inverted `0001…`) + the event core.
* **bare 10-byte core** — `7a00…` with the sync stripped (rtl_433's newer output for this device).

Every frame names its transmitter in the clear, so `crack` groups observations **per TXID** and brute-forces each device independently — a second sensor on the band can't dilute the search.
It recovers **every** device present, not just the first: `cat *.json | revivint crack` cracks a whole house at once, reporting each device's packet count, distinct-counter count, and earliest counter, and printing a single combined `ID1=s1,ID2=s2,…` mapping covering all of them.
From a live stdin stream it re-attempts the brute force every few lines, announces each device's seed the moment it is pinned, and runs until the stream ends.

`decode` emits one line per event (contact open/closed, decoded by un-keying the status byte with the seed) and collapses repeats.
It takes either a single seed or that same comma-separated `TXID=seed` mapping — with a mapping, each frame is decoded with its own transmitter's seed, so one invocation handles every sensor on the band (a keyed event whose TXID isn't in the mapping is skipped with a note).

## Capturing for a fast crack

The counter increments per **event** and entropy resets only at power-up, so:

1. **Power-cycle the sensor** (battery pull) — counters restart near 24.
2. **Toggle the reed switch ~10–12 times** (or let heartbeats run) for distinct low counters.
3. Feed the capture in.

~8–12 distinct low counters pin the seed (each frame's byte-10 nibble gives 4 bits; the seed is 16).
A capture starting at a high counter still works but the brute force replays from event entry for every candidate (slower — `crack` warns).
If more than one candidate survives, capture more low-counter frames.

## Scope

Validated on the DW21R-family door sensor and any unit on the same firmware.
Other Vivint models use a different frame mapping/schedule and are not covered.
