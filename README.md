# revivint

Decode Vivint 345 MHz door and window sensors, and recover the 16-bit seed that keys their newer transmissions.

This repo provides a command-line tool for decoding transmissions captured by e.g. rtl433 as well as firmware for a standalone ESP32C3 + CC1101 combo that translates received transmission into MQTT messages compatible with Home-Assistant.

The keyed sensors (the 5817-style DW11 and DW21R families) scramble their open/closed status with a keystream derived from a per-device seed.
Recover a sensor's seed once, from a few rtl_433 captures, and every later transmission can be read.
The older 64-bit (5718-style) family is not keyed and decodes without one.

Lots of discussion, background, and reverse engineering at <https://github.com/merbanan/rtl_433/issues/1504>.

## LLM Policy

Caveat emptor: This project was almost entirely vibe-coded with a Claude Opus (and a little Fable).
In spite of this, I generally do not care for LLM-generated or LLM-assisted contributions.
Please divulge LLM involvement in any communication or code, and note that issues, PR, or other contributions may (or may not) be closed on this basis alone, with or without additional feedback from me.

## Crates

| Crate | What it is |
|---|---|
| [`revivint`](revivint/) | The command-line tool: `crack` recovers seeds from captures, `decode` reads events with them. |
| [`revivint-core`](revivint-core/) | The `no_std`, allocation-free decoder both of the others are built on: framing, CRC, keystream and the OOK bit layer. |
| [`revivint-esp`](revivint-esp/) | Firmware for an ESP32-C3 with a CC1101 radio, publishing sensor state to MQTT and Home Assistant. |

Each crate's README has the details.

## Quick start

Crack and decode with the CLI, from rtl_433 output:

```sh
cargo install revivint
rtl_433 -f 345M -X 'n=v,m=OOK_MC_ZEROBIT,s=133,l=133,r=500,invert' -F json:- | revivint crack
```

Or, with Nix and nothing installed:

```sh
nix run github:n8henrie/revivint-rs -- crack capture.json
```

`crack` prints a `TXID=seed` mapping for every sensor it pins down.
Hand that mapping to `revivint decode`, or bake it into the firmware as `VIVINT_KEYS`.

## Firmware

With a board plugged in, this builds the firmware with your settings, flashes it and opens the serial monitor:

```sh
cp .env.sample .env
$EDITOR .env
source .env
nix run --impure .#flash
```

The settings are read from the environment, and `--impure` is what lets the build see them.
Without it, or with any of `WIFI_SSID`, `WIFI_PASS`, `MQTT_BROKER_IP` and `VIVINT_KEYS` unset, the build fails and names what is missing.
See [`revivint-esp/README.md`](revivint-esp/README.md) for wiring, the optional settings, a rustup-based build and troubleshooting.

## Development

Cargo and rustc come from rustup, which reads `rust-toolchain.toml` and installs the stable toolchain, the RISC-V target and `rust-src`.
`nix develop` adds the rest: `espflash`, `lld`, `rust-analyzer` and `rustfmt`.

```sh
cargo test --all-features   # the host crates; the firmware is not a default member
cargo clippy --all-targets --all-features
(cd revivint-esp && cargo build --release)
```

`nix build .#revivint` builds the CLI and runs its tests.
`nix build --impure .#revivint-esp` builds the firmware, given the required settings in the environment.

## Releases

Pushing a tag `vX.Y.Z` that matches the CLI's version publishes `revivint-core` (when that version is not already on crates.io) and then `revivint`.

## License

MIT; see [LICENSE](LICENSE).
