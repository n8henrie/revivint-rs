//! ESP32-C3 + CC1101 — receive Vivint/Honeywell 345 MHz door/window sensors and
//! publish open/closed (plus battery, tamper, heartbeat) to MQTT, with Home
//! Assistant discovery.
//!
//! Everything after the antenna runs on the MCU. Two builds exist, selected by
//! a Cargo feature — exactly one is enabled.
//!
//! # Who does what
//!
//! | stage | `hw` (default) | `sw` (debugging only) |
//! |---|---|---|
//! | RF filtering, OOK demodulation | **radio** | **radio** |
//! | Bit/chip timing recovery | **radio** | MCU (times every edge via RMT) |
//! | Sync detection | **radio** (chip-encoded sync word) | MCU (searches for `FFFE`) |
//! | Packet buffering | **radio** (64-byte FIFO) | none — per-edge interrupts |
//! | Manchester decode | MCU (~160 chips/packet) | MCU |
//! | Framing, CRC, keystream | MCU | MCU |
//!
//! The radio does everything it is good at. The one step left to the MCU is
//! Manchester decoding, and that is deliberate: the CC1101 *can* do it, but its
//! decoder pairs chips and commits to a bit with no recovery path, so a single
//! mis-sliced chip loses the frame. Measured on this hardware, letting the radio
//! decode Manchester yielded ~0 frames while doing it on the MCU yields 100% of
//! events — the MCU's version searches chip phase, recovers from glitches, and
//! lets the CRC arbitrate.
//!
//! # `sw` exists for debugging, not for receiving
//!
//! It puts the radio in asynchronous transparent mode and times every GDO0 edge
//! with the RMT. That is far more CPU and it measured ~50% of events against
//! `hw`'s 100%, so it is not a production candidate. It is kept because it is
//! the only mode that can report **raw edge timings**, which is how the chip
//! period (133 us) and the receiver's slicer skew were measured in the first
//! place. Reach for it when the radio is behaving inexplicably, not otherwise.
//!
//! Both feed one [`Registry`], so a single board serves the 96-bit (5817-style
//! `0x7x`/`0xd0`) and 64-bit legacy (5718-style) families at once, in either OOK
//! polarity, un-keying each sensor with its own seed.
//!
//! Built against esp-hal 1.1 / esp-rtos 0.3 / esp-radio 0.18 (riscv32imc). The
//! pin map below is the one knob to match to your board.
#![no_std]
#![no_main]

#[cfg(not(feature = "diag"))]
mod net;
#[cfg(feature = "diag")]
#[path = "net_stub.rs"]
mod net;

#[cfg(feature = "hw")]
mod hw;
#[cfg(feature = "sw")]
mod sw;

// The two decode strategies configure the radio differently and own different
// peripherals, so "both" and "neither" are build errors rather than surprises on
// the bench.
#[cfg(all(feature = "sw", feature = "hw"))]
compile_error!("features `chip` and `sw` are mutually exclusive: pick one");
#[cfg(not(any(feature = "sw", feature = "hw")))]
compile_error!("enable exactly one decode strategy: `chip` (default) or `sw`");

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;

use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::ram;
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::spi::Mode;
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::Blocking;

use revivint_core::cc1101::config::REG_TABLE;
use revivint_core::cc1101::{config, Cc1101, OutputPin, SpiBus};

// ESP-IDF bootloader app descriptor (required by espflash / the 2nd-stage
// bootloader to recognise the image).
esp_bootloader_esp_idf::esp_app_desc!();

// ===== Board wiring — change these `peripherals.GPIOxx` in `run()` to match =====
// CC1101 <-> ESP32-C3 (defaults; any free SPI-capable pins work):
//   SCLK=GPIO4  MOSI=GPIO6  MISO=GPIO5  CS=GPIO7
//   GDO0=GPIO3  (hw: packet-ready interrupt; sw: RMT edge-capture input)

// ---- radio configuration ---------------------------------------------------
//
// A production build has exactly ONE setting: `VIVINT_KEYS`. Everything about
// the RF path was determined experimentally on hardware and is baked in, which
// is the point of having done the sweep — a user should not have to know what a
// sync word or an OOK decision boundary is to receive their own sensors.
//
// The tuning knobs still exist, but only in a `diag` build. They are bench
// instruments for re-running the sweep on different hardware, not configuration.

/// Sync word for the software-framing path (`sw`), matched on decoded data bits.
const SYNC_WORD: u16 = config::SYNC_WORD;

/// Sync word for the `hw` path, matched on the raw Manchester chip stream.
///
/// `0x5556` — measured, not chosen. See [`config::SYNC_WORD_CHIPS`]: the
/// derivation gives `0xAAA9`, and the CC1101's OOK slicer emits its inverse.
/// On the bench `0x5556` decoded 100% of events; `0xAAA9` decoded none.
const CHIP_SYNC_WORD: u16 = config::SYNC_WORD_CHIPS;

/// Radio profile for a production build: the values the sweep settled on.
///
/// Every one of these was measured. The bench swept close-in attenuation, data
/// rate, `BSCFG`, the OOK decision boundary, `MAGN_TARGET`, sync mode and
/// carrier-sense threshold — 28 configurations — and every one reached 100% of
/// events once the sync word was right. These are simply the best-performing
/// row, and there is nothing left for a user to tune.
#[cfg(not(feature = "diag"))]
const SQUELCH: config::Squelch = config::SQUELCH;

/// Starting point for `diag` sweeps: TI DN022's OOK bring-up values rather than
/// the production profile, because production squelch can suppress the very
/// frames being debugged.
#[cfg(feature = "diag")]
const BASE: config::Squelch = config::SQUELCH_DIAG;

/// Radio profile for a `diag` build: every field overridable for bench sweeps.
///
/// Values are validated at compile time — an out-of-range `VIVINT_MAGN=8` fails
/// the build rather than silently wrapping to 0 and making a sweep row measure
/// something other than its label claims.
#[cfg(feature = "diag")]
const SQUELCH: config::Squelch = config::Squelch {
    abs_thr_db: match option_env!("VIVINT_CS_THR") {
        Some(s) => {
            let v = parse_i8(s);
            assert!(v >= -8 && v <= 7, "VIVINT_CS_THR must be -8..=7");
            v
        }
        None => BASE.abs_thr_db,
    },
    max_dvga_gain: match option_env!("VIVINT_MAX_DVGA") {
        Some(s) => parse_field(s, 3, "VIVINT_MAX_DVGA"),
        None => BASE.max_dvga_gain,
    },
    magn_target: match option_env!("VIVINT_MAGN") {
        Some(s) => parse_field(s, 7, "VIVINT_MAGN"),
        None => BASE.magn_target,
    },
    agcctrl0: match option_env!("VIVINT_AGC") {
        Some(s) => parse_hex_u16(s) as u8,
        None => BASE.agcctrl0,
    },
    chanbw: match option_env!("VIVINT_CHANBW") {
        Some(s) => parse_field(s, 0xf, "VIVINT_CHANBW"),
        None => BASE.chanbw,
    },
    bscfg: match option_env!("VIVINT_BSCFG") {
        Some(s) => parse_hex_u16(s) as u8,
        None => BASE.bscfg,
    },
    drate_m: match option_env!("VIVINT_DRATE_M") {
        Some(s) => parse_hex_u16(s) as u8,
        None => BASE.drate_m,
    },
    sync_mode: match option_env!("VIVINT_SYNC_MODE") {
        Some(s) => parse_field(s, 7, "VIVINT_SYNC_MODE"),
        None => BASE.sync_mode,
    },
    fifothr: match option_env!("VIVINT_FIFOTHR") {
        Some(s) => parse_hex_u16(s) as u8,
        None => BASE.fifothr,
    },
};

/// Sync word for a `diag` build, overridable to test the other OOK polarity.
#[cfg(all(feature = "diag", feature = "hw"))]
const CHIP_SYNC_WORD_DIAG: u16 = match option_env!("VIVINT_SYNC") {
    Some(s) => parse_hex_u16(s),
    None => config::SYNC_WORD_CHIPS,
};

// ---- build-time value parsing (diag builds only) ---------------------------
//
// These exist solely so a bench sweep can override radio fields. A production
// build has no such knobs, so the helpers are gated with them.

/// Parse `0x….`/`….` hex in const context.
#[cfg(feature = "diag")]
const fn parse_hex_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    let mut i = if b.len() > 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        2
    } else {
        0
    };
    assert!(i < b.len(), "empty hex value");
    let mut v: u32 = 0;
    while i < b.len() {
        let c = b[i];
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("expected hex, e.g. 0x5556"),
        };
        v = v * 16 + d as u32;
        assert!(v <= 0xffff, "hex value out of 16-bit range");
        i += 1;
    }
    v as u16
}

/// Parse a hex byte and assert it is within `0..=max`.
///
/// Masking instead of asserting is a trap: `VIVINT_MAX_DVGA=4` would silently
/// become 0, so a sweep row would test a different setting than its label claims
/// and the results would be quietly wrong.
#[cfg(feature = "diag")]
const fn parse_field(s: &str, max: u8, name: &str) -> u8 {
    let v = parse_hex_u16(s);
    assert!(v <= max as u16, "value out of range for this field");
    let _ = name;
    v as u8
}

/// Parse a signed decimal in const context.
#[cfg(feature = "diag")]
const fn parse_i8(s: &str) -> i8 {
    let b = s.as_bytes();
    let (neg, mut i) = if !b.is_empty() && b[0] == b'-' {
        (true, 1)
    } else {
        (false, 0)
    };
    assert!(i < b.len(), "empty signed value");
    let mut v: i16 = 0;
    while i < b.len() {
        let c = b[i];
        assert!(c >= b'0' && c <= b'9', "expected a decimal integer");
        v = v * 10 + (c - b'0') as i16;
        assert!(v <= 128, "signed value out of range");
        i += 1;
    }
    if neg { -v as i8 } else { v as i8 }
}

// ---- esp-hal -> cc1101 trait adapters ---------------------------------------
// Thin shims so the dependency-free driver in `revivint_core::cc1101` can drive
// esp-hal's SPI/GPIO without either side knowing about the other.
struct HalSpi<T>(T);
struct HalCs<T>(T);

impl<T: EspSpiLike> SpiBus for HalSpi<T> {
    type Error = T::Error;
    fn transfer_in_place(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
        self.0.transfer(words)
    }
}
impl<T: EspPinLike> OutputPin for HalCs<T> {
    type Error = core::convert::Infallible;
    fn set_low(&mut self) -> Result<(), Self::Error> {
        self.0.set_low();
        Ok(())
    }
    fn set_high(&mut self) -> Result<(), Self::Error> {
        self.0.set_high();
        Ok(())
    }
}

// Minimal capability traits, implemented for the concrete esp-hal types below.
trait EspSpiLike {
    type Error;
    fn transfer(&mut self, words: &mut [u8]) -> Result<(), Self::Error>;
}
trait EspPinLike {
    fn set_low(&mut self);
    fn set_high(&mut self);
}
impl EspSpiLike for Spi<'_, Blocking> {
    type Error = esp_hal::spi::Error;
    fn transfer(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
        Spi::transfer(self, words)
    }
}
impl EspPinLike for Output<'_> {
    fn set_low(&mut self) {
        Output::set_low(self);
    }
    fn set_high(&mut self) {
        Output::set_high(self);
    }
}

/// `MARCSTATE` value meaning "in RX" (datasheet §10.3).
pub const MARC_STATE_RX: u8 = 0x0d;

/// The configured radio, as both decode paths receive it.
type Radio = Cc1101<HalSpi<Spi<'static, Blocking>>, HalCs<Output<'static>>>;

/// One label per fatal bring-up step so `main` can report without panicking.
#[derive(Debug)]
pub struct Fatal(&'static str);

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger_from_env();
    log::info!(
        "revivint-esp: {} decode starting, sync={:#06x}",
        if cfg!(feature = "hw") {
            "hardware-offloaded (radio: OOK+timing+sync+FIFO, MCU: Manchester)"
        } else {
            "software (RMT edge capture) — debugging only"
        },
        if cfg!(feature = "hw") { CHIP_SYNC_WORD } else { SYNC_WORD }
    );
    if let Err(Fatal(step)) = run(spawner).await {
        log::error!("fatal during {step}; halting");
    }
    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}

/// Shared bring-up: clocks, heap, scheduler, Wi-Fi/MQTT, SPI and the CC1101.
/// Only the receive loop itself differs between the two decode strategies.
async fn run(spawner: Spawner) -> Result<(), Fatal> {
    // `sw` + `diag` spawns nothing: no network tasks, and the software receive
    // loop owns its own statistics.
    let _ = &spawner;
    // esp-radio requires CPU clock >= 80 MHz.
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    // Heap. esp-radio's Wi-Fi init is allocation-hungry (RX/TX buffer pools, the
    // WPA supplicant), and esp-rtos allocates every task from it too, so a single
    // 72 KB region runs out during `wifi::new` — the failure looks like a bare
    // `memory allocation of 4 bytes failed` panic. Use the two regions esp-radio
    // documents: the RAM reclaimed from the ESP-IDF bootloader (otherwise wasted)
    // plus a regular dram_seg region. rust-mqtt's AllocBuffer draws from this too.
    esp_alloc::heap_allocator!(#[ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 36 * 1024);

    // esp-rtos is the scheduler that both embassy and esp-radio run on, so it
    // must be started before any radio call. It replaces esp-hal-embassy::init.
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // Wi-Fi + embassy-net + MQTT (background tasks; publishes are decoupled via
    // a channel — see net::report).
    #[cfg(not(feature = "diag"))]
    net::start(spawner, peripherals.WIFI).map_err(Fatal)?;
    #[cfg(feature = "diag")]
    {
        let _ = peripherals.WIFI;
        log::info!("diag build: Wi-Fi and MQTT disabled; RF path only");
    }
    // Wi-Fi init is by far the biggest consumer; log what is left so a future
    // allocation failure has a number attached to it.
    let heap = esp_alloc::HEAP.stats();
    log::info!(
        "heap after radio init: {} used / {} total",
        heap.current_usage,
        heap.size
    );

    // SPI to the CC1101 + chip-select.
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_khz(500))
            .with_mode(Mode::_0),
    )
    .map_err(|_| Fatal("spi init"))?
    .with_sck(peripherals.GPIO4)
    .with_mosi(peripherals.GPIO6)
    .with_miso(peripherals.GPIO5);
    let cs = Output::new(peripherals.GPIO7, Level::High, OutputConfig::default());

    let mut radio = Cc1101::new(HalSpi(spi), HalCs(cs));
    radio.reset().map_err(|_| Fatal("cc1101 reset"))?;
    // SRES is not instantaneous: the datasheet has the chip hold MISO low until
    // the crystal is stable, and reading registers before that returns partially
    // settled garbage. Waiting here is the difference between a real identity
    // check and a scary-but-wrong "SPI is not reaching the radio".
    Timer::after(Duration::from_millis(5)).await;

    // Prove the SPI bus reaches a real chip before blaming the antenna, the
    // frequency or the framing. A floating bus reads all-ones or all-zeros, and
    // every downstream symptom ("no sync", "undecodable bytes") looks identical
    // whether the cause is RF or a swapped MISO/MOSI wire.
    let (part, ver) = radio.part_version().map_err(|_| Fatal("cc1101 part_version"))?;
    if radio.probe().map_err(|_| Fatal("cc1101 probe"))? {
        log::info!("cc1101: found chip, partnum={part:#04x} version={ver:#04x}");
    } else {
        // Not fatal, and deliberately hedged: if the register read-back below
        // passes, the bus is fine and this reading was just early.
        log::warn!(
            "cc1101: unexpected partnum={part:#04x} version={ver:#04x} (expected 0x00/0x14) \
             — check the register read-back below before suspecting wiring"
        );
    }

    let mut regs = [(0u8, 0u8); REG_TABLE];
    // The two profiles differ in exactly the way the strategies do: one hands the
    // packet engine the sync word and a fixed length, the other asks for raw
    // asynchronous demodulated data.
    #[cfg(all(feature = "hw", not(feature = "diag")))]
    let n = config::profile_hardware_chips_tuned(&mut regs, CHIP_SYNC_WORD, SQUELCH);
    #[cfg(all(feature = "hw", feature = "diag"))]
    let n = config::profile_hardware_chips_diag(&mut regs, CHIP_SYNC_WORD_DIAG, SQUELCH);
    #[cfg(feature = "sw")]
    let n = config::profile_software_tuned(&mut regs, SQUELCH);
    // Write the profile *and read it back*: this is what distinguishes "the radio
    // is mis-tuned" from "the radio never received the configuration at all".
    if let Some(bad) = radio
        .apply_verified(&regs[..n])
        .map_err(|_| Fatal("cc1101 apply"))?
    {
        // Fatal, not a warning: continuing past a config that demonstrably did
        // not reach the chip turns a known SPI/bus fault into hours of chasing
        // "undecodable bytes" at the RF layer.
        log::error!(
            "cc1101: register {:#04x} read back {:#04x} after writing {:#04x} \
             — the config did not take (SPI too fast? try a lower Rate::from_khz)",
            bad.addr,
            bad.read,
            bad.wrote
        );
        return Err(Fatal("cc1101 register readback"));
    }
    radio.start_rx().map_err(|_| Fatal("cc1101 start_rx"))?;

    // Confirm the state machine actually armed, then take a noise-floor reading.
    //
    // MCSM0 asks for auto-calibration on IDLE->RX, which takes ~720 us, so an
    // immediate read catches MARCSTATE mid-calibration (0x08 = STARTCAL) and
    // reports a failure that resolves itself microseconds later. Poll instead.
    let mut marc = 0;
    for _ in 0..20 {
        marc = radio.marc_state().map_err(|_| Fatal("cc1101 marcstate"))?;
        if marc == MARC_STATE_RX {
            break;
        }
        Timer::after(Duration::from_millis(1)).await;
    }
    let floor = radio.rssi_dbm().map_err(|_| Fatal("cc1101 rssi"))?;
    if marc == MARC_STATE_RX {
        // In a quiet room this RSSI *is* the noise floor. Compare it against a
        // reading taken while the sensor transmits: if they do not differ, the
        // radio is not hearing the sensor and no framing or key change will help.
        log::info!("cc1101: in RX, noise floor {floor} dBm");
    } else {
        // Fatal. Continuing turns a known radio-state fault into an apparent RF
        // or decoding problem, which is exactly the misdiagnosis this project
        // has already spent several rounds on.
        log::error!(
            "cc1101: never reached RX (marcstate {marc:#04x}, wanted {MARC_STATE_RX:#04x})"
        );
        return Err(Fatal("cc1101 never reached RX"));
    }

    #[cfg(feature = "hw")]
    return hw::rx_loop(spawner, radio, peripherals.GPIO3).await;
    #[cfg(feature = "sw")]
    return sw::rx_loop(radio, peripherals.GPIO3, peripherals.RMT).await;
}
