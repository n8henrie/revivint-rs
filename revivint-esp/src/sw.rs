//! SOFTWARE receive loop.
//!
//! The CC1101 is a dumb OOK slicer (asynchronous transparent mode, raw demod on
//! GDO0). Everything else runs on the MCU, through the *same* code the host CLI
//! and its tests exercise:
//!
//!   RMT RX captures GDO0 edge timings (level, duration_µs)
//!     -> revivint_core::manchester::pulses_to_chips  (round to 156 µs chips)
//!     -> revivint_core::manchester::decode           (Manchester -> data bits)
//!     -> revivint_core::for_each_frame               (0xFFFE sync + CRC)
//!     -> net::report                                 (MQTT)
//!
//! Costs more CPU/awake time than the hardware path, but nothing here depends on
//! the CC1101's packet engine locking onto the burst, and both Manchester
//! polarities are tried per burst — so there is no sync word or `invert` flag to
//! calibrate.

use embassy_time::{Duration, Instant, Timer};
use esp_hal::gpio::Level;
use esp_hal::rmt::{PulseCode, Rmt, RxChannelConfig, RxChannelCreator};
use esp_hal::time::Rate;

use revivint_core::bits::BitBuf;
use revivint_core::{for_each_frame_in_run_vetted, manchester, Policy, Registry};

use crate::{Fatal, Radio};

/// Largest single edge-capture burst we buffer (level, duration_µs).
const MAX_PULSES: usize = 512;
/// RMT codes per receive() — each u32 packs two (level, length) entries.
const MAX_CODES: usize = MAX_PULSES / 2;
/// RMT base rate: 1 MHz -> 1 tick == 1 µs, so PulseCode lengths are already µs.
const RMT_TICK_MHZ: u32 = 1;
/// End-of-burst idle gap (µs). Matches `manchester::RESET_US` (rtl_433's
/// `reset_limit`, and the `r=500` of the proven capture command): above the
/// longest legitimate two-chip run (266 µs) so a frame's own gaps never end the
/// capture, but below the gap between repeats.
const RMT_IDLE_US: u16 = revivint_core::manchester::RESET_US as u16;

/// Expand RMT pulse codes (two entries per code) into (is_high, duration_µs)
/// pairs for the decoder. Stops at the first zero-length terminator.
fn expand(codes: &[PulseCode], out: &mut [(bool, u32)]) -> usize {
    let mut n = 0;
    for &code in codes {
        let l1 = code.length1();
        if l1 == 0 || n >= out.len() {
            break;
        }
        out[n] = (matches!(code.level1(), Level::High), u32::from(l1));
        n += 1;
        let l2 = code.length2();
        if l2 == 0 || n >= out.len() {
            break;
        }
        out[n] = (matches!(code.level2(), Level::High), u32::from(l2));
        n += 1;
    }
    n
}

/// How often to report receive statistics when nothing is decoding.
const STATS_EVERY: Duration = Duration::from_secs(60);

/// How many pulses of the best burst to keep for the timing report.
/// A frame is ~192 chips, which arrives as roughly 150-200 edges, so anything
/// less than this shows only a fraction of a burst — and a fraction cannot tell
/// you where decoding actually failed.
const PROBE_PULSES: usize = 220;

/// Ignore bursts shorter than this many edges.
///
/// A real frame is 96 data bits, Manchester-encoded to 192 chips, so it arrives
/// as roughly 100-200 edges. The OOK slicer chatters constantly on noise between
/// bursts, producing a flood of ~13-edge fragments (observed: 20k bursts/minute)
/// that cannot possibly be a frame. Dropping them before the decoder keeps the
/// statistics meaningful and the MCU idle.
const MIN_BURST_PULSES: usize = 48;

pub async fn rx_loop(
    mut radio: Radio,
    gdo0: esp_hal::peripherals::GPIO3<'static>,
    rmt: esp_hal::peripherals::RMT<'static>,
) -> Result<(), Fatal> {
    // RMT RX on GDO0: capture the demodulated OOK edge timings.
    let rmt = Rmt::new(rmt, Rate::from_mhz(RMT_TICK_MHZ))
        .map_err(|_| Fatal("rmt init"))?
        .into_async();
    // `Rmt::new` already divides the source clock down to RMT_TICK_MHZ, so the
    // per-channel divider stays at 1 and one tick is one microsecond.
    let rx_config = RxChannelConfig::default()
        .with_clk_divider(1)
        .with_idle_threshold(RMT_IDLE_US);
    let mut rx = rmt
        .channel2 // ESP32-C3: RMT RX is channels 2/3 (0/1 are TX-only)
        .configure_rx(&rx_config)
        .map_err(|_| Fatal("rmt configure_rx"))?
        .with_pin(gdo0);

    let mut raw = [PulseCode::default(); MAX_CODES];
    let mut pulses = [(false, 0u32); MAX_PULSES];

    // Per-device keystreams for every keyed sensor (seeds baked in at compile
    // time via VIVINT_KEYS), held across frames to recover the true contact state
    // from each sensor's whitened status. Unkeyed/legacy sensors pass through.
    let mut registry = Registry::new();

    // Silence must be legible. Previously the only "nothing decoded" message was
    // a `debug!`, and the shipped ESP_LOG is `info` — so a receiver that heard
    // nothing and one that heard plenty but failed to decode looked identical
    // (both printed absolutely nothing). Count what happens and say so.
    let mut bursts = 0u32;
    let mut noise_bursts = 0u32;
    let mut pulses_seen = 0u32;
    let mut longest = 0usize;
    let mut frames = 0u32;
    // Raw edge timings from the longest burst of the period. This is the one
    // measurement that settles the chip width against real hardware instead of
    // against a comment: the shortest cluster here *is* one Manchester chip.
    let mut probe = [(false, 0u32); PROBE_PULSES];
    let mut probe_len = 0usize;
    let mut next_stats = Instant::now() + STATS_EVERY;

    loop {
        if Instant::now() >= next_stats {
            next_stats = Instant::now() + STATS_EVERY;
            let floor = radio.rssi_dbm().unwrap_or(0);
            // `longest` is the diagnostic that matters: a real frame is ~100-200
            // edges, so if the longest burst all minute was tens of edges, the
            // radio never heard a sensor and the rest is slicer noise.
            log::info!(
                "rx: {bursts} bursts (+{noise_bursts} too short to be a frame), \
                 {pulses_seen} pulses, longest {longest}, {frames} CRC-valid frames \
                 (RSSI {floor} dBm)"
            );
            if frames == 0 && longest < MIN_BURST_PULSES {
                log::info!(
                    "rx: nothing resembling a frame (need ~{MIN_BURST_PULSES}+ edges) — \
                     the radio is not hearing the sensor; check antenna/frequency"
                );
            }
            if probe_len > 0 {
                // Printed as `level:duration_us` so the widths can be read
                // straight off. Expect two clusters ~1x and ~2x the chip width.
                log::info!("rx: longest-burst edge timings (us), first {probe_len}:");
                let mut i = 0;
                while i < probe_len {
                    let end = (i + 14).min(probe_len);
                    let mut line: heapless::String<160> = heapless::String::new();
                    for &(lvl, d) in &probe[i..end] {
                        let _ = core::fmt::Write::write_fmt(
                            &mut line,
                            format_args!("{}:{} ", u8::from(lvl), d),
                        );
                    }
                    log::info!("  {line}");
                    i = end;
                }
                // The *shortest* edge is essentially always a glitch, so it says
                // nothing about the chip width. Report the median of the 1-chip
                // cluster split by level: the slicer's threshold is off-centre,
                // so highs and lows differ systematically and only their SUM is
                // a trustworthy two-chip measure.
                let mut hi: heapless::Vec<u32, PROBE_PULSES> = heapless::Vec::new();
                let mut lo: heapless::Vec<u32, PROBE_PULSES> = heapless::Vec::new();
                for &(lvl, d) in &probe[..probe_len] {
                    if d > manchester::CHIP_US / 2 && d < manchester::CHIP_US * 3 / 2 {
                        let _ = if lvl { hi.push(d) } else { lo.push(d) };
                    }
                }
                let med = |v: &mut heapless::Vec<u32, PROBE_PULSES>| -> u32 {
                    if v.is_empty() {
                        return 0;
                    }
                    v.sort_unstable();
                    v[v.len() / 2]
                };
                let (mh, ml) = (med(&mut hi), med(&mut lo));
                if mh > 0 && ml > 0 {
                    log::info!(
                        "  1-chip median: high {mh} us / low {ml} us -> pair {} us, chip {} us \
                         (configured {} us)",
                        mh + ml,
                        (mh + ml) / 2,
                        manchester::CHIP_US
                    );
                    if mh > ml + manchester::CHIP_US / 3 {
                        log::info!(
                            "  slicer threshold off-centre by ~{} us — highs long, lows short",
                            (mh - ml) / 2
                        );
                    }
                }
                // Where does Manchester decoding actually stop?
                let mut probe_chips = BitBuf::new();
                manchester::pulses_to_chips(&probe[..probe_len], &mut probe_chips);
                for inv in [false, true] {
                    let mut longest_run = 0usize;
                    let mut nruns = 0u32;
                    manchester::for_each_run(probe_chips.as_slice(), inv, |b| {
                        nruns += 1;
                        longest_run = longest_run.max(b.len());
                    });
                    log::info!(
                        "  invert={inv}: {} chips -> {nruns} run(s), longest {longest_run} bits \
                         (a body is 80, a full frame 96)",
                        probe_chips.len()
                    );
                }
                probe_len = 0;
            }
            bursts = 0;
            noise_bursts = 0;
            pulses_seen = 0;
            longest = 0;
            frames = 0;
        }

        for c in raw.iter_mut() {
            c.reset();
        }
        // esp-hal 1.1 reports how many codes were actually captured.
        let Ok(codes) = rx.receive(&mut raw).await else {
            // overflow/timeout: re-arm after a short pause
            Timer::after(Duration::from_millis(5)).await;
            continue;
        };
        let count = expand(&raw[..codes.min(raw.len())], &mut pulses);
        if count == 0 {
            continue;
        }
        if count > longest {
            probe_len = count.min(PROBE_PULSES);
            probe[..probe_len].copy_from_slice(&pulses[..probe_len]);
        }
        longest = longest.max(count);
        if count < MIN_BURST_PULSES {
            noise_bursts += 1;
            continue; // slicer chatter, not a frame
        }
        bursts += 1;
        pulses_seen += count as u32;

        // Decode in software using the host-tested library.
        let mut chips = BitBuf::new();
        manchester::pulses_to_chips(&pulses[..count], &mut chips);

        // Try both Manchester polarities, and within each let `for_each_run`
        // handle chip *phase* and glitch recovery: a capture that starts one
        // chip late pairs every chip wrongly, and a single runt pulse used to
        // abandon the whole burst. Polarity alone cannot fix either.
        // The vetting predicate needs an immutable view while the reporting
        // closure holds `registry` mutably, so snapshot the key table first.
        // Same declaration gate as the hardware path — `sw` exists to debug the
        // RF chain, not to see a different set of devices than production does.
        // (No `+legacy` corroboration here: this build is for bring-up, and a
        // second policy to keep in sync would be a place for them to drift.)
        let policy = Policy::from_map(&revivint_core::KEYS);
        let mut decoded = 0usize;
        for invert in [false, true] {
            manchester::for_each_run(chips.as_slice(), invert, |databits| {
            // Not `for_each_frame`: the preamble is usually lost while the AGC
            // settles, so a run typically holds the bare 80-bit body with no
            // sync in it at all. The sync-less path is vetted against the
            // registry so a chance CRC hit cannot invent a sensor.
            for_each_frame_in_run_vetted(databits, |f| policy.declares(f.txid), |frame, _rec| {
                decoded += 1;
                let mut frame = *frame;
                // A 0x73 seed-announce self-configures the registry (for_each_frame
                // hands us already-decoded frames, so learn here before un-keying).
                if let Some(seed) = frame.announced_seed() {
                    registry.learn(frame.txid, seed);
                    log::info!(
                        "rx id={:05x} announced seed {seed:#06x} (learned)",
                        frame.txid
                    );
                } else {
                    registry.apply_key(&mut frame); // recover true contact for keyed 0x7x
                    log::info!("rx {frame}");
                }
                crate::net::report(frame);
            });
            });
            if decoded > 0 {
                frames += decoded as u32;
                break; // this polarity works; don't double-report the same burst
            }
        }
        if decoded == 0 {
            // A burst that yielded no valid frame is the normal case for RF
            // noise, so keep it at debug — but it is also what you look at when
            // real sensor events are missing.
            log::debug!("rx: burst of {count} pulses produced no CRC-valid frame");
        }
    }
}
