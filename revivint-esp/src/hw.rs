//! HARDWARE-assisted receive loop.
//!
//! The CC1101 does OOK demodulation, Manchester decode, a 16/16 sync-word match
//! and a fixed-length packet capture into its RX FIFO. GDO0 asserts on sync and
//! de-asserts at end of packet, so a falling edge means "a body is waiting".
//! The MCU only reads bytes and calls into [`revivint_core`].

use embassy_executor::Spawner;
use embassy_time::{with_timeout, Duration, Timer};
use esp_hal::gpio::{Input, InputConfig, Pull};
use portable_atomic::{AtomicU32, Ordering};

#[cfg(not(feature = "diag"))]
use revivint_core::cc1101::config::CAPTURE_CHIP_BYTES as CAPTURE_BYTES;
#[cfg(feature = "diag")]
use revivint_core::cc1101::config::CAPTURE_CHIP_BYTES_DIAG as CAPTURE_BYTES;
use core::cell::RefCell;
use revivint_core::{ChipCapture, DecodedFrame, Family, Policy, Recovery, Registry};

use crate::{Fatal, Radio};

/// The declaration/vetting policy, from `VIVINT_KEYS` at build time.
static POLICY: Policy = Policy::from_map(&revivint_core::KEYS);

/// How often to report receive statistics.
const STATS_EVERY: Duration = Duration::from_secs(60);
/// Longest wait for a fixed-length capture to complete before reading whatever
/// arrived. A burst that stops mid-packet would otherwise wedge the loop.
///
/// Derived, not chosen: a complete capture is `CAPTURE_BYTES` of chips at
/// [`revivint_core::manchester::CHIP_US`] each, so anything longer than that is
/// a capture that will never finish. Four times over is ample margin, and it
/// matters because every late false sync (see [`ChipCapture`]) costs one of
/// these waits before the radio is flushed back into RX.
const RX_TIMEOUT: Duration = Duration::from_micros(
    4 * CAPTURE_BYTES as u64 * 8 * revivint_core::manchester::CHIP_US as u64,
);
/// Times the radio matched the sync word and woke us (i.e. captures started).
static SYNCS: AtomicU32 = AtomicU32::new(0);
/// Captures actually read out of the FIFO (a sync can wake us and yield nothing).
static CAPTURES: AtomicU32 = AtomicU32::new(0);
/// Of those, how many decoded to a CRC-valid frame.
static FRAMES: AtomicU32 = AtomicU32::new(0);
/// RX FIFO overflows: GDO0 de-asserts for these too, so they masquerade as packets.
static OVERFLOWS: AtomicU32 = AtomicU32::new(0);
/// Truncated captures that did not decode: the burst stopped before the FIFO
/// filled, so the radio read out a tail. Distinct from a *full* capture that
/// decodes to nothing, which is the one worth a warning.
static PARTIAL: AtomicU32 = AtomicU32::new(0);
/// Captures too short to hold any frame — the radio re-armed mid-burst and
/// matched the sync word on the tail of a packet it had already delivered.
/// Expected and harmless; counted rather than warned about.
static SHORT: AtomicU32 = AtomicU32::new(0);
/// `+legacy`: undeclared 64-bit senders, admitted only once corroborated.
///
/// `+legacy` on its own restores the fabrication rate the declaration gate
/// exists to stop — ~0.092% of unrelated bursts, each inventing a fresh random
/// TXID. What separates those from a real sensor is not the CRC, it is
/// **repetition**: a phantom is a one-off (259 measured, 259 distinct TXIDs,
/// none seen twice), while a real sensor sends every event about six times,
/// 129 ms apart.
///
/// So an undeclared legacy TXID is held provisionally on first sight and only
/// believed if it comes back inside one burst. Two independent phantoms would
/// have to collide on the same 20-bit id *and* land within the same second,
/// which is not a rate worth writing down.
struct LegacyGate {
    seen: [(u32, u64); 8],
    len: usize,
    next: usize,
}

/// How long a provisional sighting stays valid — one burst, generously.
/// A sensor repeats an event ~6x at 129 ms; a phantom never repeats at all.
const CORROBORATE_MS: u64 = 1_500;

impl LegacyGate {
    const fn new() -> Self {
        Self { seen: [(0, 0); 8], len: 0, next: 0 }
    }

    /// Record a sighting; true once this TXID is corroborated.
    fn corroborated(&mut self, txid: u32, now_ms: u64) -> bool {
        for e in self.seen[..self.len].iter_mut() {
            if e.0 == txid {
                if now_ms.saturating_sub(e.1) <= CORROBORATE_MS {
                    return true; // seen twice inside one burst
                }
                e.1 = now_ms; // too long ago to corroborate; restart its window
                return false;
            }
        }
        // First sighting: remember it, believe nothing yet.
        if self.len < self.seen.len() {
            self.seen[self.len] = (txid, now_ms);
            self.len += 1;
        } else {
            self.seen[self.next] = (txid, now_ms); // ring: evict the oldest slot
            self.next = (self.next + 1) % self.seen.len();
        }
        false
    }
}

// ---- reception quality ------------------------------------------------------
//
// How *hard* the decoder had to work, not just whether it succeeded. Two
// receivers can both report 100% of events while one is comfortably locked and
// the other is scraping frames out of a marginal signal; only this tells them
// apart, and it degrades before the yield does. See `revivint_core::Recovery`.
//
// The counter these replace was `HW_SYNC_EXACT`, incremented unconditionally on
// every successful decode and then reported as "N direct, M rescued" with
// `M = frames - N`. It was arithmetically incapable of showing anything but
// "all direct, none rescued", which is exactly what every log said.

/// Frames that needed no correction at all: the radio triggered on the frame
/// itself, and the chips decoded at the delivered phase and polarity.
static CLEAN: AtomicU32 = AtomicU32::new(0);
/// The radio's packet engine triggered early (a preamble bit error matched the
/// sync pattern) and the real sync was found by scanning forward.
static EARLY_TRIGGER: AtomicU32 = AtomicU32::new(0);
/// Manchester chip phase had to be shifted. A one-chip shift is still locally
/// valid Manchester, so only the CRC catches it.
static PHASE_SHIFTED: AtomicU32 = AtomicU32::new(0);
/// Chip polarity had to be inverted. Should be *stable* for a given radio
/// configuration; flickering means the slicer is sitting on its boundary.
static POLARITY_FLIPPED: AtomicU32 = AtomicU32::new(0);
/// Body did not start on the expected bit boundary within its run.
static BIT_SHIFTED: AtomicU32 = AtomicU32::new(0);
/// Largest sync offset seen, in chips — how much capture slack is really needed.
static WORST_SYNC_AT: AtomicU32 = AtomicU32::new(0);

/// Fold one frame's [`Recovery`] into the counters above.
fn record_quality(r: &Recovery) {
    if r.is_clean() {
        CLEAN.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // Not exclusive: one marginal frame can need several of these, and which
    // ones co-occur is the diagnostic.
    if r.sync_at > 0 {
        EARLY_TRIGGER.fetch_add(1, Ordering::Relaxed);
        WORST_SYNC_AT.fetch_max(r.sync_at as u32, Ordering::Relaxed);
    }
    if r.chip_phase > 0 {
        PHASE_SHIFTED.fetch_add(1, Ordering::Relaxed);
    }
    if r.inverted {
        POLARITY_FLIPPED.fetch_add(1, Ordering::Relaxed);
    }
    if r.bit_offset > 0 {
        BIT_SHIFTED.fetch_add(1, Ordering::Relaxed);
    }
}

pub async fn rx_loop(
    spawner: Spawner,
    mut radio: Radio,
    gdo0: esp_hal::peripherals::GPIO3<'static>,
) -> Result<(), Fatal> {
    spawner.spawn(rx_stats().map_err(|_| Fatal("spawn rx_stats"))?);

    // GDO0 asserts on sync and de-asserts at end of packet: await its falling
    // edge to know a packet is ready in the FIFO.
    let mut gdo0 = Input::new(gdo0, InputConfig::default().with_pull(Pull::None));

    // Per-device keystreams for every keyed sensor, seeds baked in at compile
    // time (VIVINT_KEYS). Each device's cipher is held across frames so it tracks
    // that sensor's counter sequence; frames from unkeyed/legacy sensors pass
    // through in the clear. See `revivint_core::cipher` docs.
    let mut registry = Registry::new();
    // What the operator declared, from the same `VIVINT_KEYS` string. Seeds and
    // declaration are separate questions: a legacy sensor is declared with a
    // bare entry and keyed with none.
    let gate = RefCell::new(LegacyGate::new());

    // A capture much larger than a frame: the radio's sync fires early inside the
    // preamble (see `for_each_frame_bytes`), so we collect well past the trigger
    // and find the real frame in software.
    let mut fifo = [0u8; CAPTURE_BYTES as usize];
    // Consecutive identical un-decodable payloads are collapsed: a sensor sends
    // the same frame many times per event, so without this a mis-tuned radio
    // buries the log in one repeated line. (Corollary worth remembering when
    // debugging: a burst of *differing* undecodable payloads is noise, not a
    // sensor — a real event repeats itself.)
    let mut last_bad = [0u8; CAPTURE_BYTES as usize];
    let mut last_bad_len = 0usize;
    let mut last_bad_reps = 0u32;
    loop {
        // A fixed-length capture only completes if enough bits keep arriving; a
        // burst that stops short would otherwise wedge us here forever, so cap
        // the wait and read whatever the FIFO managed to collect.
        if with_timeout(RX_TIMEOUT, gdo0.wait_for_falling_edge())
            .await
            .is_err()
            && radio.rx_bytes().map_err(|_| Fatal("cc1101 rx_bytes"))? == 0
        {
            continue;
        }
        SYNCS.fetch_add(1, Ordering::Relaxed);

        // GDO0 also de-asserts on FIFO overflow, not just packet-received, so an
        // overflow is indistinguishable from a ready packet without this flag —
        // and its bytes are garbage.
        let st = radio.rx_status().map_err(|_| Fatal("cc1101 rx_status"))?;
        if st.overflow {
            OVERFLOWS.fetch_add(1, Ordering::Relaxed);
            log::debug!("rx: FIFO overflow; flushing");
            radio.start_rx().map_err(|_| Fatal("cc1101 start_rx"))?;
            continue;
        }
        let n = st.count as usize;
        if n == 0 || n > fifo.len() {
            // nothing usable / overflow: flush back to a clean RX state
            log::debug!(
                "rx: {n} bytes in FIFO (expected 1..={}); flushing",
                fifo.len()
            );
            radio.start_rx().map_err(|_| Fatal("cc1101 start_rx"))?;
            continue;
        }
        radio
            .read_fifo(&mut fifo[..n])
            .map_err(|_| Fatal("cc1101 read_fifo"))?;
        CAPTURES.fetch_add(1, Ordering::Relaxed);

        // Two shapes can come out of the FIFO, and the difference is the whole
        // ballgame:
        //
        // 1. **A correct sync match.** The packet engine consumes `ff fe` and the
        //    FIFO holds only the *body* (`7a 00 19 …`). This is the normal case.
        // 2. **An early false trigger.** A bit error in the all-ones preamble
        //    matches the sync word, so the capture opens with preamble and the
        //    real `ff fe` + body sits somewhere later inside it.
        //
        // Case 1 must be tried first. It was previously not tried at all — only
        // the case-2 scanner ran, and that scanner searches *for* `ff fe`, which
        // a correctly received packet by definition does not contain. Every
        // properly synced frame was therefore thrown away as "undecodable", and
        // the only frames that ever decoded were the ones a false trigger had
        // accidentally rescued.
        log::debug!("rx: {n} bytes {:02x?}", &fifo[..n]);

        // A capture shorter than the smallest possible body is not a decode
        // failure; there was never enough there to try. Rejecting it here — and
        // only here — is what keeps the warning below meaningful.
        let Some(capture) = ChipCapture::new(&fifo[..n]) else {
            SHORT.fetch_add(1, Ordering::Relaxed);
            log::debug!("rx: {n}-byte capture is shorter than any frame; late false sync");
            radio.start_rx().map_err(|_| Fatal("cc1101 start_rx"))?;
            continue;
        };

        #[cfg(feature = "hw")]
        let decoded: usize = {
            // The FIFO holds raw Manchester *chips*: the radio matched the
            // chip-encoded sync and did no Manchester of its own. Decoding here
            // uses the same tolerant path as the software build — phase search
            // and glitch recovery — which is exactly what the CC1101's own
            // Manchester decoder lacks.
            // Vetted like the software bare-body fallback: a chip capture has no
            // sync-in-band corroboration once decoded, and the 0x7x check is
            // only 12 bits, so an unknown TXID here is more likely a chance hit
            // than a new sensor.
            // The vetting predicate is `scan_chip_capture`'s own argument rather
            // than a filter applied after the fact, because the filter that used
            // to sit here was a no-op twice over:
            //
            //   known.knows(f.txid) || f.announced_seed().is_none() && f.crc_ok
            //
            // `&&` binds tighter than `||`, so this read "known TXID, OR (not a
            // seed announce AND CRC ok)" — and virtually every real frame
            // satisfies the second clause. Worse, the decode underneath it also
            // ran unvetted. Unrelated 345 MHz traffic therefore fabricated a
            // frame from ~0.1% of bursts, each with a fresh random TXID, and
            // every one became a new Home Assistant device.
            let now_ms = embassy_time::Instant::now().as_millis();
            let accepts = |f: &DecodedFrame| {
                if POLICY.declares(f.txid) {
                    return true;
                }
                // `+legacy` only: an undeclared legacy sender has to show up
                // twice inside one burst before it is believed. See `LegacyGate`.
                POLICY.undeclared_legacy()
                    && f.family() == Family::Legacy64
                    && gate.borrow_mut().corroborated(f.txid, now_ms)
            };
            // `scan_chip_capture` also reports *where* the true sync sat. On a
            // diagnostic-length capture that offset is the measurement wanted:
            // it says how early the radio is triggering, which decides how short
            // the production capture can safely be.
            match revivint_core::scan_chip_capture(capture, crate::CHIP_SYNC_WORD, &accepts) {
                Some((mut frame, rec)) => {
                    record_quality(&rec);
                    if !rec.is_clean() {
                        // Only the frames that needed help are worth a line; a
                        // clean one saying so on every packet is what buried the
                        // interesting cases in the last logs.
                        log::debug!(
                            "rx: corrected — sync_at={} phase={} inverted={} bit_offset={}",
                            rec.sync_at, rec.chip_phase, rec.inverted, rec.bit_offset
                        );
                    }
                    if let Some(seed) = frame.announced_seed() {
                        registry.learn(frame.txid, seed);
                    }
                    registry.apply_key(&mut frame);
                    report(frame);
                    1
                }
                None => 0,
            }
        };


        if decoded > 0 {
            FRAMES.fetch_add(decoded as u32, Ordering::Relaxed);
            last_bad_len = 0;
            last_bad_reps = 0;
        } else if n == last_bad_len && fifo[..n] == last_bad[..n] {
            last_bad_reps += 1;
        } else {
            // Truncated or full-length? The radio is programmed to collect
            // exactly CAPTURE_BYTES, so anything shorter was read out by the
            // RX_TIMEOUT path: the burst stopped mid-capture. That is the same
            // burst-tail phenomenon as `short`, merely long enough to clear
            // MIN_CHIP_BYTES, and it is not evidence of anything wrong — a
            // healthy 100%-yield receiver produced a dozen a minute, each one a
            // WARN line about a tail it was never going to decode.
            //
            // A **full-length** capture that decodes to nothing is the real
            // signal: the radio filled its FIFO and none of it was a frame.
            let truncated = n < CAPTURE_BYTES as usize;
            if truncated {
                PARTIAL.fetch_add(1, Ordering::Relaxed);
            }
            if last_bad_reps > 1 && !truncated {
                log::warn!("rx: ...previous pattern repeated {last_bad_reps}x");
            }
            // Raw bytes are the whole diagnostic. The ones/zeros balance reads
            // it: nearly all ones is preamble, meaning the radio heard the
            // sensor but the frame fell outside the window (the reason
            // CAPTURE_BYTES is far larger than a frame); nearly all zeros is
            // silence; balanced is modulated traffic we could not parse.
            let ones: u32 = fifo[..n].iter().map(|b| b.count_ones()).sum();
            let pct = ones * 100 / (n as u32 * 8).max(1);
            if truncated {
                log::debug!(
                    "rx: {n}/{CAPTURE_BYTES}-byte partial capture, undecodable ({pct}% ones) \
                     {:02x?}",
                    &fifo[..n]
                );
            } else {
                log::warn!("rx: {n} undecodable bytes ({pct}% ones) {:02x?}", &fifo[..n]);
            }
            last_bad[..n].copy_from_slice(&fifo[..n]);
            last_bad_len = n;
            last_bad_reps = 1;
        }

        radio.start_rx().map_err(|_| Fatal("cc1101 start_rx"))?; // flush + back to RX
    }
}

/// Log and publish one decoded frame. Shared by both dispatch paths above so a
/// frame reported through the fallback cannot drift from the normal one.
fn report(frame: revivint_core::DecodedFrame) {
    if let Some(seed) = frame.announced_seed() {
        log::info!(
            "rx id={:05x} announced seed {seed:#06x} (learned)",
            frame.txid
        );
    } else {
        // `DecodedFrame`'s Display prints only the fields this frame's family
        // actually carries, so a startup beacon does not report `contact=None`
        // and a contact event reads `contact=closed`, not `Some(false)`.
        log::info!("rx {frame}");
    }
    crate::net::report(frame);
}

/// Periodic receive statistics.
///
/// Silence from the sensors is ambiguous, so make it legible: `syncs` counts
/// times the radio matched the sync word and woke us, `frames` counts those that
/// decoded with a valid CRC.
///
/// * `syncs=0` — the radio never fired. Check wiring (GDO0), the antenna, and
///   try the inverted sync word: `VIVINT_SYNC=0x0001`.
/// * `syncs>0, frames=0` — the radio hears bursts but the framing is wrong; the
///   `undecodable bytes` warnings above show what actually arrived. If those
///   payloads never repeat back-to-back, the packet engine is triggering on
///   noise rather than on a sensor — build with `--no-default-features
///   --features sw` to decode from raw edge timings instead.
#[embassy_executor::task]
async fn rx_stats() {
    loop {
        Timer::after(STATS_EVERY).await;
        let (syncs, frames) = (SYNCS.load(Ordering::Relaxed), FRAMES.load(Ordering::Relaxed));
        if syncs == 0 {
            log::info!(
                "rx: no sync matches yet — check GDO0 wiring/antenna, or try VIVINT_SYNC=0x0001"
            );
        } else {
            let captures = CAPTURES.load(Ordering::Relaxed);
            log::info!(
                "rx: {syncs} syncs, {captures} captures, {frames} frames, \
                 {} undecodable, {} partial, {} short, {} overflows",
                captures
                    .saturating_sub(frames)
                    .saturating_sub(SHORT.load(Ordering::Relaxed))
                    .saturating_sub(PARTIAL.load(Ordering::Relaxed)),
                PARTIAL.load(Ordering::Relaxed),
                SHORT.load(Ordering::Relaxed),
                OVERFLOWS.load(Ordering::Relaxed)
            );

            // Reception quality: of the frames we accepted, how many arrived
            // needing nothing done to them. This is the number that moves first
            // when the link degrades — yield stays at 100% long after `clean`
            // starts falling, because the decoder keeps rescuing frames.
            let clean = CLEAN.load(Ordering::Relaxed);
            let (early, phase) = (
                EARLY_TRIGGER.load(Ordering::Relaxed),
                PHASE_SHIFTED.load(Ordering::Relaxed),
            );
            let (flip, shift) = (
                POLARITY_FLIPPED.load(Ordering::Relaxed),
                BIT_SHIFTED.load(Ordering::Relaxed),
            );
            log::info!(
                "rx quality: {clean}/{frames} clean ({}%), corrected: \
                 {early} early-trigger (worst +{} chips), {phase} chip-phase, \
                 {flip} polarity, {shift} bit-offset",
                (clean * 100).checked_div(frames).unwrap_or(0),
                WORST_SYNC_AT.load(Ordering::Relaxed),
            );
            // A *majority* needing a polarity flip means the compiled-in sync
            // word is inverted for this radio — a configuration error, and one
            // worth saying out loud because everything still decodes, just via
            // the slower path. An occasional flip is a marginal slicer and is
            // already visible in the counts above, so it is not worth a warning.
            if frames > 0 && flip * 2 > frames {
                log::warn!(
                    "rx quality: {flip}/{frames} frames needed a polarity flip — the \
                     compiled-in sync word is probably inverted for this radio; try the \
                     other one (see cc1101::config::SYNC_WORD_CHIPS)"
                );
            }
        }
    }
}
