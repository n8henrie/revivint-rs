// Register math + two 345 MHz OOK profiles: software-decode (raw async data on
// GDO0) and hardware-assisted (Manchester + sync-word + packet FIFO).
//
// These are *starting points*. OOK RX on real hardware always needs a little
// tuning of the AGC/bandwidth registers against your antenna and RF
// environment; the values here follow TI's SmartRF OOK guidance. The timing is
// measured from this project's raw I/Q captures — see `crate::manchester`.

use super::regs::*;

/// Capacity of a register-profile buffer. Sized with headroom: the profiles
/// have grown as tuning fields moved out of magic constants, and an overflow
/// here shows up as a panic in a slice index rather than anything legible.
pub const REG_TABLE: usize = 40;

/// Typical CC1101 crystal.
pub const XTAL_HZ: u32 = 26_000_000;
/// Carrier for these sensors.
pub const FREQ_HZ: u32 = 345_000_000;
/// Manchester chip rate (the CC1101 "data rate" is the chip rate; one data bit =
/// two chips).
///
/// Re-exported from [`crate::manchester::CHIP_BAUD`] so the radio and the
/// software decoder cannot disagree. They previously held independent constants
/// — 6410 here, 156 us there — and both were 15% away from the transmitter's
/// measured timing, which broke the hardware path's bit synchroniser.
pub use crate::manchester::CHIP_BAUD;

/// FREQ2/FREQ1/FREQ0 for `freq_hz`: word = freq * 2^16 / xtal (24-bit).
pub fn freq_regs(freq_hz: u32, xtal_hz: u32) -> (u8, u8, u8) {
    let word = ((freq_hz as u64) << 16) / xtal_hz as u64;
    (
        ((word >> 16) & 0xff) as u8,
        ((word >> 8) & 0xff) as u8,
        (word & 0xff) as u8,
    )
}

/// Inverse of [`freq_regs`], for tests / sanity checks.
pub fn freq_from_regs(f2: u8, f1: u8, f0: u8, xtal_hz: u32) -> u32 {
    let word = ((f2 as u64) << 16) | ((f1 as u64) << 8) | f0 as u64;
    ((word * xtal_hz as u64) >> 16) as u32
}

/// DRATE_E (exponent, MDMCFG4 low nibble) and DRATE_M (mantissa, MDMCFG3) for a
/// target baud: Rdata = (256 + M) * 2^E / 2^28 * xtal.
pub fn drate_regs(baud: u32, xtal_hz: u32) -> (u8, u8) {
    let xtal = xtal_hz as u64;
    // exponent: floor(log2(baud * 2^20 / xtal))
    let mut exp = 0u32;
    // ratio = baud * 2^28 / xtal, find E so that mantissa lands in [0,255]
    while exp < 16 {
        let next = exp + 1;
        // baud for mantissa 0 at exponent `next`: 256 * 2^next * xtal / 2^28
        let r_next = (xtal << next) >> 20;
        if r_next > baud as u64 {
            break;
        }
        exp = next;
    }
    // mantissa = baud * 2^28 / (xtal * 2^E) - 256
    let m = ((baud as u64) << (28 - exp)) / xtal;
    let mantissa = m.saturating_sub(256).min(255) as u8;
    (exp as u8, mantissa)
}

/// Inverse of [`drate_regs`].
pub fn baud_from_regs(exp: u8, mantissa: u8, xtal_hz: u32) -> u32 {
    let r = (256u64 + mantissa as u64) * (1u64 << exp) * xtal_hz as u64;
    (r >> 28) as u32
}

// ---- OOK squelch -------------------------------------------------------------
//
// The single hardest part of OOK RX on a CC1101: there is no carrier to lock to,
// so the AGC has nothing to hold it down between bursts. Left alone it winds the
// gain up during silence until the slicer starts turning the **noise floor**
// into bits. The packet engine then dutifully finds "sync" inside that noise and
// hands you a full PKTLEN of garbage — differing every time, because it is
// static rather than a sensor (a real sensor repeats its frame several times per
// event). The two knobs below are what stop that, and both cost the MCU nothing:
// they are evaluated in the radio.
//
// This mirrors what a known-working software receiver has to do for the same
// sensors: `rtl_433_ESP` (as used by OpenMQTTGateway) measures an average RSSI
// floor and ignores everything within a delta of it (`RSSI_THRESHOLD=12`). Doing
// it in the CC1101 keeps the ESP32 asleep instead of timing every noise edge.

/// `AGCCTRL2.MAX_DVGA_GAIN` (bits 7:6) — how many of the highest digital gain
/// steps the AGC may **not** use. `0` lets it gain all the way up into the noise;
/// `1`–`3` progressively deafen it to weak signals, which for OOK is the point.
pub const MAX_DVGA_GAIN: u8 = 2;

/// `AGCCTRL2.MAGN_TARGET` (bits 2:0) — the AGC's target channel amplitude.
/// `3` = 33 dB, TI's usual ASK/OOK starting point.
pub const MAGN_TARGET: u8 = 3;

/// `AGCCTRL1.CARRIER_SENSE_ABS_THR` (bits 3:0) — the absolute carrier-sense
/// threshold, a 4-bit two's-complement value in dB **relative to
/// [`MAGN_TARGET`]**. Positive means "a burst must be this far above the AGC
/// target before it counts as a carrier", which is exactly the squelch OOK needs.
/// Range −8..=+7; `0` disables the absolute threshold.
pub const CARRIER_SENSE_ABS_THR: i8 = 6;

/// RX channel-bandwidth nibble for `MDMCFG4` (bits 7:6 `CHANBW_E`, 5:4 `CHANBW_M`).
///
/// `BW = f_xosc / (8 * (4 + CHANBW_M) * 2^CHANBW_E)`, so at a 26 MHz crystal:
///
/// | nibble | `E` | `M` | bandwidth |
/// |---|---|---|---|
/// | `0x8` | 2 | 0 | **203 kHz** |
/// | `0xC` | 3 | 0 | 102 kHz |
/// | `0xF` | 3 | 3 | 58 kHz |
///
/// **102 kHz.** The signal itself needs far less: OOK at a ~7.5 kchip/s rate
/// occupies a few tens of kHz. The filter was previously left at 203 kHz because
/// the chip rate was unknown and a wide filter is forgiving — but it also admits
/// ~2x the noise power, and noise is what makes the packet engine trigger on
/// nothing. Now that the timing is measured, the extra width buys nothing.
///
/// Not narrowed further: at 345 MHz a +-50 ppm crystal error on each end is
/// +-17 kHz, and this module's crystal is unverified. 102 kHz keeps generous
/// margin over that; 58 kHz would not.
pub const CHANBW: u8 = 0xc;

/// `FREND1` matching [`CHANBW`]. TI's OOK design note (SWRA215) pairs the wide
/// (203 kHz) setting with `0xB6` and the narrow (58 kHz) one with `0x56`; at the
/// 102 kHz midpoint `0xB6` remains the safer (higher-gain) choice.
pub const FREND1_VAL: u8 = 0xb6;

/// `FIFOTHR` matching [`CHANBW`]: SWRA215 uses `0x47` across its OOK settings.
pub const FIFOTHR_VAL: u8 = 0x47;

/// `AGCCTRL0` — AGC dynamics: `HYST_LEVEL(7:6) | WAIT_TIME(5:4) |
/// AGC_FREEZE(3:2) | FILTER_LENGTH(1:0)`.
///
/// This is the knob for the "first packet of every burst is garbage" symptom.
/// The sensor sends ~6 repeats 129 ms apart, so the radio sits in ~104 ms of
/// silence between them; the AGC drifts up chasing noise during the gap and is
/// still settling when the next packet starts. Shorter `WAIT_TIME` and
/// `FILTER_LENGTH` settle faster; `AGC_FREEZE` can stop it adapting after sync.
///
/// `0x91` is TI's OOK starting point (SWRA215); `0x92` is its other suggestion.
pub const AGCCTRL0_VAL: u8 = 0x91;

/// Assemble `AGCCTRL2` from its fields (`MAX_DVGA_GAIN`, `MAX_LNA_GAIN` = 0,
/// `MAGN_TARGET`).
pub const fn agcctrl2(max_dvga_gain: u8, magn_target: u8) -> u8 {
    ((max_dvga_gain & 0x03) << 6) | (magn_target & 0x07)
}

/// Assemble `AGCCTRL1` from a signed absolute carrier-sense threshold in dB.
/// `CARRIER_SENSE_REL_THR` and `AGC_LNA_PRIORITY` stay 0.
pub const fn agcctrl1(abs_thr_db: i8) -> u8 {
    (abs_thr_db as u8) & 0x0f
}

/// Recover the signed `CARRIER_SENSE_ABS_THR` from an `AGCCTRL1` value.
pub const fn carrier_sense_abs_thr(agcctrl1: u8) -> i8 {
    let n = agcctrl1 & 0x0f;
    // 4-bit two's complement -> i8
    if n & 0x08 != 0 {
        (n as i8) - 16
    } else {
        n as i8
    }
}

/// The squelch settings as one bundle, so a caller can sweep them on hardware
/// without editing this file. [`SQUELCH`] is the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Squelch {
    /// [`MAX_DVGA_GAIN`] (0..=3).
    pub max_dvga_gain: u8,
    /// [`MAGN_TARGET`] (0..=7).
    pub magn_target: u8,
    /// `AGCCTRL1.CARRIER_SENSE_ABS_THR` (-8..=7).
    ///
    /// **`0` does not disable it** — 0 puts the threshold *at* `MAGN_TARGET`.
    /// The disabling value is `-8`. To run with no carrier-sense qualification
    /// at all, set [`sync_mode`](Self::sync_mode) to
    /// [`SYNC_MODE_16_16`] rather than relying on this field.
    pub abs_thr_db: i8,
    /// Raw `AGCCTRL0`: `HYST_LEVEL(7:6) | WAIT_TIME(5:4) | AGC_FREEZE(3:2) |
    /// FILTER_LENGTH(1:0)`. See [`AGCCTRL0_VAL`]; the low two bits are the
    /// OOK/ASK decision boundary and are the field to sweep first.
    pub agcctrl0: u8,
    /// RX channel-bandwidth nibble; see [`CHANBW`].
    pub chanbw: u8,
    /// `BSCFG` — bit-synchroniser configuration.
    ///
    /// **Previously never programmed**, leaving the reset value `0x6C` whose
    /// `BS_LIMIT` field is 0: data-rate offset compensation *disabled*. That
    /// matters here because the measured chip period spans 133-135 us while the
    /// radio is programmed for one fixed rate. `0x6D` keeps the same loop gains
    /// and allows +-3.125% of rate offset.
    pub bscfg: u8,
    /// `MDMCFG3` (DRATE_M mantissa) with exponent 8. Sweeping `0x2b..=0x2f`
    /// spans ~134.9 to ~133.1 us per chip, bracketing every measurement taken.
    pub drate_m: u8,
    /// `MDMCFG2.SYNC_MODE` (0..=7). Use [`SYNC_MODE_16_16`] for diagnosis —
    /// it asks only whether bit sync and sync-word matching work — and
    /// [`SYNC_MODE_16_16_CS`] once that is proven, to suppress false triggers.
    pub sync_mode: u8,
    /// `FIFOTHR` high nibble selects close-in RX attenuation: `0x4`=0 dB,
    /// `0x5`=6 dB, `0x6`=12 dB, `0x7`=18 dB. The low nibble is the FIFO
    /// threshold. Attenuation is the direct control for close-range overload,
    /// which is known to affect this setup.
    pub fifothr: u8,
}

/// `SYNC_MODE` = 2: exact 16-of-16 sync word, **no** carrier-sense
/// qualification. The right choice while diagnosing, because it asks one
/// question only.
pub const SYNC_MODE_16_16: u8 = 2;

/// `SYNC_MODE` = 6: 16-of-16 **and** carrier sense above threshold. A
/// false-trigger control to add once reception is proven, not a diagnostic
/// baseline.
pub const SYNC_MODE_16_16_CS: u8 = 6;

/// `BSCFG` with `BS_LIMIT` = 1 (+-3.125% data-rate offset compensation),
/// other loop gains at their reset values.
pub const BSCFG_PM_3_125: u8 = 0x6d;
/// `BSCFG` reset value: `BS_LIMIT` = 0, i.e. no rate compensation.
pub const BSCFG_NONE: u8 = 0x6c;

/// `MDMCFG3` for the derived [`CHIP_BAUD`]; ~7513 baud, 133.1 us per chip.
pub const DRATE_M_133US: u8 = 0x2f;
/// `MDMCFG3` closest to the raw-I/Q estimate of 134.5 us (~7439 baud).
pub const DRATE_M_134US: u8 = 0x2c;

/// `FIFOTHR` with 0 dB close-in attenuation.
pub const FIFOTHR_ATT_0DB: u8 = 0x47;
/// `FIFOTHR` with 6 dB close-in attenuation.
pub const FIFOTHR_ATT_6DB: u8 = 0x57;
/// `FIFOTHR` with 12 dB close-in attenuation.
pub const FIFOTHR_ATT_12DB: u8 = 0x67;
/// `FIFOTHR` with 18 dB close-in attenuation.
pub const FIFOTHR_ATT_18DB: u8 = 0x77;

/// `FREND1` for the chosen [`Squelch::chanbw`].
///
/// TI's OOK design note (SWRA215/DN022) pairs the wide setting with `0xB6` and
/// the narrow one with `0x56`. Mixing them is incoherent: a bandwidth sweep that
/// changes only `MDMCFG4` is not comparing whole profiles, which is why the
/// earlier 58 kHz row could not be trusted.
pub const fn frend1_for(chanbw: u8) -> u8 {
    // CHANBW_E lives in the top two bits of the nibble; a larger exponent means
    // a narrower filter. 0x8/0xC are the wide/medium settings, 0xF the narrow.
    if chanbw >= 0xe { 0x56 } else { 0xb6 }
}

/// Default squelch: the values documented above.
pub const SQUELCH: Squelch = Squelch {
    max_dvga_gain: MAX_DVGA_GAIN,
    magn_target: MAGN_TARGET,
    abs_thr_db: CARRIER_SENSE_ABS_THR,
    agcctrl0: AGCCTRL0_VAL,
    chanbw: CHANBW,
    // Programmed for the first time: the reset value disables rate compensation.
    bscfg: BSCFG_PM_3_125,
    drate_m: DRATE_M_133US,
    // Diagnosis first: carrier-sense qualification is a false-trigger control to
    // add back once reception is proven, not a baseline.
    sync_mode: SYNC_MODE_16_16,
    fifothr: FIFOTHR_ATT_0DB,
};

/// TI DN022's OOK bring-up baseline, for diagnosis rather than deployment.
///
/// The shipped [`SQUELCH`] is a *deployment squelch*: `AGCCTRL2=0x83` excludes
/// the two highest DVGA settings and `AGCCTRL1=0x06` puts carrier sense 6 dB
/// above `MAGN_TARGET`. Both are outside DN022's recommended range, and both can
/// suppress the very frames being debugged. Start here, prove reception, then
/// add squelch back as a separate step.
pub const SQUELCH_DIAG: Squelch = Squelch {
    max_dvga_gain: 0,          // AGCCTRL2 = 0x04 with MAGN_TARGET 4
    magn_target: 4,
    abs_thr_db: 0,             // AGCCTRL1 = 0x00
    agcctrl0: 0x92,            // DN022's other suggestion; boundary field = 2
    chanbw: 0x8,               // 203 kHz first: removes filter-width uncertainty
    bscfg: BSCFG_PM_3_125,
    drate_m: DRATE_M_133US,
    sync_mode: SYNC_MODE_16_16,
    fifothr: FIFOTHR_ATT_0DB,
};

/// Common register block (frequency, modem rate, OOK modulation, RX setup)
/// shared by both profiles, with an explicit squelch. `out` must hold at least
/// 24 entries.
fn common_squelch(out: &mut [(u8, u8); REG_TABLE], sq: Squelch) -> usize {
    let (f2, f1, f0) = freq_regs(FREQ_HZ, XTAL_HZ);
    // Only the exponent is derived; the mantissa is a tuning field so the rate
    // can be swept around the measured chip period without a code change.
    let (drate_e, _) = drate_regs(CHIP_BAUD, XTAL_HZ);

    // MDMCFG4: channel bandwidth (high nibble) + DRATE_E (low nibble).
    let mdmcfg4 = (sq.chanbw << 4) | (drate_e & 0x0f);

    let block = [
        (FSCTRL1, 0x06),
        (FSCTRL0, 0x00),
        (FREQ2, f2),
        (FREQ1, f1),
        (FREQ0, f0),
        (MDMCFG4, mdmcfg4),
        (MDMCFG3, sq.drate_m),
        // MDMCFG2 is set per-profile (Manchester / sync mode differ).
        (DEVIATN, 0x00), // unused for OOK
        (MCSM0, 0x18),   // auto-calibrate on IDLE->RX, PO_TIMEOUT
        (FOCCFG, 0x00),
        // OOK AGC: TI SmartRF OOK recommendations.
        (AGCCTRL2, agcctrl2(sq.max_dvga_gain, sq.magn_target)),
        (AGCCTRL1, agcctrl1(sq.abs_thr_db)),
        (AGCCTRL0, sq.agcctrl0),
        // Bit-synchroniser rate-offset compensation. Never programmed before.
        (BSCFG, sq.bscfg),
        (FREND1, frend1_for(sq.chanbw)),
        (FREND0, 0x11),
        (FSCAL3, 0xe9),
        (FSCAL2, 0x2a),
        (FSCAL1, 0x00),
        (FSCAL0, 0x1f),
        (TEST2, 0x81),
        (TEST1, 0x35),
        (TEST0, 0x09),
    ];
    out[..block.len()].copy_from_slice(&block);
    block.len()
}

/// `IOCFG0` value that routes `CLK_XOSC/192` to GDO0.
///
/// Every frequency and timing constant in this crate assumes a 26 MHz crystal.
/// Measuring GDO0 with this programmed settles that in one reading:
///
/// | measured | crystal |
/// |---|---|
/// | ~135.417 kHz | 26 MHz — assumption holds |
/// | ~140.625 kHz | 27 MHz — every constant needs rescaling |
pub const IOCFG0_CLK_XOSC_192: u8 = 0x3f;

/// The `IOCFG0` register address, so callers need not import all of `regs`.
pub const fn regs_iocfg0() -> u8 {
    IOCFG0
}

/// Expected GDO0 frequency for a 26 MHz crystal, in Hz.
pub const XTAL_PROBE_HZ_26M: u32 = XTAL_HZ / 192;

/// SOFTWARE-DECODE profile.
///
/// CC1101 acts as a dumb OOK demodulator: asynchronous transparent mode, raw
/// demodulated data out on GDO0, no Manchester, no sync, no packet engine. The
/// firmware times the GDO0 edges (RMT) and does Manchester + framing in
/// software via `revivint_core`. Most flexible, most CPU/awake time.
pub fn profile_software(out: &mut [(u8, u8); REG_TABLE]) -> usize {
    profile_software_tuned(out, SQUELCH)
}

/// [`profile_software`] with an explicit [`Squelch`]. There is no packet engine
/// to gate here, but capping the AGC still matters: it is what stops the slicer
/// manufacturing edges out of the noise floor, which the MCU would otherwise
/// have to time and discard on every burst.
pub fn profile_software_tuned(out: &mut [(u8, u8); REG_TABLE], sq: Squelch) -> usize {
    let mut n = common_squelch(out, sq);
    let extra = [
        // GDO0 = asynchronous serial data output (raw demod). 0x0D = async data.
        (IOCFG0, 0x0d),
        // GDO2 = carrier-sense / RX-active is handy as a wake source. 0x0E = CS.
        (IOCFG2, 0x0e),
        // OOK/ASK (MOD_FORMAT=3), no Manchester, no preamble/sync (SYNC_MODE=0).
        (MDMCFG2, 0x30),
        // Asynchronous serial mode (PKTCTRL0 = 0x30), no CRC, length irrelevant.
        (PKTCTRL0, 0x30),
        (PKTCTRL1, 0x00),
        (MCSM1, 0x30), // stay in RX after RX
    ];
    out[n..n + extra.len()].copy_from_slice(&extra);
    n += extra.len();
    n
}

/// `MDMCFG2` base values. `SYNC_MODE` is supplied per-profile from
/// [`Squelch::sync_mode`] rather than baked in, so a diagnostic run can ask
/// about sync matching alone (mode 2) and a deployment run can add
/// carrier-sense qualification (mode 6) without touching this file.
/// `MDMCFG2` with ASK/OOK + Manchester, `SYNC_MODE` left clear for the caller.
const MDMCFG2_OOK_MANCHESTER: u8 = 0b0011_1000;
/// `MDMCFG2` with ASK/OOK and Manchester **off**, `SYNC_MODE` left clear.
const MDMCFG2_OOK_NO_MANCHESTER: u8 = 0b0011_0000;

/// The whole `SYNC_MODE` field (bits 2:0) of an `MDMCFG2` value.
pub const fn sync_mode(mdmcfg2: u8) -> u8 {
    mdmcfg2 & 0x07
}

/// The sync-word match strength alone (`SYNC_MODE` low 2 bits), ignoring the
/// carrier-sense bit. `2` = the whole 16-bit sync word must match, which is the
/// only setting that aligns the packet engine to the real start of frame — see
/// [`profile_hardware_sync`].
pub const fn sync_match_mode(mdmcfg2: u8) -> u8 {
    mdmcfg2 & 0x03
}

/// Whether `SYNC_MODE` also gates sync detection on carrier sense (its high bit).
/// This is the OOK squelch: see the module notes above [`MAX_DVGA_GAIN`].
pub const fn sync_needs_carrier_sense(mdmcfg2: u8) -> bool {
    mdmcfg2 & 0x04 != 0
}

/// Default sync word: the `0xFFFE` preamble every one of these sensors opens
/// with. Depending on how the CC1101's OOK slicer settles you may instead need
/// its bit-inverse `0x0001` — see [`profile_hardware_sync`].
pub const SYNC_WORD: u16 = 0xfffe;

/// Fixed packet length the radio collects after the sync word, in bytes.
///
/// The **96-bit** family's body (12-byte frame minus the 2 sync bytes) plus
/// [`crate::BODY_SLACK`], so a frame the radio latched onto a few bits early is
/// still captured whole for [`crate::decode_body_aligned`] to re-align.
/// The 64-bit legacy family (5718-style) is shorter, so it arrives with 4 bytes
/// of the following repeat stuck on the end; `revivint_core::decode_body` tries
/// both lengths and lets the CRC pick, which is what lets one radio config
/// receive both sensor families.
///
/// Taken from [`crate::BODY_MAX`] rather than hand-copied, so the radio
/// and the decoder cannot drift apart.
pub const PKT_BODY_LEN: u8 = CAPTURE_BYTES;

/// Bytes the packet engine collects per trigger.
///
/// **Much larger than a frame, deliberately.** These sensors' preamble is a run
/// of `1`s, and one bit error in it looks exactly like the `0xFFFE` sync — so the
/// radio's sync detector fires early, inside the preamble, and a frame-sized
/// capture holds preamble instead of payload (observed: ~93% ones, with the true
/// sync at bit offset 30-60). Capturing well past the trigger means a whole frame
/// follows it, and `revivint_core::for_each_frame_bytes` re-finds the real sync
/// in software. 40 bytes covers the worst observed early trigger plus a full
/// 12-byte frame, and stays inside the CC1101's 64-byte RX FIFO.
pub const CAPTURE_BYTES: u8 = 40;

/// Sync word for the chip-level profile, in the polarity the CC1101 actually
/// produces.
///
/// Derivation: Manchester maps `1 -> 10` and `0 -> 01`, so the last 8 data bits
/// before the body (`0xFE` = seven 1s then a 0) encode to
/// `10 10 10 10 10 10 10 01` = `0xAAA9`. Matching that puts the packet engine
/// exactly at the start of frame with no hardware Manchester involved.
///
/// **But the CC1101's OOK slicer emits the inverse of that logical convention**,
/// so the word to program is `0x5556`. This is measured, not assumed: on the
/// bench `0x5556` decoded 100% of events with 209 frames straight from the
/// packet engine, while `0xAAA9` decoded exactly zero across 209 captures.
///
/// `0xAAA9` is not merely wrong, it is actively harmful — that pattern occurs
/// *inside* the encoded payload, so the radio syncs mid-frame, fills the FIFO
/// from the wrong offset, and produces a stream of confident-looking but
/// undecodable captures.
pub const SYNC_WORD_CHIPS: u16 = 0x5556;

/// The logical-convention polarity, `0xAAA9`. Kept for reference and for a
/// receiver whose slicer is the other way round; see [`SYNC_WORD_CHIPS`].
pub const SYNC_WORD_CHIPS_LOGICAL: u16 = 0xaaa9;

/// Re-exported for continuity; the derivation itself is pure Manchester and
/// lives in [`crate::manchester`], so it is available without this feature.
/// Keeping it here too would have meant `framer` — which is always compiled —
/// depending on the optional radio driver, which is exactly the build break
/// that `cargo check -p revivint-core` (no `--all-features`) caught.
pub use crate::manchester::chips_need_inverting;


/// Bytes of *chips* to capture after the chip-level sync.
///
/// An 80-bit body is 160 chips = 20 bytes exactly, but capturing exactly that is
/// a trap: if the radio's sync lands even one chip early, the body's tail falls
/// off the end and the CRC fails on an otherwise perfect frame. Two spare bytes
/// cover 16 chips of slack.
pub const CAPTURE_CHIP_BYTES: u8 = 22;

/// Diagnostic chip capture length. Long enough to contain a complete frame
/// *after* an early false trigger, so the true sync's offset can be measured
/// before shortening the production capture.
pub const CAPTURE_CHIP_BYTES_DIAG: u8 = 44;

/// CHIP-LEVEL profile: hardware does OOK, bit timing, sync detection and the
/// packet FIFO — but **not** Manchester.
///
/// This is the middle ground between the two extremes, and it exists because
/// hardware Manchester is the one offload that measurably fails here.
///
/// The CC1101's Manchester decoder pairs chips and commits to a data bit with no
/// way to recover: a single mis-sliced chip corrupts a bit, a bit corrupts a
/// byte, and the frame is lost. That is fatal when the OOK slicer's threshold is
/// off-centre (measured: "on" periods ~178 us against "off" ~100 us, where both
/// should be ~133), because the pairing has no tolerance for it.
///
/// Sampling *chips* is far more forgiving: each chip is decided independently at
/// its centre, so a ~30 us edge shift out of a 133 us chip does not flip it. The
/// MCU then runs the same Manchester code as the software path — which searches
/// chip phase and recovers from glitches — over 160 chips per packet, which is
/// nothing compared with timing every edge through the RMT.
///
/// So the radio still does everything it is good at, and software does only the
/// one step it is measurably better at.
pub fn profile_hardware_chips(out: &mut [(u8, u8); REG_TABLE], sync: u16) -> usize {
    profile_hardware_chips_tuned(out, sync, SQUELCH)
}

/// [`profile_hardware_chips`] with the **diagnostic** capture length.
///
/// Split out because the length has to reach `PKTLEN`: allocating a longer
/// buffer in the firmware achieves nothing on its own, and the previous code
/// did exactly that — a 44-byte buffer while the radio was still told 22, so
/// every capture was 22 bytes and the long-capture scanner never saw the data
/// it was written for.
pub fn profile_hardware_chips_diag(
    out: &mut [(u8, u8); REG_TABLE],
    sync: u16,
    sq: Squelch,
) -> usize {
    let n = profile_hardware_chips_tuned(out, sync, sq);
    for e in out[..n].iter_mut() {
        if e.0 == PKTLEN {
            e.1 = CAPTURE_CHIP_BYTES_DIAG;
        }
    }
    n
}

/// [`profile_hardware_chips`] with an explicit [`Squelch`].
pub fn profile_hardware_chips_tuned(out: &mut [(u8, u8); REG_TABLE], sync: u16, sq: Squelch) -> usize {
    let mut n = common_squelch(out, sq);
    let extra = [
        (IOCFG0, 0x06), // asserts on sync, de-asserts at end of packet
        (IOCFG2, 0x00),
        // ASK/OOK, **Manchester OFF**, 16/16 sync + carrier sense.
        (MDMCFG2, MDMCFG2_OOK_NO_MANCHESTER | (sq.sync_mode & 0x07)),
        (SYNC1, (sync >> 8) as u8),
        (SYNC0, (sync & 0xff) as u8),
        (PKTCTRL0, 0x00), // fixed length, no hardware CRC, no whitening
        (PKTLEN, CAPTURE_CHIP_BYTES),
        (PKTCTRL1, 0x00),
        (FIFOTHR, sq.fifothr),
        (MCSM1, 0x3c),
    ];
    out[n..n + extra.len()].copy_from_slice(&extra);
    n += extra.len();
    n
}

/// HARDWARE-ASSISTED profile with the default [`SYNC_WORD`].
pub fn profile_hardware(out: &mut [(u8, u8); REG_TABLE]) -> usize {
    profile_hardware_sync(out, SYNC_WORD)
}

/// HARDWARE-ASSISTED profile.
///
/// Let the CC1101 do as much as possible: OOK + hardware Manchester decode +
/// 16-bit sync word + a fixed-length packet into the RX FIFO. The firmware just
/// reads bytes from the FIFO and calls `revivint_core::decode_body`.
///
/// **Fixed length, not variable.** These sensors send no length byte — the first
/// byte after the sync is the frame type (`0x7a`, `0xd0`, a legacy channel
/// nibble...). In variable-length mode the CC1101 would read that type byte as a
/// length (`0x7a` = 122 > `PKTLEN`) and silently discard every packet, so the
/// MCU would never see a frame. [`PKT_BODY_LEN`] is therefore a fixed count.
///
/// The sync word itself is a parameter because OOK polarity is not knowable in
/// advance: pass [`SYNC_WORD`] (`0xFFFE`) or its inverse `0x0001`. The byte
/// polarity *after* sync needs no calibration — `decode_body_auto` tries both.
pub fn profile_hardware_sync(out: &mut [(u8, u8); REG_TABLE], sync: u16) -> usize {
    profile_hardware_tuned(out, sync, SQUELCH)
}

/// [`profile_hardware_sync`] with an explicit [`Squelch`], so the OOK threshold
/// can be swept on real hardware without a code change.
pub fn profile_hardware_tuned(out: &mut [(u8, u8); REG_TABLE], sync: u16, sq: Squelch) -> usize {
    let mut n = common_squelch(out, sq);
    let extra = [
        // GDO0 asserts on sync received / de-asserts at end of packet (0x06):
        // a clean "packet ready" interrupt for the MCU.
        (IOCFG0, 0x06),
        (IOCFG2, 0x00), // GDO2 = RX FIFO threshold
        // OOK + Manchester + a full 16/16 sync-word match + carrier sense.
        //
        // MOD_FORMAT(6:4)=011 ASK/OOK | MANCHESTER_EN(3)=1 | SYNC_MODE(2:0)=110.
        //
        // The SYNC_MODE high bit (carrier sense) is what keeps the packet engine
        // from "finding" this sync word inside amplified noise between bursts —
        // the failure mode where every packet is a full PKTLEN of bytes that
        // never repeat. See the OOK squelch notes near MAX_DVGA_GAIN.
        //
        // SYNC_MODE **must** be 2 (16/16), not 3 (30/32). 30/32 expects the sync
        // word sent *twice* and accepts a 30-of-32 bit match, so against these
        // sensors' run of preamble ones `FFFF FFFE` scores 31/32 against the
        // expected `FFFE FFFE` — sync fires one bit early, inside the preamble,
        // and the FIFO fills with preamble instead of payload.
        (MDMCFG2, MDMCFG2_OOK_MANCHESTER | (sq.sync_mode & 0x07)),
        (SYNC1, (sync >> 8) as u8),
        (SYNC0, (sync & 0xff) as u8),
        // Fixed length, CRC off (we verify our own CRC), whitening off.
        (PKTCTRL0, 0x00),
        (PKTLEN, PKT_BODY_LEN),
        (PKTCTRL1, 0x00),
        (FIFOTHR, sq.fifothr),
        (MCSM1, 0x3c), // CCA always, back to RX after RX
    ];
    out[n..n + extra.len()].copy_from_slice(&extra);
    n += extra.len();
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freq_word_round_trips_within_a_channel() {
        let (f2, f1, f0) = freq_regs(FREQ_HZ, XTAL_HZ);
        let back = freq_from_regs(f2, f1, f0, XTAL_HZ);
        // CC1101 frequency synthesizer step at 26 MHz xtal is ~397 Hz.
        let err = (back as i64 - FREQ_HZ as i64).unsigned_abs();
        assert!(err < 400, "freq error {err} Hz (regs {f2:02x} {f1:02x} {f0:02x})");
    }

    #[test]
    fn freq_regs_known_value() {
        // 345.0 MHz / 26 MHz: word = 345e6*65536/26e6 = 0x0D44EC
        let (f2, f1, f0) = freq_regs(345_000_000, 26_000_000);
        assert_eq!((f2, f1, f0), (0x0d, 0x44, 0xec));
    }

    #[test]
    fn drate_round_trips_close() {
        let (e, m) = drate_regs(CHIP_BAUD, XTAL_HZ);
        let back = baud_from_regs(e, m, XTAL_HZ);
        let err_pct = ((back as i64 - CHIP_BAUD as i64).abs() as f64) / CHIP_BAUD as f64 * 100.0;
        assert!(err_pct < 2.0, "baud {back} (E={e} M={m}) off by {err_pct:.2}%");
    }

    #[test]
    fn software_profile_is_async_ook() {
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_software(&mut regs);
        let map = |addr: u8| regs[..n].iter().find(|(a, _)| *a == addr).map(|(_, v)| *v);
        assert_eq!(map(MDMCFG2), Some(0x30)); // OOK, no manchester, no sync
        assert_eq!(map(PKTCTRL0), Some(0x30)); // async serial
        assert_eq!(map(IOCFG0), Some(0x0d)); // GDO0 async data out
    }

    #[test]
    fn hardware_profile_enables_manchester_and_sync() {
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware(&mut regs);
        let map = |addr: u8| regs[..n].iter().find(|(a, _)| *a == addr).map(|(_, v)| *v);
        let mdmcfg2 = map(MDMCFG2).expect("MDMCFG2 is configured");
        assert_eq!((mdmcfg2 >> 4) & 0x7, 0b011, "MOD_FORMAT must be ASK/OOK");
        assert_eq!((mdmcfg2 >> 3) & 0x1, 1, "MANCHESTER_EN must be set");
        assert_eq!(map(SYNC1), Some(0xff));
        assert_eq!(map(SYNC0), Some(0xfe));
    }

    #[test]
    fn hardware_profile_requires_a_full_16_of_16_sync_match() {
        // SYNC_MODE 3 (30/32) expects the sync word sent twice and tolerates two
        // wrong bits, so a run of preamble ones (`FFFF FFFE` vs `FFFE FFFE`)
        // scores 31/32 and fires sync one bit early — the FIFO then holds
        // preamble, not payload, and every "frame" decodes as device 0.
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware(&mut regs);
        let mdmcfg2 = regs[..n]
            .iter()
            .find(|(a, _)| *a == MDMCFG2)
            .map(|(_, v)| *v)
            .expect("MDMCFG2 is configured");
        assert_eq!(
            sync_match_mode(mdmcfg2),
            2,
            "sync-word match must be 16/16, not 15/16 or 30/32"
        );
    }

    #[test]
    fn sync_qualification_is_a_profile_field_not_a_baked_in_default() {
        // Diagnosis and deployment want different answers here, so SYNC_MODE
        // comes from the profile. The default is mode 2 (exact 16/16, no
        // carrier sense): while bringing the receiver up, the experiment should
        // ask only whether bit sync and sync matching work. Carrier sense is a
        // false-trigger control to add back once reception is proven — adding it
        // first can suppress the very frames being debugged.
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware(&mut regs);
        let get = |a: u8| regs[..n].iter().find(|(x, _)| *x == a).map(|(_, v)| *v);
        let mdmcfg2 = get(MDMCFG2).expect("MDMCFG2 configured");
        assert_eq!(sync_match_mode(mdmcfg2), 2, "must be exact 16-of-16");
        assert!(
            !sync_needs_carrier_sense(mdmcfg2),
            "default must NOT qualify sync on carrier sense"
        );

        // ...and the deployment setting is reachable through the same field.
        let sq = Squelch { sync_mode: SYNC_MODE_16_16_CS, ..SQUELCH };
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware_tuned(&mut regs, SYNC_WORD, sq);
        let mdmcfg2 = regs[..n]
            .iter()
            .find(|(a, _)| *a == MDMCFG2)
            .map(|(_, v)| *v)
            .expect("MDMCFG2 configured");
        assert!(sync_needs_carrier_sense(mdmcfg2));
        assert_eq!(sync_match_mode(mdmcfg2), 2);
    }

    #[test]
    fn the_expected_chip_polarity_is_derived_from_the_sync_word() {
        // The hardware sync word is the inverted spelling, so this radio's
        // normal, correct case is invert=true. Reporting that as a "correction"
        // made a 100%-yield receiver log `0/228 clean` and warn about its own
        // working configuration.
        assert!(chips_need_inverting(SYNC_WORD_CHIPS), "0x5556 is the inverted spelling");
        assert!(!chips_need_inverting(SYNC_WORD_CHIPS_LOGICAL), "0xaaa9 is as-delivered");
        // Anything that is not a Manchester-encoded 0xFE falls back to
        // as-delivered rather than guessing.
        assert!(!chips_need_inverting(0x0000));
        assert!(!chips_need_inverting(0xffff));
    }

    #[test]
    fn the_diagnostic_profile_actually_programs_the_long_capture() {
        // Allocating a bigger buffer in the firmware is not enough: PKTLEN is
        // what decides how many bytes the radio collects. Previously the two
        // disagreed, so the long-capture scanner never received a long capture.
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware_chips(&mut regs, SYNC_WORD_CHIPS);
        let get = |r: &[(u8, u8)], a: u8| r.iter().find(|(x, _)| *x == a).map(|(_, v)| *v);
        assert_eq!(get(&regs[..n], PKTLEN), Some(CAPTURE_CHIP_BYTES));

        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware_chips_diag(&mut regs, SYNC_WORD_CHIPS, SQUELCH);
        assert_eq!(get(&regs[..n], PKTLEN), Some(CAPTURE_CHIP_BYTES_DIAG));
        assert_eq!(CAPTURE_CHIP_BYTES_DIAG, 44);

        // ...and the diagnostic profile must still honour every tuning field,
        // or a whole sweep silently measures the defaults.
        let sq = Squelch { agcctrl0: 0x93, magn_target: 7, ..SQUELCH };
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware_chips_diag(&mut regs, SYNC_WORD_CHIPS, sq);
        assert_eq!(get(&regs[..n], AGCCTRL0), Some(0x93));
        assert_eq!(get(&regs[..n], AGCCTRL2), Some(agcctrl2(sq.max_dvga_gain, 7)));
    }

    #[test]
    fn bit_synchroniser_rate_compensation_is_programmed() {
        // BSCFG was never written, leaving the reset 0x6C whose BS_LIMIT is 0 —
        // data-rate offset compensation disabled. The measured chip period spans
        // 133-135 us against one programmed rate, so the compensation matters.
        for (label, n, regs) in [
            ("hw", {
                let mut r = [(0u8, 0u8); REG_TABLE];
                let n = profile_hardware(&mut r);
                (n, r)
            }),
            ("chip", {
                let mut r = [(0u8, 0u8); REG_TABLE];
                let n = profile_hardware_chips(&mut r, SYNC_WORD_CHIPS);
                (n, r)
            }),
            ("sw", {
                let mut r = [(0u8, 0u8); REG_TABLE];
                let n = profile_software(&mut r);
                (n, r)
            }),
        ]
        .map(|(l, (n, r))| (l, n, r))
        {
            let got = regs[..n].iter().find(|(a, _)| *a == BSCFG).map(|(_, v)| *v);
            assert_eq!(got, Some(BSCFG_PM_3_125), "{label}: BSCFG must be written");
            assert_ne!(got, Some(BSCFG_NONE), "{label}: BS_LIMIT must not be 0");
        }
    }

    #[test]
    fn front_end_registers_follow_the_selected_bandwidth() {
        // A bandwidth sweep that changes only MDMCFG4 is not comparing whole
        // profiles: TI pairs the wide setting with FREND1=0xB6 and the narrow
        // one with 0x56. The 58 kHz row was previously incoherent.
        for (chanbw, want) in [(0x8u8, 0xb6u8), (0xc, 0xb6), (0xf, 0x56)] {
            let sq = Squelch { chanbw, ..SQUELCH };
            let mut regs = [(0u8, 0u8); REG_TABLE];
            let n = profile_hardware_tuned(&mut regs, SYNC_WORD, sq);
            let get = |a: u8| regs[..n].iter().find(|(x, _)| *x == a).map(|(_, v)| *v);
            assert_eq!(get(MDMCFG4).map(|v| v >> 4), Some(chanbw));
            assert_eq!(get(FREND1), Some(want), "CHANBW {chanbw:#x}");
        }
    }

    #[test]
    fn channel_bandwidth_is_narrow_enough_to_help_and_wide_enough_to_be_safe() {
        // BW = xtal / (8 * (4 + CHANBW_M) * 2^CHANBW_E).
        let e = u32::from((CHANBW >> 2) & 0x3);
        let m = u32::from(CHANBW & 0x3);
        let bw = XTAL_HZ / (8 * (4 + m) * 2u32.pow(e));
        // Comfortably wider than the worst-case combined crystal error at
        // 345 MHz (+-50 ppm each end ~= 35 kHz total), and much narrower than the
        // 203 kHz that was only chosen because the chip rate was unknown.
        assert!(
            (80_000..=130_000).contains(&bw),
            "RX bandwidth {bw} Hz is outside the intended range"
        );
        // And the profile must carry the matching front-end value.
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware(&mut regs);
        let get = |a: u8| regs[..n].iter().find(|(x, _)| *x == a).map(|(_, v)| *v);
        assert_eq!(get(MDMCFG4).map(|v| v >> 4), Some(CHANBW));
        assert_eq!(get(FREND1), Some(FREND1_VAL));
    }

    #[test]
    fn agc_field_helpers_round_trip() {
        assert_eq!(agcctrl2(2, 3), 0b1000_0011);
        assert_eq!(agcctrl2(0, 3), 0x03); // the old hand-written value
        // 4-bit two's complement, both signs
        assert_eq!(carrier_sense_abs_thr(agcctrl1(6)), 6);
        assert_eq!(carrier_sense_abs_thr(agcctrl1(0)), 0);
        assert_eq!(carrier_sense_abs_thr(agcctrl1(-8)), -8);
        assert_eq!(carrier_sense_abs_thr(agcctrl1(7)), 7);
        assert_eq!(agcctrl1(-1), 0x0f);
    }

    #[test]
    fn software_profile_leaves_squelch_to_the_host() {
        // The async path has no packet engine to gate, so SYNC_MODE is 0 there;
        // the AGC caps still apply (they are in the shared block) but the frame
        // decision is the CRC in software.
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_software(&mut regs);
        let mdmcfg2 = regs[..n]
            .iter()
            .find(|(a, _)| *a == MDMCFG2)
            .map(|(_, v)| *v)
            .expect("MDMCFG2 is configured");
        assert_eq!(sync_mode(mdmcfg2), 0);
    }

    #[test]
    fn hardware_profile_uses_fixed_length_not_variable() {
        // These sensors send no length byte: the first byte after sync is the
        // frame type. Variable-length mode (PKTCTRL0 low bits = 01) would read
        // 0x7a as a 122-byte length and discard every packet, so the MCU would
        // never see a frame. Must be fixed (low bits = 00) with PKTLEN = body.
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware(&mut regs);
        let map = |addr: u8| regs[..n].iter().find(|(a, _)| *a == addr).map(|(_, v)| *v);
        let pktctrl0 = map(PKTCTRL0).expect("PKTCTRL0 is configured");
        assert_eq!(pktctrl0 & 0x03, 0x00, "LENGTH_CONFIG must be fixed");
        assert_eq!(pktctrl0 & 0x04, 0x00, "hardware CRC off; we check our own");
        assert_eq!(map(PKTLEN), Some(PKT_BODY_LEN));
    }

    #[test]
    fn hardware_profile_sync_word_is_selectable() {
        // OOK polarity decides whether the sensors' preamble arrives as 0xFFFE
        // or its inverse; both must be configurable without editing the driver.
        let mut regs = [(0u8, 0u8); REG_TABLE];
        let n = profile_hardware_sync(&mut regs, 0x0001);
        let map = |addr: u8| regs[..n].iter().find(|(a, _)| *a == addr).map(|(_, v)| *v);
        assert_eq!(map(SYNC1), Some(0x00));
        assert_eq!(map(SYNC0), Some(0x01));
    }

    #[test]
    fn both_profiles_share_the_same_frequency() {
        let (mut a, mut b) = ([(0u8, 0u8); REG_TABLE], [(0u8, 0u8); REG_TABLE]);
        let na = profile_software(&mut a);
        let nb = profile_hardware(&mut b);
        let get = |regs: &[(u8, u8)], addr: u8| regs.iter().find(|(x, _)| *x == addr).map(|(_, v)| *v);
        for r in [FREQ2, FREQ1, FREQ0] {
            assert_eq!(get(&a[..na], r), get(&b[..nb], r));
        }
    }
}
