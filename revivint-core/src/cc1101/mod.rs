// Minimal `no_std` CC1101 driver for receiving 345 MHz OOK door sensors.
//
// Pairs with the rest of this crate for decoding: [`config::PKT_BODY_LEN`] is the
// fixed packet length that covers both on-air frame families, and the bytes the
// FIFO yields go straight to [`crate::decode_body`].
//
// SPI / chip-select are abstracted behind the tiny [`SpiBus`] / [`OutputPin`]
// traits so this crate has zero external dependencies and the register math
// ([`config`]) is fully host-testable. The firmware provides one-line adapters
// from esp-hal's SPI/GPIO to these traits.

pub mod config;
pub mod regs;

use regs::*;

/// Full-duplex 8-bit SPI transfer (MISO read into the same buffer that supplied
/// MOSI). Matches the shape of `embedded-hal`'s `SpiBus::transfer_in_place`.
pub trait SpiBus {
    type Error;
    fn transfer_in_place(&mut self, words: &mut [u8]) -> Result<(), Self::Error>;
}

/// Approximate RSSI offset for the CC1101 in dB (datasheet §17.3; ~74 dB across
/// the low-data-rate settings used here).
pub const RSSI_OFFSET_DB: i16 = 74;

/// Convert a raw `RSSI` status-register reading to dBm (datasheet §17.3): the
/// register is a signed 8-bit value in half-dB steps, offset by [`RSSI_OFFSET_DB`].
pub const fn rssi_to_dbm(raw: u8) -> i16 {
    let signed = raw as i8 as i16; // two's complement, half-dB units
    signed / 2 - RSSI_OFFSET_DB
}

/// `MARCSTATE` value for IDLE (datasheet section 10.3).
pub const MARC_STATE_IDLE: u8 = 0x01;
/// `MARCSTATE` value for RX.
pub const MARC_STATE_RX: u8 = 0x0d;
/// Bounded spin when waiting for `MARCSTATE`; a state transition is sub-millisecond
/// and this driver has no timer, so a wedged radio must not spin forever.
const MARC_POLL_TRIES: u32 = 64;

/// RX FIFO byte count plus the overflow flag. See [`Cc1101::rx_status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxBytes {
    pub count: u8,
    pub overflow: bool,
}

/// A register that did not read back what was written: `(addr, wrote, read)`.
/// See [`Cc1101::apply_verified`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegMismatch {
    pub addr: u8,
    pub wrote: u8,
    pub read: u8,
}

/// A push-pull output (chip select).
pub trait OutputPin {
    type Error;
    fn set_low(&mut self) -> Result<(), Self::Error>;
    fn set_high(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum Error<S, P> {
    Spi(S),
    Pin(P),
    /// The radio did not reach IDLE when asked, so the FIFO could not be safely
    /// flushed. See [`Cc1101::start_rx`].
    NotIdle,
}

pub struct Cc1101<SPI, CS> {
    spi: SPI,
    cs: CS,
}

/// Upper bound on `RXBYTES` reads in [`Cc1101::rx_status`] while waiting for
/// two consecutive reads to agree. Each read is ~2 bytes of SPI; at the data
/// rates here a byte lands in the FIFO every ~1 ms, far slower than a few SPI
/// transactions, so agreement normally comes on the second read and this cap
/// only matters if the bus or chip is misbehaving.
pub const RXBYTES_MAX_READS: usize = 4;

impl<SPI, CS> Cc1101<SPI, CS>
where
    SPI: SpiBus,
    CS: OutputPin,
{
    pub fn new(spi: SPI, cs: CS) -> Self {
        Self { spi, cs }
    }

    pub fn release(self) -> (SPI, CS) {
        (self.spi, self.cs)
    }

    fn xfer(&mut self, words: &mut [u8]) -> Result<(), Error<SPI::Error, CS::Error>> {
        self.cs.set_low().map_err(Error::Pin)?;
        let r = self.spi.transfer_in_place(words).map_err(Error::Spi);
        // Always raise CS, even on transfer error.
        let cs = self.cs.set_high().map_err(Error::Pin);
        r.and(cs)
    }

    /// Send a command strobe (e.g. [`regs::SRX`]); returns the status byte.
    pub fn strobe(&mut self, cmd: u8) -> Result<u8, Error<SPI::Error, CS::Error>> {
        let mut buf = [cmd];
        self.xfer(&mut buf)?;
        Ok(buf[0])
    }

    pub fn write_reg(&mut self, addr: u8, val: u8) -> Result<(), Error<SPI::Error, CS::Error>> {
        let mut buf = [addr & 0x3f, val];
        self.xfer(&mut buf)
    }

    pub fn read_reg(&mut self, addr: u8) -> Result<u8, Error<SPI::Error, CS::Error>> {
        let mut buf = [(addr & 0x3f) | READ, 0];
        self.xfer(&mut buf)?;
        Ok(buf[1])
    }

    /// Read a status register (needs the burst bit per the datasheet errata).
    pub fn read_status(&mut self, addr: u8) -> Result<u8, Error<SPI::Error, CS::Error>> {
        let mut buf = [(addr & 0x3f) | READ | BURST, 0];
        self.xfer(&mut buf)?;
        Ok(buf[1])
    }

    /// Apply a `(addr, val)` register table, e.g. from [`config::profile_software`].
    pub fn apply(&mut self, table: &[(u8, u8)]) -> Result<(), Error<SPI::Error, CS::Error>> {
        for &(addr, val) in table {
            self.write_reg(addr, val)?;
        }
        Ok(())
    }

    /// Apply a register table and read every entry back, returning the first
    /// register that disagrees.
    ///
    /// Worth doing once at bring-up: a mis-wired SPI bus, a chip held in reset or
    /// a bus speed the module cannot follow all present as "the radio hears
    /// nothing", and are otherwise indistinguishable from a bad antenna or the
    /// wrong frequency. Config registers (`0x00..=0x2e`) read back exactly what
    /// was written, so any mismatch here is a hardware/bus fault, not tuning.
    pub fn apply_verified(
        &mut self,
        table: &[(u8, u8)],
    ) -> Result<Option<RegMismatch>, Error<SPI::Error, CS::Error>> {
        self.apply(table)?;
        for &(addr, wrote) in table {
            let read = self.read_reg(addr)?;
            if read != wrote {
                return Ok(Some(RegMismatch { addr, wrote, read }));
            }
        }
        Ok(None)
    }

    /// `(PARTNUM, VERSION)` — the chip's identity.
    ///
    /// A genuine CC1101 answers `(0x00, 0x14)` (some batches report `0x04`). All
    /// ones or all zeros means the SPI bus is not talking to a chip at all, which
    /// is the first thing to rule out when nothing is received.
    pub fn part_version(&mut self) -> Result<(u8, u8), Error<SPI::Error, CS::Error>> {
        Ok((self.read_status(PARTNUM)?, self.read_status(VERSION)?))
    }

    /// True if [`part_version`](Self::part_version) looks like a real CC1101
    /// rather than a floating bus.
    pub fn probe(&mut self) -> Result<bool, Error<SPI::Error, CS::Error>> {
        let (part, ver) = self.part_version()?;
        Ok(part == 0x00 && ver != 0x00 && ver != 0xff)
    }

    /// Current RSSI in dBm.
    ///
    /// In RX with no transmitter present this reads the **noise floor** — the
    /// single most useful number when debugging OOK reception, because the whole
    /// problem is telling a real burst apart from amplified static. Compare a
    /// quiet reading against one taken while the sensor transmits: if they do not
    /// differ, the radio is not hearing the sensor and no amount of framing or
    /// key configuration will help.
    ///
    /// Uses the datasheet conversion with the usual ~74 dB offset, so treat it as
    /// accurate to a few dB — the *difference* between readings is what matters.
    pub fn rssi_dbm(&mut self) -> Result<i16, Error<SPI::Error, CS::Error>> {
        Ok(rssi_to_dbm(self.read_status(RSSI)?))
    }

    /// Radio state-machine state (`MARCSTATE`), low 5 bits. `0x0d` is RX; if this
    /// is not RX after [`start_rx`](Self::start_rx), the radio never armed.
    pub fn marc_state(&mut self) -> Result<u8, Error<SPI::Error, CS::Error>> {
        Ok(self.read_status(MARCSTATE)? & 0x1f)
    }

    /// SRES soft reset.
    pub fn reset(&mut self) -> Result<(), Error<SPI::Error, CS::Error>> {
        self.strobe(SRES)?;
        Ok(())
    }

    /// Number of bytes available in the RX FIFO, **and whether it overflowed**.
    ///
    /// `RXBYTES` bit 7 is the overflow flag. It matters because GDO0 in
    /// packet-received mode also de-asserts when the receiver enters
    /// `RXFIFO_OVERFLOW` — so an overflow looks exactly like "a packet is ready"
    /// unless this bit is checked, and the bytes read afterwards are garbage.
    ///
    /// # Read twice, trust only agreement
    ///
    /// `RXBYTES` is a live counter the radio updates as bytes shift into the
    /// FIFO, not a snapshot. TI's CC1101 silicon errata (SWRZ020, "SPI read
    /// synchronization") documents that a status register read while the chip
    /// is updating it can return a corrupt value, and gives the workaround used
    /// here: read repeatedly until two consecutive reads agree.
    ///
    /// It matters because the receive loop trusts this count completely — it
    /// burst-reads exactly `count` bytes and has no other way to know where the
    /// real data ends. A count that reads high makes it read past the payload.
    ///
    /// Why this was added: several full-length captures on hardware showed
    /// real bytes followed by a hard run of zeros (`… 66 56 00 00 00 00 00 00
    /// 00`). That shape fits an over-read, but it *also* fits the innocent case
    /// of a burst ending inside the capture window, where a no-carrier OOK
    /// slicer genuinely outputs zeros. The log cannot tell them apart. Closing
    /// the documented race costs one extra 2-byte SPI transaction per capture,
    /// so it is done regardless: if trailing-zero captures persist afterwards,
    /// they are the benign kind.
    ///
    /// Bounded, because the count legitimately changes while a packet is still
    /// arriving. If the reads never settle within [`RXBYTES_MAX_READS`], the
    /// most recent value is returned: it is the freshest, and the caller's
    /// fixed `PKTLEN` and overflow check still bound what can go wrong.
    pub fn rx_status(&mut self) -> Result<RxBytes, Error<SPI::Error, CS::Error>> {
        let mut raw = self.read_status(RXBYTES)?;
        for _ in 1..RXBYTES_MAX_READS {
            let again = self.read_status(RXBYTES)?;
            if again == raw {
                break;
            }
            raw = again;
        }
        Ok(RxBytes {
            count: raw & 0x7f,
            overflow: raw & 0x80 != 0,
        })
    }

    /// Byte count only; see [`rx_status`](Self::rx_status) for the overflow flag.
    pub fn rx_bytes(&mut self) -> Result<u8, Error<SPI::Error, CS::Error>> {
        Ok(self.rx_status()?.count)
    }

    /// Burst-read `out.len()` bytes out of the RX FIFO.
    pub fn read_fifo(&mut self, out: &mut [u8]) -> Result<(), Error<SPI::Error, CS::Error>> {
        // First byte clocks the header, the rest read the FIFO.
        // We do it in two CS-framed transfers to keep buffers small & on-stack.
        self.cs.set_low().map_err(Error::Pin)?;
        let mut hdr = [FIFO | READ | BURST];
        let r1 = self.spi.transfer_in_place(&mut hdr).map_err(Error::Spi);
        let r2 = if r1.is_ok() {
            self.spi.transfer_in_place(out).map_err(Error::Spi)
        } else {
            Ok(())
        };
        let cs = self.cs.set_high().map_err(Error::Pin);
        r1.and(r2).and(cs)
    }

    /// Enter RX, flushing the FIFO first.
    ///
    /// `SFRX` is only legal in `IDLE` or `RXFIFO_OVERFLOW`, and `SIDLE` does not
    /// take effect instantly — firing `SFRX` straight after it can be ignored,
    /// leaving stale bytes in the FIFO that surface as an undecodable "packet"
    /// on the next interrupt. Poll `MARCSTATE` down to IDLE first, bounded so a
    /// wedged radio cannot hang the caller.
    pub fn start_rx(&mut self) -> Result<(), Error<SPI::Error, CS::Error>> {
        self.strobe(SIDLE)?;
        let mut idle = false;
        for _ in 0..MARC_POLL_TRIES {
            if self.marc_state()? == MARC_STATE_IDLE {
                idle = true;
                break;
            }
        }
        // Fail closed. `SFRX` is only legal in IDLE/RXFIFO_OVERFLOW; issuing it
        // anyway is silently ignored, leaving stale bytes in the FIFO that
        // surface later as an inexplicable "undecodable packet". Reporting the
        // state failure keeps that from masquerading as an RF problem.
        if !idle {
            return Err(Error::NotIdle);
        }
        self.strobe(SFRX)?;
        self.strobe(SRX)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recording SPI that echoes a programmable MISO sequence and logs MOSI.
    #[derive(Default)]
    struct FakeSpi {
        mosi_log: std::vec::Vec<u8>,
        miso: std::collections::VecDeque<u8>,
    }
    impl SpiBus for FakeSpi {
        type Error = ();
        fn transfer_in_place(&mut self, words: &mut [u8]) -> Result<(), ()> {
            for w in words.iter_mut() {
                self.mosi_log.push(*w);
                *w = self.miso.pop_front().unwrap_or(0);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakePin {
        states: std::vec::Vec<bool>,
    }
    impl OutputPin for FakePin {
        type Error = ();
        fn set_low(&mut self) -> Result<(), ()> {
            self.states.push(false);
            Ok(())
        }
        fn set_high(&mut self) -> Result<(), ()> {
            self.states.push(true);
            Ok(())
        }
    }

    #[test]
    fn rssi_converts_per_datasheet() {
        // Negative half-dB readings are the common case (noise floor / weak RX).
        assert_eq!(rssi_to_dbm(0x00), -74); //   0 -> 0/2 - 74
        assert_eq!(rssi_to_dbm(0x80), -138); // -128 -> -64 - 74
        assert_eq!(rssi_to_dbm(0xff), -74); //   -1 -> 0 (trunc) - 74
        // A strong local burst reads well above the floor: that *gap* is the
        // whole diagnostic when deciding signal vs. amplified static.
        assert!(rssi_to_dbm(0x50) > rssi_to_dbm(0x90));
    }

    #[test]
    fn apply_verified_reports_the_first_mismatching_register() {
        // Read-back proves the bus actually carried the config. Feed a MISO
        // stream where the second register reads back wrong.
        let mut spi = FakeSpi::default();
        // two writes (2 bytes each, MISO ignored), then two read_reg (2 bytes each)
        spi.miso.extend([0, 0, 0, 0]); // write phase
        spi.miso.extend([0, 0xaa]); // read_reg(0x10) -> 0xaa (matches)
        spi.miso.extend([0, 0x00]); // read_reg(0x11) -> 0x00 (we wrote 0xbb)
        let mut radio = Cc1101::new(spi, FakePin::default());
        let bad = radio
            .apply_verified(&[(0x10, 0xaa), (0x11, 0xbb)])
            .unwrap();
        assert_eq!(bad, Some(RegMismatch { addr: 0x11, wrote: 0xbb, read: 0x00 }));
    }

    #[test]
    fn apply_verified_is_quiet_when_every_register_reads_back() {
        let mut spi = FakeSpi::default();
        spi.miso.extend([0, 0, 0, 0]); // write phase
        spi.miso.extend([0, 0xaa]);
        spi.miso.extend([0, 0xbb]);
        let mut radio = Cc1101::new(spi, FakePin::default());
        assert_eq!(
            radio.apply_verified(&[(0x10, 0xaa), (0x11, 0xbb)]).unwrap(),
            None
        );
    }

    #[test]
    fn probe_rejects_a_floating_bus() {
        // All-ones (no chip / MISO pulled high) and all-zeros must not pass.
        for (part, ver) in [(0xff, 0xff), (0x00, 0x00), (0x00, 0xff)] {
            let mut spi = FakeSpi::default();
            spi.miso.extend([0, part, 0, ver]);
            let mut radio = Cc1101::new(spi, FakePin::default());
            assert!(!radio.probe().unwrap(), "part={part:#04x} ver={ver:#04x}");
        }
        // A real CC1101 answers PARTNUM=0x00, VERSION=0x14.
        let mut spi = FakeSpi::default();
        spi.miso.extend([0, 0x00, 0, 0x14]);
        let mut radio = Cc1101::new(spi, FakePin::default());
        assert!(radio.probe().unwrap());
    }

    #[test]
    fn write_reg_sends_addr_and_value_masked() {
        let mut dev = Cc1101::new(FakeSpi::default(), FakePin::default());
        dev.write_reg(0x8d /* should mask to 0x0d */, 0x44).unwrap();
        let (spi, pin) = dev.release();
        assert_eq!(spi.mosi_log, vec![0x0d, 0x44]);
        // CS toggled low then high exactly once.
        assert_eq!(pin.states, vec![false, true]);
    }

    #[test]
    fn read_reg_sets_read_bit_and_returns_miso() {
        let mut spi = FakeSpi::default();
        spi.miso.extend([0x00, 0x14]); // status byte, then value
        let mut dev = Cc1101::new(spi, FakePin::default());
        let v = dev.read_reg(VERSION).unwrap();
        assert_eq!(v, 0x14);
        let (spi, _) = dev.release();
        assert_eq!(spi.mosi_log[0], VERSION | READ);
    }

    #[test]
    fn read_status_uses_burst_bit() {
        let mut spi = FakeSpi::default();
        // Two agreeing RXBYTES reads (see rx_status: it reads until agreement).
        spi.miso.extend([0x00, 0x0c, 0x00, 0x0c]);
        let mut dev = Cc1101::new(spi, FakePin::default());
        let n = dev.rx_bytes().unwrap();
        assert_eq!(n, 0x0c);
        let (spi, _) = dev.release();
        assert_eq!(spi.mosi_log[0], RXBYTES | READ | BURST);
    }

    #[test]
    fn rx_status_waits_for_two_agreeing_reads() {
        // Errata SWRZ020: a read that races the chip's own update can return a
        // wrong count. Here the first read is corrupt (0x16), then the counter
        // settles at 0x0c. Trusting the first read would burst-read 22 bytes
        // from a FIFO holding 12 — the over-read this guards against.
        let mut spi = FakeSpi::default();
        spi.miso.extend([0x00, 0x16, 0x00, 0x0c, 0x00, 0x0c]);
        let mut dev = Cc1101::new(spi, FakePin::default());
        let st = dev.rx_status().unwrap();
        assert_eq!(st.count, 0x0c, "must not trust the unconfirmed first read");
        assert!(!st.overflow);
        let (spi, _) = dev.release();
        assert_eq!(spi.mosi_log.len(), 6, "three reads: corrupt, then two agreeing");
    }

    #[test]
    fn rx_status_is_bounded_when_the_count_never_settles() {
        // A FIFO still filling can change on every read. The loop must still
        // return, with the freshest value, rather than spin.
        let mut spi = FakeSpi::default();
        for n in 1..=RXBYTES_MAX_READS as u8 {
            spi.miso.extend([0x00, n]);
        }
        let mut dev = Cc1101::new(spi, FakePin::default());
        let st = dev.rx_status().unwrap();
        assert_eq!(st.count, RXBYTES_MAX_READS as u8, "freshest read wins");
        let (spi, _) = dev.release();
        assert_eq!(spi.mosi_log.len(), RXBYTES_MAX_READS * 2);
    }

    #[test]
    fn apply_software_profile_writes_every_register() {
        let mut table = [(0u8, 0u8); config::REG_TABLE];
        let n = config::profile_software(&mut table);
        let mut dev = Cc1101::new(FakeSpi::default(), FakePin::default());
        dev.apply(&table[..n]).unwrap();
        let (spi, _) = dev.release();
        assert_eq!(spi.mosi_log.len(), n * 2);
        // first written pair is the first table entry (addr masked, value)
        assert_eq!(spi.mosi_log[0], table[0].0 & 0x3f);
        assert_eq!(spi.mosi_log[1], table[0].1);
    }

    #[test]
    fn read_fifo_emits_burst_header_then_reads() {
        let mut spi = FakeSpi::default();
        spi.miso.extend([0x00]); // header response
        spi.miso.extend([0xff, 0xfe, 0x7a]); // fifo bytes
        let mut dev = Cc1101::new(spi, FakePin::default());
        let mut out = [0u8; 3];
        dev.read_fifo(&mut out).unwrap();
        assert_eq!(out, [0xff, 0xfe, 0x7a]);
        let (spi, _) = dev.release();
        assert_eq!(spi.mosi_log[0], FIFO | READ | BURST);
    }

    #[test]
    fn rx_status_preserves_the_overflow_flag() {
        // RXBYTES bit 7 is overflow. GDO0 de-asserts on overflow as well as on
        // packet-received, so masking this bit away made an overflow look like a
        // ready packet — and the bytes read afterwards are garbage.
        let mut spi = FakeSpi::default();
        spi.miso.extend([0, 0x80 | 12, 0, 0x80 | 12]); // two agreeing reads
        let mut radio = Cc1101::new(spi, FakePin::default());
        let st = radio.rx_status().unwrap();
        assert_eq!(st.count, 12);
        assert!(st.overflow);

        let mut spi = FakeSpi::default();
        spi.miso.extend([0, 12, 0, 12]);
        let mut radio = Cc1101::new(spi, FakePin::default());
        let st = radio.rx_status().unwrap();
        assert_eq!((st.count, st.overflow), (12, false));
    }

    #[test]
    fn start_rx_fails_closed_when_idle_is_never_reached() {
        // A radio stuck out of IDLE must be reported, not papered over: SFRX is
        // ignored outside IDLE, and the stale FIFO it leaves behind shows up
        // later as an unexplained bad packet.
        let mut spi = FakeSpi::default();
        spi.miso.extend([0]); // SIDLE
        for _ in 0..(MARC_POLL_TRIES + 4) {
            spi.miso.extend([0, 0x0d]); // never IDLE
        }
        let mut radio = Cc1101::new(spi, FakePin::default());
        assert!(matches!(radio.start_rx(), Err(Error::NotIdle)));
        assert!(
            !radio.spi.mosi_log.contains(&SFRX),
            "SFRX must not be issued outside IDLE"
        );
    }

    #[test]
    fn start_rx_waits_for_idle_before_flushing() {
        // SFRX is only legal in IDLE/RXFIFO_OVERFLOW. Report "not idle yet" once,
        // then IDLE, and assert the flush strobe came after the state settled.
        let mut spi = FakeSpi::default();
        spi.miso.extend([0]); // SIDLE strobe
        spi.miso.extend([0, 0x0d]); // MARCSTATE -> still RX
        spi.miso.extend([0, MARC_STATE_IDLE]); // MARCSTATE -> IDLE
        spi.miso.extend([0, 0]); // SFRX, SRX
        let mut radio = Cc1101::new(spi, FakePin::default());
        radio.start_rx().unwrap();

        let log = &radio.spi.mosi_log;
        let sidle = log.iter().position(|&b| b == SIDLE).expect("SIDLE sent");
        let sfrx = log.iter().position(|&b| b == SFRX).expect("SFRX sent");
        let srx = log.iter().position(|&b| b == SRX).expect("SRX sent");
        assert!(sidle < sfrx && sfrx < srx, "strobe order: {log:02x?}");
        // A MARCSTATE read must sit between SIDLE and SFRX.
        let marc = (MARCSTATE & 0x3f) | READ | BURST;
        assert!(
            log[sidle..sfrx].contains(&marc),
            "no MARCSTATE poll before SFRX: {log:02x?}"
        );
    }
}