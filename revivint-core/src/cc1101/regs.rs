// CC1101 register addresses, strobes, and status registers (subset we use).

// Configuration registers (0x00..0x2E).
pub const IOCFG2: u8 = 0x00;
pub const IOCFG1: u8 = 0x01;
pub const IOCFG0: u8 = 0x02;
pub const FIFOTHR: u8 = 0x03;
pub const SYNC1: u8 = 0x04;
pub const SYNC0: u8 = 0x05;
pub const PKTLEN: u8 = 0x06;
pub const PKTCTRL1: u8 = 0x07;
pub const PKTCTRL0: u8 = 0x08;
pub const ADDR: u8 = 0x09;
pub const CHANNR: u8 = 0x0a;
pub const FSCTRL1: u8 = 0x0b;
pub const FSCTRL0: u8 = 0x0c;
pub const FREQ2: u8 = 0x0d;
pub const FREQ1: u8 = 0x0e;
pub const FREQ0: u8 = 0x0f;
pub const MDMCFG4: u8 = 0x10;
pub const MDMCFG3: u8 = 0x11;
pub const MDMCFG2: u8 = 0x12;
pub const MDMCFG1: u8 = 0x13;
pub const MDMCFG0: u8 = 0x14;
pub const DEVIATN: u8 = 0x15;
pub const MCSM2: u8 = 0x16;
pub const MCSM1: u8 = 0x17;
pub const MCSM0: u8 = 0x18;
pub const FOCCFG: u8 = 0x19;
pub const BSCFG: u8 = 0x1a;
pub const AGCCTRL2: u8 = 0x1b;
pub const AGCCTRL1: u8 = 0x1c;
pub const AGCCTRL0: u8 = 0x1d;
pub const FREND1: u8 = 0x21;
pub const FREND0: u8 = 0x22;
pub const FSCAL3: u8 = 0x23;
pub const FSCAL2: u8 = 0x24;
pub const FSCAL1: u8 = 0x25;
pub const FSCAL0: u8 = 0x26;
pub const TEST2: u8 = 0x2c;
pub const TEST1: u8 = 0x2d;
pub const TEST0: u8 = 0x2e;

// Command strobes (0x30..0x3D).
pub const SRES: u8 = 0x30;
pub const SFSTXON: u8 = 0x31;
pub const SXOFF: u8 = 0x32;
pub const SCAL: u8 = 0x33;
pub const SRX: u8 = 0x34;
pub const STX: u8 = 0x35;
pub const SIDLE: u8 = 0x36;
pub const SFRX: u8 = 0x3a;
pub const SFTX: u8 = 0x3b;
pub const SNOP: u8 = 0x3d;

// Status registers (read with burst bit set).
pub const PARTNUM: u8 = 0x30;
pub const VERSION: u8 = 0x31;
pub const RSSI: u8 = 0x34;
pub const MARCSTATE: u8 = 0x35;
pub const RXBYTES: u8 = 0x3b;

// FIFO.
pub const FIFO: u8 = 0x3f;

// Header bits.
pub const READ: u8 = 0x80;
pub const BURST: u8 = 0x40;
