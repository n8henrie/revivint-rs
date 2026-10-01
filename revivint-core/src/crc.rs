//! CRC-16, MSB-first, no reflection (firmware `crc16_8050` @ 0xf92e, table @ 0xe02c).

/// Generic MSB-first CRC-16 with `init` and no reflection / no xorout.
pub fn crc16(data: &[u8], poly: u16, init: u16) -> u16 {
    let mut crc = init;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ poly
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// The Vivint/2GIG polynomial 0x8050, init 0. Used by all 345 MHz frame families
/// except legacy Honeywell "channel 0x8", which uses 0x8005.
#[inline]
pub fn crc16_8050(data: &[u8]) -> u16 {
    crc16(data, 0x8050, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_64bit_crc_matches_firmware() {
        // fffea630d600af20 : CRC input a630d600 -> af20
        assert_eq!(crc16_8050(&[0xa6, 0x30, 0xd6, 0x00]), 0xaf20);
        // fffea630d6801f10 : CRC input a630d680 -> 1f10
        assert_eq!(crc16_8050(&[0xa6, 0x30, 0xd6, 0x80]), 0x1f10);
    }

    #[test]
    fn d0_startup_crc_matches_firmware() {
        // fffed03a0f4003863139d6d0 : input d03a0f4003863139 -> d6d0
        assert_eq!(
            crc16_8050(&[0xd0, 0x3a, 0x0f, 0x40, 0x03, 0x86, 0x31, 0x39]),
            0xd6d0
        );
    }

    #[test]
    fn seven_a_packed_check_matches_firmware() {
        // fffe7a01d364038631393a4b : input 7a01d3640386313930 -> crc a4b0 -> check12 a4b
        let input = [0x7a, 0x01, 0xd3, 0x64, 0x03, 0x86, 0x31, 0x39, 0x30];
        assert_eq!(crc16_8050(&input), 0xa4b0);
        assert_eq!(crc16_8050(&input) >> 4, 0xa4b);
    }

    #[test]
    fn channel8_variant_poly_differs() {
        // Just exercise the generic poly path; 0x8005 is the legacy Honeywell poly.
        assert_ne!(crc16(&[0x81, 0x00, 0x00, 0x00], 0x8005, 0), crc16_8050(&[0x81, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn empty_is_init() {
        assert_eq!(crc16_8050(&[]), 0);
        assert_eq!(crc16(&[], 0x8050, 0x1234), 0x1234);
    }
}
