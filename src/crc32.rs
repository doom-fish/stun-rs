//! Minimal table-based CRC-32 (ITU-T V.42 / IEEE 802.3 polynomial).
//!
//! STUN's `FINGERPRINT` attribute (RFC 5389 §15.5) is the standard CRC-32 of
//! the message XORed with `0x5354_554e`. We roll a tiny implementation here so
//! the crate does not depend on `crc32fast` or zlib.

/// Reversed CRC-32 polynomial (`0x04C1_1DB7` reflected).
const POLYNOMIAL: u32 = 0xEDB8_8320;

/// Precomputed lookup table for byte-at-a-time CRC-32.
const TABLE: [u32; 256] = build_table();

/// Build the 256-entry CRC-32 lookup table at compile time.
const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                POLYNOMIAL ^ (crc >> 1)
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Compute the CRC-32 checksum of `data`.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = TABLE[index] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn known_vectors() {
        // CRC-32 of the ASCII string "123456789" is 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        // CRC-32 of the empty string is 0.
        assert_eq!(crc32(b""), 0);
    }
}
