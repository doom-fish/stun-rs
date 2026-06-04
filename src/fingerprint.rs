//! STUN `FINGERPRINT` attribute (RFC 5389 §15.5).
//!
//! The fingerprint value is the CRC-32 of the STUN message — header plus all
//! preceding attributes, with the header length field already set to include
//! the 8-byte `FINGERPRINT` attribute itself — XORed with the constant
//! `0x5354_554e` (the ASCII string `"STUN"`).

use crate::crc32::crc32;

/// XOR constant applied to the CRC-32 to form the `FINGERPRINT` value.
pub const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// Compute the `FINGERPRINT` value over an already-serialized prefix.
///
/// `prefix` must be the full STUN message up to (but not including) the
/// `FINGERPRINT` attribute, with the header length field already adjusted to
/// account for the trailing 8-byte `FINGERPRINT` attribute.
#[must_use]
pub fn fingerprint(prefix: &[u8]) -> u32 {
    crc32(prefix) ^ FINGERPRINT_XOR
}
