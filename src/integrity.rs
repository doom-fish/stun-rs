//! `MESSAGE-INTEGRITY` (RFC 5389) and `MESSAGE-INTEGRITY-SHA256` (RFC 8489).
//!
//! Both attributes carry an HMAC computed over the STUN message **with the
//! header length field temporarily set as if the integrity attribute were the
//! last attribute in the message** (RFC 5389 §15.4). This module owns that
//! length-trickery so the rest of the codec can stay simple.
//!
//! * `MESSAGE-INTEGRITY` uses HMAC-SHA1 (20-byte value) via CommonCrypto.
//! * `MESSAGE-INTEGRITY-SHA256` uses HMAC-SHA256 (32-byte value) via CryptoKit.

use cryptokit::hmac::hmac_sha256 as ck_hmac_sha256;
use cryptokit::symmetric::SymmetricKey;

use crate::ffi::commoncrypto;

/// Byte length of an HMAC-SHA1 value.
pub const SHA1_LEN: usize = 20;

/// Byte length of an HMAC-SHA256 value.
pub const SHA256_LEN: usize = 32;

/// Compute `HMAC-SHA1(key, data)`.
#[must_use]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_LEN] {
    commoncrypto::hmac_sha1(key, data)
}

/// Compute `HMAC-SHA256(key, data)`.
///
/// CryptoKit's HMAC bridge never fails for valid inputs, but it returns a
/// `Result`; if the bridge ever reports an error we fall back to an all-zero
/// MAC, which will simply fail any subsequent verification.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_LEN] {
    let symmetric = SymmetricKey::from_bytes(key.to_vec());
    let mut out = [0u8; SHA256_LEN];
    if let Ok(mac) = ck_hmac_sha256(data, &symmetric) {
        if mac.len() == SHA256_LEN {
            out.copy_from_slice(&mac);
        }
    }
    out
}

/// Constant-time comparison of two byte slices of equal meaning.
///
/// Used when verifying integrity attributes so that verification time does not
/// leak how many leading bytes matched.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
