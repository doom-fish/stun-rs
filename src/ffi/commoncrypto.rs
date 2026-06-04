//! Thin FFI to Apple's CommonCrypto (`<CommonCrypto/CommonDigest.h>` and
//! `<CommonCrypto/CommonHMAC.h>`).
//!
//! CryptoKit deliberately omits MD5 and HMAC-SHA1 from its safe surface
//! (SHA-1 only appears via the `Insecure` hashing namespace, and there is no
//! HMAC-SHA1 at all). STUN's long-term credential mechanism (RFC 5389 §15.4)
//! needs MD5, and `MESSAGE-INTEGRITY` needs HMAC-SHA1, so we bind the two
//! system functions here. Both symbols live in `libSystem`, which every
//! macOS binary already links against.

use core::ffi::c_void;

/// `CCHmacAlgorithm` value for HMAC-SHA1 (`kCCHmacAlgSHA1`, the first enumerator).
const KCC_HMAC_ALG_SHA1: u32 = 0;

/// Length in bytes of an MD5 digest.
const MD5_DIGEST_LEN: usize = 16;

/// Length in bytes of a SHA-1 / HMAC-SHA1 digest.
const SHA1_DIGEST_LEN: usize = 20;

extern "C" {
    /// `unsigned char *CC_MD5(const void *data, CC_LONG len, unsigned char *md);`
    fn CC_MD5(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;

    /// `void CCHmac(CCHmacAlgorithm algorithm, const void *key, size_t keyLength,
    ///             const void *data, size_t dataLength, void *macOut);`
    fn CCHmac(
        algorithm: u32,
        key: *const c_void,
        key_length: usize,
        data: *const c_void,
        data_length: usize,
        mac_out: *mut c_void,
    );
}

/// Compute the MD5 digest of `data`.
///
/// MD5 is cryptographically broken and is used here only because the STUN
/// long-term credential key derivation (RFC 5389 §15.4) is specified in terms
/// of it; it is never used as a general-purpose hash.
#[must_use]
pub fn md5(data: &[u8]) -> [u8; MD5_DIGEST_LEN] {
    let mut out = [0u8; MD5_DIGEST_LEN];
    // CC_LONG is u32; STUN credential inputs are tiny, so the cast is safe.
    let len = u32::try_from(data.len()).expect("md5 input too large");
    unsafe {
        CC_MD5(data.as_ptr().cast(), len, out.as_mut_ptr());
    }
    out
}

/// Compute `HMAC-SHA1(key, data)`.
#[must_use]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    let mut out = [0u8; SHA1_DIGEST_LEN];
    unsafe {
        CCHmac(
            KCC_HMAC_ALG_SHA1,
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr().cast(),
            data.len(),
            out.as_mut_ptr().cast(),
        );
    }
    out
}
