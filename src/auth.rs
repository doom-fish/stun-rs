//! Short-term and long-term credential key derivation (RFC 5389 §15.4,
//! RFC 8489 §9).

use zeroize::{Zeroize, Zeroizing};

use crate::ffi::commoncrypto;

/// Derive the HMAC key for the **short-term credential** mechanism.
///
/// RFC 8489 §9.1.1 specifies the key as `SASLprep(password)` encoded as UTF-8.
/// SASLprep (RFC 4013) is a stringprep profile that normalizes Unicode; it is
/// only meaningful when the password contains non-ASCII characters. ICE
/// (RFC 8445 §5.3) mandates that the `ice-pwd` be generated from the 64
/// printable ASCII characters, for which SASLprep is the identity function.
/// We therefore use the raw password bytes and document the assumption here:
/// **non-ASCII passwords are passed through unchanged rather than SASLprep'd.**
#[must_use]
pub fn short_term_key(password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.as_bytes().to_vec())
}

/// Derive the HMAC key for the **long-term credential** mechanism.
///
/// RFC 5389 §15.4 defines the key as `MD5(username ":" realm ":" password)`.
/// MD5 is not part of CryptoKit's safe surface, so it is computed via
/// CommonCrypto (see [`crate::ffi::commoncrypto`]).
#[must_use]
pub fn long_term_key(username: &str, realm: &str, password: &str) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(
        username.len() + realm.len() + password.len() + 2,
    ));
    input.extend_from_slice(username.as_bytes());
    input.push(b':');
    input.extend_from_slice(realm.as_bytes());
    input.push(b':');
    input.extend_from_slice(password.as_bytes());
    let mut digest = commoncrypto::md5(&input);
    let key = Zeroizing::new(digest.to_vec());
    digest.zeroize();
    key
}
