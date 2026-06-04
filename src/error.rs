//! Error type for STUN encoding, decoding, and transport.

use std::fmt;

/// Errors produced while parsing, building, or exchanging STUN messages.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The input was shorter than required (header or attribute truncated).
    Truncated,
    /// The 32-bit magic cookie did not equal `0x2112_A442`.
    BadMagicCookie,
    /// The two most-significant bits of the message type were not zero.
    BadMessageType,
    /// An attribute's declared length ran past the end of the message body.
    BadAttributeLength,
    /// An attribute value was not valid for its type (e.g. bad address family).
    MalformedAttribute(&'static str),
    /// A textual attribute was not valid UTF-8.
    BadUtf8,
    /// A `MAPPED-ADDRESS` / `XOR-MAPPED-ADDRESS` used an unknown address family.
    BadAddressFamily(u8),
    /// A `MESSAGE-INTEGRITY` or `MESSAGE-INTEGRITY-SHA256` check failed.
    IntegrityMismatch,
    /// A `FINGERPRINT` check failed.
    FingerprintMismatch,
    /// A STUN URI could not be parsed.
    InvalidUri(String),
    /// The transaction timed out without a matching response.
    Timeout,
    /// An underlying network operation failed.
    Network(String),
    /// The system RNG failed while generating a transaction ID.
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("STUN message truncated"),
            Self::BadMagicCookie => f.write_str("invalid STUN magic cookie"),
            Self::BadMessageType => f.write_str("invalid STUN message type (high bits set)"),
            Self::BadAttributeLength => f.write_str("STUN attribute length out of bounds"),
            Self::MalformedAttribute(what) => write!(f, "malformed STUN attribute: {what}"),
            Self::BadUtf8 => f.write_str("STUN text attribute is not valid UTF-8"),
            Self::BadAddressFamily(family) => {
                write!(f, "unknown STUN address family: {family:#04x}")
            }
            Self::IntegrityMismatch => f.write_str("STUN MESSAGE-INTEGRITY check failed"),
            Self::FingerprintMismatch => f.write_str("STUN FINGERPRINT check failed"),
            Self::InvalidUri(uri) => write!(f, "invalid STUN URI: {uri}"),
            Self::Timeout => f.write_str("STUN transaction timed out"),
            Self::Network(msg) => write!(f, "network error: {msg}"),
            Self::Rng => f.write_str("secure RNG failed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::rng::RngError> for Error {
    fn from(_: crate::rng::RngError) -> Self {
        Self::Rng
    }
}

/// Convenient result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
