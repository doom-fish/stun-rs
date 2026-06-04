//! STUN attributes and their type-length-value (TLV) codec.
//!
//! Every attribute is encoded as a 16-bit type, a 16-bit value length (the
//! length **before** padding), the value itself, and zero padding up to the
//! next 4-byte boundary (RFC 5389 §15). The padding bytes are *not* counted in
//! the length field.

use std::net::SocketAddr;

use crate::address::{self, XorKey};
use crate::error::{Error, Result};

/// Attribute type registry (RFC 5389, RFC 8489, RFC 8445).
pub mod types {
    #![allow(missing_docs)]

    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
    pub const PASSWORD_ALGORITHM: u16 = 0x001D;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const PRIORITY: u16 = 0x0024;
    pub const USE_CANDIDATE: u16 = 0x0025;
    pub const SOFTWARE: u16 = 0x8022;
    pub const ALTERNATE_SERVER: u16 = 0x8023;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const ICE_CONTROLLED: u16 = 0x8029;
    pub const ICE_CONTROLLING: u16 = 0x802A;
}

/// The boundary between comprehension-required (`< 0x8000`) and
/// comprehension-optional (`>= 0x8000`) attribute types (RFC 5389 §15).
pub const COMPREHENSION_OPTIONAL_FLOOR: u16 = 0x8000;

/// Returns `true` if `attribute_type` is in the comprehension-required range.
#[must_use]
pub const fn is_comprehension_required(attribute_type: u16) -> bool {
    attribute_type < COMPREHENSION_OPTIONAL_FLOOR
}

/// A decoded `ERROR-CODE` attribute (RFC 5389 §15.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCode {
    /// The error class (the hundreds digit, 3–6).
    pub class: u8,
    /// The error number within the class (0–99).
    pub number: u8,
    /// The human-readable reason phrase.
    pub reason: String,
}

impl ErrorCode {
    /// Build an `ERROR-CODE` from a combined code (e.g. `401`) and reason.
    #[must_use]
    pub fn new(code: u16, reason: impl Into<String>) -> Self {
        Self {
            class: u8::try_from(code / 100).unwrap_or(0),
            number: u8::try_from(code % 100).unwrap_or(0),
            reason: reason.into(),
        }
    }

    /// The combined error code (`class * 100 + number`).
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.class as u16 * 100 + self.number as u16
    }
}

/// A decoded `PASSWORD-ALGORITHM` attribute (RFC 8489 §14.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordAlgorithm {
    /// The algorithm identifier (e.g. `0x0001` MD5, `0x0002` SHA-256).
    pub algorithm: u16,
    /// Algorithm-specific parameters.
    pub parameters: Vec<u8>,
}

/// A single STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attribute {
    /// `MAPPED-ADDRESS` — the reflexive transport address, unobfuscated.
    MappedAddress(SocketAddr),
    /// `XOR-MAPPED-ADDRESS` — the reflexive transport address, XOR-obfuscated.
    XorMappedAddress(SocketAddr),
    /// `USERNAME` — the authentication username (UTF-8).
    Username(String),
    /// `MESSAGE-INTEGRITY` — a 20-byte HMAC-SHA1 value.
    MessageIntegrity([u8; 20]),
    /// `MESSAGE-INTEGRITY-SHA256` — an HMAC-SHA256 value (up to 32 bytes).
    MessageIntegritySha256(Vec<u8>),
    /// `FINGERPRINT` — the CRC-32 fingerprint value.
    Fingerprint(u32),
    /// `ERROR-CODE` — a class/number/reason error.
    ErrorCode(ErrorCode),
    /// `UNKNOWN-ATTRIBUTES` — a list of unknown attribute types.
    UnknownAttributes(Vec<u16>),
    /// `REALM` — the authentication realm (UTF-8).
    Realm(String),
    /// `NONCE` — the authentication nonce (UTF-8).
    Nonce(String),
    /// `PASSWORD-ALGORITHM` — the negotiated password algorithm.
    PasswordAlgorithm(PasswordAlgorithm),
    /// `SOFTWARE` — a human-readable description of the sender (UTF-8).
    Software(String),
    /// `ALTERNATE-SERVER` — an alternate server transport address.
    AlternateServer(SocketAddr),
    /// `PRIORITY` — the ICE candidate priority (RFC 8445).
    Priority(u32),
    /// `USE-CANDIDATE` — flags the candidate pair for nomination (RFC 8445).
    UseCandidate,
    /// `ICE-CONTROLLED` — the agent is in the controlled role (RFC 8445).
    IceControlled(u64),
    /// `ICE-CONTROLLING` — the agent is in the controlling role (RFC 8445).
    IceControlling(u64),
    /// Any attribute this crate does not model, preserved verbatim.
    Unknown {
        /// The 16-bit attribute type.
        attribute_type: u16,
        /// The raw value bytes (without padding).
        value: Vec<u8>,
    },
}

impl Attribute {
    /// The 16-bit type code of this attribute.
    #[must_use]
    pub const fn attribute_type(&self) -> u16 {
        match self {
            Self::MappedAddress(_) => types::MAPPED_ADDRESS,
            Self::XorMappedAddress(_) => types::XOR_MAPPED_ADDRESS,
            Self::Username(_) => types::USERNAME,
            Self::MessageIntegrity(_) => types::MESSAGE_INTEGRITY,
            Self::MessageIntegritySha256(_) => types::MESSAGE_INTEGRITY_SHA256,
            Self::Fingerprint(_) => types::FINGERPRINT,
            Self::ErrorCode(_) => types::ERROR_CODE,
            Self::UnknownAttributes(_) => types::UNKNOWN_ATTRIBUTES,
            Self::Realm(_) => types::REALM,
            Self::Nonce(_) => types::NONCE,
            Self::PasswordAlgorithm(_) => types::PASSWORD_ALGORITHM,
            Self::Software(_) => types::SOFTWARE,
            Self::AlternateServer(_) => types::ALTERNATE_SERVER,
            Self::Priority(_) => types::PRIORITY,
            Self::UseCandidate => types::USE_CANDIDATE,
            Self::IceControlled(_) => types::ICE_CONTROLLED,
            Self::IceControlling(_) => types::ICE_CONTROLLING,
            Self::Unknown { attribute_type, .. } => *attribute_type,
        }
    }

    /// Encode just this attribute's value (no type/length/padding) into `out`.
    ///
    /// `key` is the message's XOR key (`magic-cookie || transaction-id`), used
    /// only by the XOR-obfuscated address attributes.
    fn encode_value(&self, key: &XorKey, out: &mut Vec<u8>) {
        match self {
            Self::MappedAddress(addr) => address::encode_mapped(*addr, out),
            Self::AlternateServer(addr) => address::encode_mapped(*addr, out),
            Self::XorMappedAddress(addr) => address::encode_xor(*addr, key, out),
            Self::Username(s) | Self::Realm(s) | Self::Nonce(s) | Self::Software(s) => {
                out.extend_from_slice(s.as_bytes());
            }
            Self::MessageIntegrity(mac) => out.extend_from_slice(mac),
            Self::MessageIntegritySha256(mac) => out.extend_from_slice(mac),
            Self::Fingerprint(value) => out.extend_from_slice(&value.to_be_bytes()),
            Self::ErrorCode(err) => {
                out.extend_from_slice(&[0, 0, err.class, err.number]);
                out.extend_from_slice(err.reason.as_bytes());
            }
            Self::UnknownAttributes(list) => {
                for ty in list {
                    out.extend_from_slice(&ty.to_be_bytes());
                }
            }
            Self::PasswordAlgorithm(pa) => {
                out.extend_from_slice(&pa.algorithm.to_be_bytes());
                let len = u16::try_from(pa.parameters.len()).unwrap_or(0);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&pa.parameters);
            }
            Self::Priority(value) => out.extend_from_slice(&value.to_be_bytes()),
            Self::UseCandidate => {}
            Self::IceControlled(value) | Self::IceControlling(value) => {
                out.extend_from_slice(&value.to_be_bytes());
            }
            Self::Unknown { value, .. } => out.extend_from_slice(value),
        }
    }

    /// Encode the full TLV (type, length, value, padding) into `out`.
    pub fn encode(&self, key: &XorKey, out: &mut Vec<u8>) {
        let type_pos = out.len();
        out.extend_from_slice(&self.attribute_type().to_be_bytes());
        // Reserve the length field; fill it in after encoding the value.
        out.extend_from_slice(&[0, 0]);
        let value_start = out.len();
        self.encode_value(key, out);
        let value_len = out.len() - value_start;
        let len_bytes = u16::try_from(value_len).unwrap_or(u16::MAX).to_be_bytes();
        out[type_pos + 2] = len_bytes[0];
        out[type_pos + 3] = len_bytes[1];
        // Pad to a 4-byte boundary.
        let padding = (4 - (value_len % 4)) % 4;
        out.extend(std::iter::repeat(0u8).take(padding));
    }

    /// Decode a single attribute value given its type, raw value bytes, and the
    /// message XOR key.
    pub fn decode(attribute_type: u16, value: &[u8], key: &XorKey) -> Result<Self> {
        match attribute_type {
            types::MAPPED_ADDRESS => Ok(Self::MappedAddress(address::decode_mapped(value)?)),
            types::ALTERNATE_SERVER => Ok(Self::AlternateServer(address::decode_mapped(value)?)),
            types::XOR_MAPPED_ADDRESS => {
                Ok(Self::XorMappedAddress(address::decode_xor(value, key)?))
            }
            types::USERNAME => Ok(Self::Username(decode_utf8(value)?)),
            types::REALM => Ok(Self::Realm(decode_utf8(value)?)),
            types::NONCE => Ok(Self::Nonce(decode_utf8(value)?)),
            types::SOFTWARE => Ok(Self::Software(decode_utf8(value)?)),
            types::MESSAGE_INTEGRITY => {
                let mac: [u8; 20] = value
                    .try_into()
                    .map_err(|_| Error::MalformedAttribute("MESSAGE-INTEGRITY must be 20 bytes"))?;
                Ok(Self::MessageIntegrity(mac))
            }
            types::MESSAGE_INTEGRITY_SHA256 => {
                if value.is_empty() || value.len() > 32 {
                    return Err(Error::MalformedAttribute(
                        "MESSAGE-INTEGRITY-SHA256 length out of range",
                    ));
                }
                Ok(Self::MessageIntegritySha256(value.to_vec()))
            }
            types::FINGERPRINT => {
                let bytes: [u8; 4] = value
                    .try_into()
                    .map_err(|_| Error::MalformedAttribute("FINGERPRINT must be 4 bytes"))?;
                Ok(Self::Fingerprint(u32::from_be_bytes(bytes)))
            }
            types::ERROR_CODE => decode_error_code(value),
            types::UNKNOWN_ATTRIBUTES => {
                if value.len() % 2 != 0 {
                    return Err(Error::MalformedAttribute("UNKNOWN-ATTRIBUTES odd length"));
                }
                let list = value
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Ok(Self::UnknownAttributes(list))
            }
            types::PASSWORD_ALGORITHM => decode_password_algorithm(value),
            types::PRIORITY => Ok(Self::Priority(decode_u32(value, "PRIORITY")?)),
            types::USE_CANDIDATE => {
                if value.is_empty() {
                    Ok(Self::UseCandidate)
                } else {
                    Err(Error::MalformedAttribute("USE-CANDIDATE must be empty"))
                }
            }
            types::ICE_CONTROLLED => Ok(Self::IceControlled(decode_u64(value, "ICE-CONTROLLED")?)),
            types::ICE_CONTROLLING => {
                Ok(Self::IceControlling(decode_u64(value, "ICE-CONTROLLING")?))
            }
            other => Ok(Self::Unknown {
                attribute_type: other,
                value: value.to_vec(),
            }),
        }
    }
}

/// Decode a UTF-8 attribute value.
fn decode_utf8(value: &[u8]) -> Result<String> {
    std::str::from_utf8(value)
        .map(ToOwned::to_owned)
        .map_err(|_| Error::BadUtf8)
}

/// Decode a big-endian `u32` attribute value.
fn decode_u32(value: &[u8], what: &'static str) -> Result<u32> {
    let bytes: [u8; 4] = value.try_into().map_err(|_| match what {
        "PRIORITY" => Error::MalformedAttribute("PRIORITY must be 4 bytes"),
        _ => Error::MalformedAttribute("expected 4-byte value"),
    })?;
    Ok(u32::from_be_bytes(bytes))
}

/// Decode a big-endian `u64` attribute value.
fn decode_u64(value: &[u8], what: &'static str) -> Result<u64> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| match what {
        "ICE-CONTROLLED" => Error::MalformedAttribute("ICE-CONTROLLED must be 8 bytes"),
        "ICE-CONTROLLING" => Error::MalformedAttribute("ICE-CONTROLLING must be 8 bytes"),
        _ => Error::MalformedAttribute("expected 8-byte value"),
    })?;
    Ok(u64::from_be_bytes(bytes))
}

/// Decode an `ERROR-CODE` value.
fn decode_error_code(value: &[u8]) -> Result<Attribute> {
    if value.len() < 4 {
        return Err(Error::MalformedAttribute("ERROR-CODE too short"));
    }
    let class = value[2] & 0x07;
    let number = value[3];
    let reason = std::str::from_utf8(&value[4..])
        .map_err(|_| Error::BadUtf8)?
        .to_owned();
    Ok(Attribute::ErrorCode(ErrorCode {
        class,
        number,
        reason,
    }))
}

/// Decode a `PASSWORD-ALGORITHM` value.
fn decode_password_algorithm(value: &[u8]) -> Result<Attribute> {
    if value.len() < 4 {
        return Err(Error::MalformedAttribute("PASSWORD-ALGORITHM too short"));
    }
    let algorithm = u16::from_be_bytes([value[0], value[1]]);
    let param_len = usize::from(u16::from_be_bytes([value[2], value[3]]));
    let parameters = value
        .get(4..4 + param_len)
        .ok_or(Error::MalformedAttribute(
            "PASSWORD-ALGORITHM parameter length out of bounds",
        ))?
        .to_vec();
    Ok(Attribute::PasswordAlgorithm(PasswordAlgorithm {
        algorithm,
        parameters,
    }))
}
