//! STUN message header, method/class encoding, and the top-level [`Message`]
//! type with its builder.

use crate::address::XorKey;
use crate::attribute::{types, Attribute};
use crate::error::{Error, Result};
use crate::fingerprint::fingerprint;
use crate::integrity::{self, constant_time_eq};
use crate::transaction::{TransactionId, TRANSACTION_ID_LEN};

/// The STUN magic cookie (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Fixed STUN header length in bytes.
pub const HEADER_LEN: usize = 20;

/// A keyed message-authentication function `(key, data) -> mac`.
type MacFn<'a> = &'a dyn Fn(&[u8], &[u8]) -> Vec<u8>;

/// The STUN method (the operation being performed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// `Binding` (`0x001`) — the only method defined by RFC 5389.
    Binding,
    /// Any other method, preserved as its raw 12-bit value.
    Other(u16),
}

impl Method {
    /// The raw 12-bit method value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Binding => 0x001,
            Self::Other(value) => value & 0x0FFF,
        }
    }

    /// Build a [`Method`] from a raw 12-bit value.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value & 0x0FFF {
            0x001 => Self::Binding,
            other => Self::Other(other),
        }
    }
}

/// The STUN message class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// A request that expects a response.
    Request,
    /// An indication, which expects no response.
    Indication,
    /// A success response to a request.
    SuccessResponse,
    /// An error response to a request.
    ErrorResponse,
}

impl Class {
    /// The raw 2-bit class value.
    #[must_use]
    pub const fn as_bits(self) -> u16 {
        match self {
            Self::Request => 0b00,
            Self::Indication => 0b01,
            Self::SuccessResponse => 0b10,
            Self::ErrorResponse => 0b11,
        }
    }

    /// Build a [`Class`] from a raw 2-bit value.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        match bits & 0b11 {
            0b00 => Self::Request,
            0b01 => Self::Indication,
            0b10 => Self::SuccessResponse,
            _ => Self::ErrorResponse,
        }
    }
}

/// The combined 14-bit STUN message type, encoding both method and class with
/// the bit-interleaving defined by RFC 5389 §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageType {
    /// The STUN method.
    pub method: Method,
    /// The STUN class.
    pub class: Class,
}

impl MessageType {
    /// Construct a message type from a method and class.
    #[must_use]
    pub const fn new(method: Method, class: Class) -> Self {
        Self { method, class }
    }

    /// Encode into the 14-bit on-the-wire value.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        let m = self.method.as_u16();
        let c = self.class.as_bits();
        (m & 0x000F) | ((m & 0x0070) << 1) | ((m & 0x0F80) << 2) | ((c & 0x1) << 4) | ((c & 0x2) << 7)
    }

    /// Decode from the 14-bit on-the-wire value.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        let m = (value & 0x000F) | ((value & 0x00E0) >> 1) | ((value & 0x3E00) >> 2);
        let c = ((value & 0x0010) >> 4) | ((value & 0x0100) >> 7);
        Self {
            method: Method::from_u16(m),
            class: Class::from_bits(c),
        }
    }
}

/// A fully decoded or built STUN message.
#[derive(Debug, Clone)]
pub struct Message {
    message_type: MessageType,
    transaction_id: TransactionId,
    attributes: Vec<Attribute>,
    raw: Option<Vec<u8>>,
}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        self.message_type == other.message_type
            && self.transaction_id == other.transaction_id
            && self.attributes == other.attributes
    }
}

impl Eq for Message {}

impl Message {
    /// Start building a new message with the given method and class.
    #[must_use]
    pub fn builder(method: Method, class: Class) -> MessageBuilder {
        MessageBuilder::new(method, class)
    }

    /// The message method.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.message_type.method
    }

    /// The message class.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.message_type.class
    }

    /// The full message type (method + class).
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// The transaction ID.
    #[must_use]
    pub const fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }

    /// The decoded attributes, in wire order.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }

    /// Find the first attribute of the given type, if present.
    #[must_use]
    pub fn get(&self, attribute_type: u16) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|a| a.attribute_type() == attribute_type)
    }

    /// The 16-byte XOR key for this message (`magic-cookie || transaction-id`).
    #[must_use]
    fn xor_key(&self) -> XorKey {
        let mut key = [0u8; 16];
        key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        key[4..16].copy_from_slice(self.transaction_id.as_bytes());
        key
    }

    /// Encode this message to its on-the-wire byte representation.
    ///
    /// Attributes are emitted in the order they were added. Any
    /// `MESSAGE-INTEGRITY`, `MESSAGE-INTEGRITY-SHA256`, or `FINGERPRINT`
    /// attributes present are encoded verbatim; use [`MessageBuilder`] to have
    /// them computed for you.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let key = self.xor_key();
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        self.write_header(&mut out, 0);
        for attr in &self.attributes {
            attr.encode(&key, &mut out);
        }
        let body_len = out.len() - HEADER_LEN;
        write_length(&mut out, body_len);
        out
    }

    /// Write the 20-byte header with a placeholder body `length`.
    fn write_header(&self, out: &mut Vec<u8>, length: usize) {
        out.extend_from_slice(&self.message_type.to_u16().to_be_bytes());
        out.extend_from_slice(&u16::try_from(length).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(self.transaction_id.as_bytes());
    }

    /// Decode a STUN message from bytes.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the header is malformed, the magic cookie is
    /// wrong, or any attribute runs past the declared message length.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let raw_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        if raw_type & 0xC000 != 0 {
            return Err(Error::BadMessageType);
        }
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(Error::BadMagicCookie);
        }
        let mut tid = [0u8; TRANSACTION_ID_LEN];
        tid.copy_from_slice(&bytes[8..20]);
        let transaction_id = TransactionId::from_bytes(tid);

        let body = bytes
            .get(HEADER_LEN..HEADER_LEN + length)
            .ok_or(Error::Truncated)?;

        let mut key = [0u8; 16];
        key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        key[4..16].copy_from_slice(&tid);

        let mut attributes = Vec::new();
        let mut offset = 0usize;
        while offset < body.len() {
            if offset + 4 > body.len() {
                return Err(Error::BadAttributeLength);
            }
            let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
            let value_len = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
            let value_start = offset + 4;
            let value_end = value_start
                .checked_add(value_len)
                .ok_or(Error::BadAttributeLength)?;
            if value_end > body.len() {
                return Err(Error::BadAttributeLength);
            }
            let value = &body[value_start..value_end];
            attributes.push(Attribute::decode(attr_type, value, &key)?);
            let padded = value_len + (4 - (value_len % 4)) % 4;
            offset = value_start + padded;
        }

        Ok(Self {
            message_type: MessageType::from_u16(raw_type),
            transaction_id,
            attributes,
            raw: Some(bytes[..HEADER_LEN + length].to_vec()),
        })
    }

    /// Verify a `MESSAGE-INTEGRITY` (HMAC-SHA1) attribute against `key`.
    ///
    /// Re-serializes the message prefix up to the integrity attribute with the
    /// header length adjusted per RFC 5389 §15.4 and compares the HMAC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedAttribute`] if no `MESSAGE-INTEGRITY`
    /// attribute is present, or [`Error::IntegrityMismatch`] on mismatch.
    pub fn verify_message_integrity(&self, key: &[u8]) -> Result<()> {
        self.verify_integrity(types::MESSAGE_INTEGRITY, integrity::SHA1_LEN, key, &|k, d| {
            integrity::hmac_sha1(k, d).to_vec()
        })
    }

    /// Verify a `MESSAGE-INTEGRITY-SHA256` attribute against `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedAttribute`] if absent, or
    /// [`Error::IntegrityMismatch`] on mismatch.
    pub fn verify_message_integrity_sha256(&self, key: &[u8]) -> Result<()> {
        self.verify_integrity(
            types::MESSAGE_INTEGRITY_SHA256,
            integrity::SHA256_LEN,
            key,
            &|k, d| integrity::hmac_sha256(k, d).to_vec(),
        )
    }

    /// Verify the `FINGERPRINT` attribute (RFC 5389 §15.5).
    ///
    /// Recomputes the CRC-32 over the original wire bytes up to the fingerprint
    /// attribute (with the header length adjusted to include it) and compares
    /// it against the stored value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedAttribute`] if no `FINGERPRINT` attribute is
    /// present, or [`Error::FingerprintMismatch`] on mismatch.
    pub fn verify_fingerprint(&self) -> Result<()> {
        let owned;
        let raw: &[u8] = match &self.raw {
            Some(bytes) => bytes,
            None => {
                owned = self.encode();
                &owned
            }
        };
        let (value_start, value_len) = find_attribute(raw, types::FINGERPRINT)
            .ok_or(Error::MalformedAttribute("FINGERPRINT not present"))?;
        if value_len != 4 {
            return Err(Error::MalformedAttribute("FINGERPRINT length"));
        }
        let attr_start = value_start - 4;
        let mut prefix = raw[..attr_start].to_vec();
        let synthetic_len = (attr_start - HEADER_LEN) + 8;
        write_length(&mut prefix, synthetic_len);
        let computed = fingerprint(&prefix);
        let stored = u32::from_be_bytes([
            raw[value_start],
            raw[value_start + 1],
            raw[value_start + 2],
            raw[value_start + 3],
        ]);
        if computed == stored {
            Ok(())
        } else {
            Err(Error::FingerprintMismatch)
        }
    }

    /// Shared integrity-verification machinery for both HMAC variants.
    ///
    /// Verification operates on the **original wire bytes** (preserved at
    /// decode time, or the canonical encoding for built messages) so that the
    /// HMAC is computed over the exact padding bytes that were transmitted —
    /// RFC 5389 permits arbitrary padding, so re-serializing with our own
    /// (zero) padding would not reproduce a peer's HMAC. The header length is
    /// set to cover everything up to and including the integrity attribute
    /// (RFC 5389 §15.4), the HMAC is recomputed, and compared in constant time.
    fn verify_integrity(
        &self,
        attr_type: u16,
        attr_value_len: usize,
        key: &[u8],
        mac_fn: MacFn<'_>,
    ) -> Result<()> {
        let owned;
        let raw: &[u8] = match &self.raw {
            Some(bytes) => bytes,
            None => {
                owned = self.encode();
                &owned
            }
        };

        let (value_start, value_len) = find_attribute(raw, attr_type)
            .ok_or(Error::MalformedAttribute("integrity attribute not present"))?;
        if value_len != attr_value_len {
            return Err(Error::MalformedAttribute("integrity attribute length"));
        }
        let attr_start = value_start - 4;

        let mut prefix = raw[..attr_start].to_vec();
        let synthetic_len = (attr_start - HEADER_LEN) + 4 + attr_value_len;
        write_length(&mut prefix, synthetic_len);

        let computed = mac_fn(key, &prefix);
        let stored = &raw[value_start..value_start + value_len];
        if constant_time_eq(&computed, stored) {
            Ok(())
        } else {
            Err(Error::IntegrityMismatch)
        }
    }
}

/// Scan the TLV body of a raw STUN message for the first attribute of
/// `attr_type`, returning `(value_start, value_len)` offsets into `raw`.
fn find_attribute(raw: &[u8], attr_type: u16) -> Option<(usize, usize)> {
    if raw.len() < HEADER_LEN {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
    let end = HEADER_LEN.checked_add(length)?;
    if end > raw.len() {
        return None;
    }
    let mut offset = HEADER_LEN;
    while offset + 4 <= end {
        let this_type = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let value_len = usize::from(u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]));
        let value_start = offset + 4;
        if value_start + value_len > end {
            return None;
        }
        if this_type == attr_type {
            return Some((value_start, value_len));
        }
        let padded = value_len + (4 - (value_len % 4)) % 4;
        offset = value_start + padded;
    }
    None
}

/// Overwrite the 16-bit length field (bytes 2–3) of an in-progress message.
fn write_length(out: &mut [u8], length: usize) {
    let bytes = u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes();
    out[2] = bytes[0];
    out[3] = bytes[1];
}

/// Builder for [`Message`], handling integrity and fingerprint computation.
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    message_type: MessageType,
    transaction_id: TransactionId,
    attributes: Vec<Attribute>,
    mi_sha1_key: Option<Vec<u8>>,
    mi_sha256_key: Option<Vec<u8>>,
    fingerprint: bool,
}

impl MessageBuilder {
    /// Create a builder for the given method and class with a random
    /// transaction ID.
    #[must_use]
    pub fn new(method: Method, class: Class) -> Self {
        Self {
            message_type: MessageType::new(method, class),
            transaction_id: TransactionId::random(),
            attributes: Vec::new(),
            mi_sha1_key: None,
            mi_sha256_key: None,
            fingerprint: false,
        }
    }

    /// Set the transaction ID (defaults to a fresh random one).
    #[must_use]
    pub fn transaction_id(mut self, transaction_id: TransactionId) -> Self {
        self.transaction_id = transaction_id;
        self
    }

    /// Append an attribute.
    #[must_use]
    pub fn attribute(mut self, attribute: Attribute) -> Self {
        self.attributes.push(attribute);
        self
    }

    /// Request that a `MESSAGE-INTEGRITY` (HMAC-SHA1) attribute be appended,
    /// computed with `key`.
    #[must_use]
    pub fn with_message_integrity_sha1(mut self, key: &[u8]) -> Self {
        self.mi_sha1_key = Some(key.to_vec());
        self
    }

    /// Request that a `MESSAGE-INTEGRITY-SHA256` attribute be appended,
    /// computed with `key`.
    #[must_use]
    pub fn with_message_integrity_sha256(mut self, key: &[u8]) -> Self {
        self.mi_sha256_key = Some(key.to_vec());
        self
    }

    /// Request that a `FINGERPRINT` attribute be appended.
    #[must_use]
    pub fn with_fingerprint(mut self) -> Self {
        self.fingerprint = true;
        self
    }

    /// Finalize into a [`Message`]. Integrity and fingerprint attributes (if
    /// requested) are computed and appended in RFC-mandated order.
    #[must_use]
    pub fn build(self) -> Message {
        let mut message = Message {
            message_type: self.message_type,
            transaction_id: self.transaction_id,
            attributes: self.attributes,
            raw: None,
        };
        let key = message.xor_key();

        if let Some(mi_key) = &self.mi_sha1_key {
            let mac = compute_integrity(&message, &key, 4 + integrity::SHA1_LEN, mi_key, &|k, d| {
                integrity::hmac_sha1(k, d).to_vec()
            });
            let mut fixed = [0u8; integrity::SHA1_LEN];
            fixed.copy_from_slice(&mac);
            message.attributes.push(Attribute::MessageIntegrity(fixed));
        }

        if let Some(mi_key) = &self.mi_sha256_key {
            let mac = compute_integrity(
                &message,
                &key,
                4 + integrity::SHA256_LEN,
                mi_key,
                &|k, d| integrity::hmac_sha256(k, d).to_vec(),
            );
            message
                .attributes
                .push(Attribute::MessageIntegritySha256(mac));
        }

        if self.fingerprint {
            let value = compute_fingerprint(&message, &key);
            message.attributes.push(Attribute::Fingerprint(value));
        }

        message.raw = Some(message.encode());
        message
    }

    /// Convenience: build and immediately encode to bytes.
    #[must_use]
    pub fn build_and_encode(self) -> Vec<u8> {
        self.build().encode()
    }
}

/// Compute an integrity HMAC over the current attributes with the synthetic
/// header length set to include the pending integrity attribute.
fn compute_integrity(
    message: &Message,
    key: &XorKey,
    attr_total_len: usize,
    mac_key: &[u8],
    mac_fn: MacFn<'_>,
) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(HEADER_LEN + 64);
    message.write_header(&mut prefix, 0);
    for attr in &message.attributes {
        attr.encode(key, &mut prefix);
    }
    let synthetic_len = (prefix.len() - HEADER_LEN) + attr_total_len;
    write_length(&mut prefix, synthetic_len);
    mac_fn(mac_key, &prefix)
}

/// Compute the `FINGERPRINT` value with the synthetic header length set to
/// include the pending 8-byte fingerprint attribute.
fn compute_fingerprint(message: &Message, key: &XorKey) -> u32 {
    let mut prefix = Vec::with_capacity(HEADER_LEN + 64);
    message.write_header(&mut prefix, 0);
    for attr in &message.attributes {
        attr.encode(key, &mut prefix);
    }
    let synthetic_len = (prefix.len() - HEADER_LEN) + 8;
    write_length(&mut prefix, synthetic_len);
    fingerprint(&prefix)
}
