//! Adversarial / malformed-input decoding tests.

use stun::{auth, Attribute, Class, Error, Message, Method, TransactionId};

fn valid_message() -> Vec<u8> {
    Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([9u8; 12]))
        .attribute(Attribute::Software("ok".to_owned()))
        .with_message_integrity_sha1(b"secret")
        .with_fingerprint()
        .build()
        .encode()
}

#[test]
fn truncated_header() {
    assert!(matches!(Message::decode(&[0u8; 10]), Err(Error::Truncated)));
    assert!(matches!(Message::decode(&[]), Err(Error::Truncated)));
}

#[test]
fn bad_magic_cookie() {
    let mut bytes = valid_message();
    bytes[4] ^= 0xff;
    assert!(matches!(Message::decode(&bytes), Err(Error::BadMagicCookie)));
}

#[test]
fn bad_message_type_high_bits() {
    let mut bytes = valid_message();
    bytes[0] |= 0xc0; // set the top two bits of the 16-bit type field
    assert!(matches!(Message::decode(&bytes), Err(Error::BadMessageType)));
}

#[test]
fn body_length_exceeds_buffer() {
    let mut bytes = valid_message();
    let bogus = (bytes.len() as u16) + 100;
    bytes[2..4].copy_from_slice(&bogus.to_be_bytes());
    assert!(matches!(Message::decode(&bytes), Err(Error::Truncated)));
}

#[test]
fn attribute_length_overruns_body() {
    // header declaring a 8-byte body, but the single attribute claims a
    // 100-byte value.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0001u16.to_be_bytes()); // type
    bytes.extend_from_slice(&8u16.to_be_bytes()); // length
    bytes.extend_from_slice(&0x2112_a442u32.to_be_bytes()); // cookie
    bytes.extend_from_slice(&[0u8; 12]); // transaction id
    bytes.extend_from_slice(&0x8022u16.to_be_bytes()); // SOFTWARE
    bytes.extend_from_slice(&100u16.to_be_bytes()); // bogus length
    bytes.extend_from_slice(&[0u8; 4]);
    assert!(matches!(
        Message::decode(&bytes),
        Err(Error::BadAttributeLength)
    ));
}

#[test]
fn invalid_utf8_software() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0001u16.to_be_bytes());
    bytes.extend_from_slice(&8u16.to_be_bytes()); // body length = 8
    bytes.extend_from_slice(&0x2112_a442u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 12]);
    bytes.extend_from_slice(&0x8022u16.to_be_bytes()); // SOFTWARE
    bytes.extend_from_slice(&4u16.to_be_bytes()); // value length 4
    bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // invalid UTF-8
    assert!(matches!(Message::decode(&bytes), Err(Error::BadUtf8)));
}

#[test]
fn integrity_mismatch_wrong_key() {
    let bytes = valid_message();
    let msg = Message::decode(&bytes).unwrap();
    let bad = auth::short_term_key("wrong-password");
    assert!(matches!(
        msg.verify_message_integrity(&bad),
        Err(Error::IntegrityMismatch)
    ));
    msg.verify_message_integrity(b"secret").unwrap();
}

#[test]
fn fingerprint_mismatch_when_corrupted() {
    let mut bytes = valid_message();
    let len = bytes.len();
    bytes[len - 1] ^= 0xff; // corrupt the last fingerprint byte
    let msg = Message::decode(&bytes).unwrap();
    assert!(matches!(
        msg.verify_fingerprint(),
        Err(Error::FingerprintMismatch)
    ));
}

#[test]
fn missing_integrity_attribute() {
    let bytes = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([0u8; 12]))
        .build()
        .encode();
    let msg = Message::decode(&bytes).unwrap();
    assert!(matches!(
        msg.verify_message_integrity(b"k"),
        Err(Error::MalformedAttribute(_))
    ));
}
