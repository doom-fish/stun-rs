//! Attribute padding edge cases (RFC 5389 §15): every attribute is padded to a
//! 4-byte boundary, and the padding is not counted in the length field.

use stun::{Attribute, Class, Message, Method, TransactionId};

fn encode(attr: Attribute) -> Vec<u8> {
    Message::builder(Method::Binding, Class::Indication)
        .transaction_id(TransactionId::from_bytes([0u8; 12]))
        .attribute(attr)
        .build()
        .encode()
}

/// A value of length `n` occupies `4 + n + pad` bytes on the wire, where
/// `pad = (4 - n % 4) % 4`, and the declared length field is exactly `n`.
fn assert_padded(value_len: usize, attr: Attribute) {
    let bytes = encode(attr);
    let body = &bytes[20..];
    let declared = usize::from(u16::from_be_bytes([body[2], body[3]]));
    assert_eq!(declared, value_len, "length field counts only the value");
    let pad = (4 - value_len % 4) % 4;
    assert_eq!(body.len(), 4 + value_len + pad, "padded to 4-byte boundary");
    // Total message length is a multiple of 4.
    assert_eq!(bytes.len() % 4, 0);
}

#[test]
fn empty_value() {
    // USE-CANDIDATE has a zero-length value.
    assert_padded(0, Attribute::UseCandidate);
}

#[test]
fn one_byte_value() {
    assert_padded(
        1,
        Attribute::Unknown {
            attribute_type: 0x7f01,
            value: vec![0xaa],
        },
    );
}

#[test]
fn two_byte_value() {
    assert_padded(
        2,
        Attribute::Unknown {
            attribute_type: 0x7f02,
            value: vec![0xaa, 0xbb],
        },
    );
}

#[test]
fn three_byte_value() {
    assert_padded(3, Attribute::Software("abc".to_owned()));
}

#[test]
fn seven_byte_value() {
    assert_padded(7, Attribute::Software("seven!!".to_owned()));
}

#[test]
fn already_aligned_value() {
    assert_padded(4, Attribute::Priority(0x1234_5678));
}

#[test]
fn padding_survives_roundtrip() {
    for len in 0usize..=9 {
        let s: String = "x".repeat(len);
        let msg = Message::builder(Method::Binding, Class::Request)
            .transaction_id(TransactionId::from_bytes([3u8; 12]))
            .attribute(Attribute::Software(s.clone()))
            .build();
        let decoded = Message::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.attributes(), &[Attribute::Software(s)]);
    }
}
