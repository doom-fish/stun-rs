//! ICE connectivity-check attribute tests (RFC 8445).

use stun::attribute::types;
use stun::{Attribute, Class, Message, Method, TransactionId};

fn encode_single(attr: Attribute) -> Vec<u8> {
    Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([0u8; 12]))
        .attribute(attr)
        .build()
        .unwrap()
        .encode()
}

#[test]
fn priority_wire_format() {
    let bytes = encode_single(Attribute::Priority(0x6e00_01ff));
    // header(20) + type(2) + len(2) + value(4)
    assert_eq!(bytes.len(), 28);
    let body = &bytes[20..];
    assert_eq!(u16::from_be_bytes([body[0], body[1]]), types::PRIORITY);
    assert_eq!(u16::from_be_bytes([body[2], body[3]]), 4);
    assert_eq!(&body[4..8], &0x6e00_01ffu32.to_be_bytes());
}

#[test]
fn use_candidate_is_zero_length() {
    let bytes = encode_single(Attribute::UseCandidate);
    assert_eq!(bytes.len(), 24); // header + 4-byte TLV header, no value
    let body = &bytes[20..];
    assert_eq!(u16::from_be_bytes([body[0], body[1]]), types::USE_CANDIDATE);
    assert_eq!(u16::from_be_bytes([body[2], body[3]]), 0);
}

#[test]
fn ice_controlled_and_controlling_tiebreaker() {
    let tie = 0x0123_4567_89ab_cdefu64;
    for attr in [Attribute::IceControlled(tie), Attribute::IceControlling(tie)] {
        let want_type = attr.attribute_type();
        let bytes = encode_single(attr);
        let body = &bytes[20..];
        assert_eq!(u16::from_be_bytes([body[0], body[1]]), want_type);
        assert_eq!(u16::from_be_bytes([body[2], body[3]]), 8);
        assert_eq!(&body[4..12], &tie.to_be_bytes());
    }
}

#[test]
fn ice_attributes_roundtrip() {
    let msg = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([1u8; 12]))
        .attribute(Attribute::Priority(0x7eff_fffe))
        .attribute(Attribute::UseCandidate)
        .attribute(Attribute::IceControlling(0xdead_beef_cafe_babe))
        .build()
        .unwrap();
    let decoded = Message::decode(&msg.encode()).unwrap();
    assert_eq!(
        decoded.attributes(),
        &[
            Attribute::Priority(0x7eff_fffe),
            Attribute::UseCandidate,
            Attribute::IceControlling(0xdead_beef_cafe_babe),
        ]
    );
}

#[test]
fn comprehension_required_classification() {
    assert!(stun::attribute::is_comprehension_required(types::PRIORITY));
    assert!(stun::attribute::is_comprehension_required(types::USE_CANDIDATE));
    assert!(!stun::attribute::is_comprehension_required(types::ICE_CONTROLLED));
    assert!(!stun::attribute::is_comprehension_required(types::SOFTWARE));
}
