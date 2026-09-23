use stun::attribute::types;
use stun::fingerprint::fingerprint;
use stun::{auth, Attribute, Class, Error, Message, Method, TransactionId};

fn set_length(bytes: &mut [u8], body_len: usize) {
    bytes[2..4].copy_from_slice(&u16::try_from(body_len).unwrap().to_be_bytes());
}

fn append_fingerprint(mut bytes: Vec<u8>) -> Vec<u8> {
    let body_len = bytes.len() - 20 + 8;
    set_length(&mut bytes, body_len);
    let crc = fingerprint(&bytes);
    bytes.extend_from_slice(&[0x80, 0x28, 0x00, 0x04]);
    bytes.extend_from_slice(&crc.to_be_bytes());
    bytes
}

fn signed_check(key: &[u8]) -> Vec<u8> {
    Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([4u8; 12]))
        .attribute(Attribute::Username("remote:local".to_owned()))
        .attribute(Attribute::Priority(0x6e00_01ff))
        .attribute(Attribute::IceControlling(0x0102_0304_0506_0708))
        .with_message_integrity_sha1(key)
        .with_fingerprint()
        .build()
        .encode()
}

#[test]
fn use_candidate_appended_after_message_integrity_is_ignored() {
    let key = auth::short_term_key("ice-password");
    let genuine = signed_check(&key);

    let mut forged = genuine[..genuine.len() - 8].to_vec();
    forged.extend_from_slice(&[0x00, 0x25, 0x00, 0x00]);
    let forged = append_fingerprint(forged);

    let message = Message::decode(&forged).unwrap();
    message.verify_message_integrity(&key).unwrap();
    message.verify_fingerprint().unwrap();
    assert!(message.get(types::USE_CANDIDATE).is_none());
    assert!(!message.attributes().contains(&Attribute::UseCandidate));
    assert_eq!(message.ignored_attributes(), &[Attribute::UseCandidate]);
    assert!(matches!(
        message.get(types::FINGERPRINT),
        Some(Attribute::Fingerprint(_))
    ));
    assert_eq!(message.encode(), forged);
}

#[test]
fn only_integrity_sha256_and_fingerprint_are_processed_after_message_integrity() {
    let message = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([5u8; 12]))
        .attribute(Attribute::Software("agent".to_owned()))
        .attribute(Attribute::MessageIntegrity([0u8; 20]))
        .attribute(Attribute::Priority(7))
        .attribute(Attribute::MessageIntegritySha256(vec![0u8; 32]))
        .attribute(Attribute::UseCandidate)
        .with_fingerprint()
        .build();

    let decoded = Message::decode(&message.encode()).unwrap();
    for view in [&message, &decoded] {
        let processed: Vec<u16> = view.attributes().iter().map(Attribute::attribute_type).collect();
        assert_eq!(
            processed,
            [
                types::SOFTWARE,
                types::MESSAGE_INTEGRITY,
                types::MESSAGE_INTEGRITY_SHA256,
                types::FINGERPRINT
            ]
        );
        assert_eq!(
            view.ignored_attributes(),
            &[Attribute::Priority(7), Attribute::UseCandidate]
        );
        assert!(view.get(types::PRIORITY).is_none());
    }
    assert_eq!(message, decoded);
}

#[test]
fn message_integrity_after_message_integrity_sha256_is_ignored() {
    let message = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([6u8; 12]))
        .attribute(Attribute::Software("agent".to_owned()))
        .attribute(Attribute::MessageIntegritySha256(vec![0u8; 32]))
        .attribute(Attribute::Priority(9))
        .attribute(Attribute::MessageIntegrity([0u8; 20]))
        .with_fingerprint()
        .build();

    let decoded = Message::decode(&message.encode()).unwrap();
    assert_eq!(
        decoded.ignored_attributes(),
        &[Attribute::Priority(9), Attribute::MessageIntegrity([0u8; 20])]
    );
    assert!(decoded.get(types::MESSAGE_INTEGRITY).is_none());
    assert!(matches!(
        decoded.verify_message_integrity(b"key"),
        Err(Error::MalformedAttribute(_))
    ));
}

#[test]
fn a_second_message_integrity_is_ignored_and_the_first_is_verified() {
    let key = auth::short_term_key("secret");
    let genuine = Message::builder(Method::Binding, Class::SuccessResponse)
        .transaction_id(TransactionId::from_bytes([7u8; 12]))
        .attribute(Attribute::Software("server".to_owned()))
        .with_message_integrity_sha1(&key)
        .build()
        .encode();

    let mut forged = genuine;
    forged.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
    forged.extend_from_slice(&[0xee; 20]);
    let body_len = forged.len() - 20;
    set_length(&mut forged, body_len);

    let message = Message::decode(&forged).unwrap();
    message.verify_message_integrity(&key).unwrap();
    assert_eq!(
        message.ignored_attributes(),
        &[Attribute::MessageIntegrity([0xee; 20])]
    );
    assert!(matches!(
        message.get(types::MESSAGE_INTEGRITY),
        Some(Attribute::MessageIntegrity(mac)) if mac != &[0xee; 20]
    ));
}
