use stun::attribute::types;
use stun::{Attribute, Class, Error, ErrorCode, Message, Method, TransactionId};

fn header(length: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0001u16.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&0x2112_a442u32.to_be_bytes());
    bytes.extend_from_slice(&[1u8; 12]);
    bytes
}

fn with_value_len(attribute_type: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = attribute_type.to_be_bytes().to_vec();
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len() + (4 - value.len() % 4) % 4, 0);
    bytes
}

fn message(attributes: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = attributes.concat();
    let mut bytes = header(u16::try_from(body.len()).unwrap());
    bytes.extend_from_slice(&body);
    bytes
}

#[test]
fn message_length_must_be_a_multiple_of_four() {
    let mut unpadded = header(7);
    unpadded.extend_from_slice(&[0x80, 0x22, 0x00, 0x03, b'a', b'b', b'c']);
    assert!(matches!(
        Message::decode(&unpadded),
        Err(Error::BadMessageLength)
    ));

    let valid = message(&[with_value_len(types::SOFTWARE, b"abc")]);
    let mut stretched = valid;
    stretched.extend_from_slice(&[0, 0]);
    stretched[2..4].copy_from_slice(&10u16.to_be_bytes());
    assert!(matches!(
        Message::decode(&stretched),
        Err(Error::BadMessageLength)
    ));
}

#[test]
fn fingerprint_must_be_the_last_attribute() {
    let bytes = message(&[
        with_value_len(types::FINGERPRINT, &[0, 0, 0, 0]),
        with_value_len(types::SOFTWARE, b"after"),
    ]);
    assert!(matches!(
        Message::decode(&bytes),
        Err(Error::MalformedAttribute(_))
    ));

    let built = Message::builder(Method::Binding, Class::Request)
        .attribute(Attribute::Fingerprint(0))
        .attribute(Attribute::Software("after".to_owned()))
        .build();
    assert!(matches!(built, Err(Error::MalformedAttribute(_))));

    let twice = Message::builder(Method::Binding, Class::Request)
        .attribute(Attribute::Fingerprint(0))
        .with_fingerprint()
        .build();
    assert!(matches!(twice, Err(Error::MalformedAttribute(_))));
}

#[test]
fn message_integrity_sha256_length_follows_rfc8489() {
    for len in [16usize, 20, 28, 32] {
        let bytes = message(&[with_value_len(
            types::MESSAGE_INTEGRITY_SHA256,
            &vec![0; len],
        )]);
        assert!(Message::decode(&bytes).is_ok(), "length {len}");
    }
    for len in [1usize, 12, 15, 18, 33, 36] {
        let bytes = message(&[with_value_len(
            types::MESSAGE_INTEGRITY_SHA256,
            &vec![0; len],
        )]);
        assert!(
            matches!(Message::decode(&bytes), Err(Error::MalformedAttribute(_))),
            "length {len}"
        );
    }
    let built = Message::builder(Method::Binding, Class::Request)
        .attribute(Attribute::MessageIntegritySha256(vec![0; 18]))
        .build();
    assert!(matches!(built, Err(Error::MalformedAttribute(_))));
}

#[test]
fn builder_rejects_a_message_longer_than_the_length_field() {
    let built = Message::builder(Method::Binding, Class::Indication)
        .attribute(Attribute::Unknown {
            attribute_type: 0x7f00,
            value: vec![0; 70_000],
        })
        .build();
    assert!(matches!(built, Err(Error::BadMessageLength)));

    let just_over = Message::builder(Method::Binding, Class::Indication)
        .attribute(Attribute::Unknown {
            attribute_type: 0x7f00,
            value: vec![0; 65_529],
        })
        .build();
    assert!(matches!(just_over, Err(Error::BadMessageLength)));

    let largest = Message::builder(Method::Binding, Class::Indication)
        .attribute(Attribute::Unknown {
            attribute_type: 0x7f00,
            value: vec![0; 65_528],
        })
        .build()
        .unwrap();
    assert_eq!(largest.encode().len(), 20 + 65_532);
    assert!(Message::decode(&largest.encode()).is_ok());
}

#[test]
fn unknown_comprehension_required_attributes_are_reported_once() {
    let request = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([3u8; 12]))
        .attribute(Attribute::Unknown {
            attribute_type: 0x7f00,
            value: vec![1],
        })
        .attribute(Attribute::Unknown {
            attribute_type: 0x8fff,
            value: vec![2],
        })
        .attribute(Attribute::Unknown {
            attribute_type: 0x7f00,
            value: vec![3],
        })
        .attribute(Attribute::Unknown {
            attribute_type: 0x0033,
            value: vec![],
        })
        .attribute(Attribute::MessageIntegrity([0; 20]))
        .attribute(Attribute::Unknown {
            attribute_type: 0x7f01,
            value: vec![],
        })
        .build()
        .unwrap();
    let decoded = Message::decode(&request.encode()).unwrap();
    assert_eq!(decoded.unknown_comprehension_required(), [0x7f00, 0x0033]);

    let known = Message::builder(Method::Binding, Class::Request)
        .attribute(Attribute::Priority(1))
        .attribute(Attribute::UseCandidate)
        .build()
        .unwrap();
    assert!(known.unknown_comprehension_required().is_empty());
}

#[test]
fn unknown_attribute_response_is_a_420_error_for_the_same_transaction() {
    let request = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([9u8; 12]))
        .attribute(Attribute::Unknown {
            attribute_type: 0x7f00,
            value: vec![],
        })
        .build()
        .unwrap();
    let unknown = request.unknown_comprehension_required();
    let response = request
        .unknown_attribute_response(&unknown)
        .with_fingerprint()
        .build()
        .unwrap();

    let decoded = Message::decode(&response.encode()).unwrap();
    decoded.verify_fingerprint().unwrap();
    assert_eq!(decoded.class(), Class::ErrorResponse);
    assert_eq!(decoded.method(), Method::Binding);
    assert_eq!(decoded.transaction_id(), request.transaction_id());
    assert_eq!(
        decoded.get(types::ERROR_CODE),
        Some(&Attribute::ErrorCode(ErrorCode::new(
            420,
            "Unknown Attribute"
        )))
    );
    assert_eq!(
        decoded.get(types::UNKNOWN_ATTRIBUTES),
        Some(&Attribute::UnknownAttributes(vec![0x7f00]))
    );
}

#[test]
fn builder_draws_a_random_transaction_id_only_when_none_is_set() {
    let fixed = TransactionId::from_bytes([0x42; 12]);
    let set = Message::builder(Method::Binding, Class::Request)
        .transaction_id(fixed)
        .build()
        .unwrap();
    assert_eq!(set.transaction_id(), &fixed);

    let first = Message::builder(Method::Binding, Class::Request)
        .build()
        .unwrap();
    let second = Message::builder(Method::Binding, Class::Request)
        .build()
        .unwrap();
    assert_ne!(first.transaction_id(), second.transaction_id());
}
