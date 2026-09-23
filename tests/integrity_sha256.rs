use stun::integrity::hmac_sha256;
use stun::{auth, Attribute, Class, Error, Message, Method, TransactionId};

#[test]
fn hmac_sha256_matches_rfc4231_test_case_2() {
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?").unwrap();
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn message_integrity_sha256_round_trips_and_rejects_a_wrong_key() {
    let key = auth::short_term_key("ice-password");
    let bytes = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([8u8; 12]))
        .attribute(Attribute::Username("a:b".to_owned()))
        .with_message_integrity_sha1(&key)
        .with_message_integrity_sha256(&key)
        .with_fingerprint()
        .build_and_encode()
        .unwrap();

    let message = Message::decode(&bytes).unwrap();
    message.verify_message_integrity(&key).unwrap();
    message.verify_message_integrity_sha256(&key).unwrap();
    message.verify_fingerprint().unwrap();
    assert!(matches!(
        message.verify_message_integrity_sha256(b"wrong"),
        Err(Error::IntegrityMismatch)
    ));
    assert!(message.ignored_attributes().is_empty());
}
