use stun::ffi::commoncrypto::md5;
use stun::integrity::constant_time_eq;
use stun::{auth, Class, Message, Method};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn md5_matches_rfc1321_test_suite() {
    let vectors: [(&[u8], &str); 5] = [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];
    for (input, expected) in vectors {
        assert_eq!(hex(&md5(input)), expected);
    }
}

#[test]
fn long_term_key_is_md5_of_username_realm_and_password() {
    let key = auth::long_term_key("user", "realm", "pass");
    assert_eq!(key.as_slice(), md5(b"user:realm:pass"));
    assert_eq!(auth::short_term_key("ice-pwd").as_slice(), b"ice-pwd");
}

#[test]
fn constant_time_eq_compares_whole_slices() {
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(b"same bytes", b"same bytes"));
    assert!(!constant_time_eq(b"same bytes", b"same byteS"));
    assert!(!constant_time_eq(b"Same bytes", b"same bytes"));
    assert!(!constant_time_eq(b"short", b"shorter"));
}

#[test]
fn message_builder_debug_does_not_print_integrity_keys() {
    let key = b"top-secret-integrity-key";
    let builder = Message::builder(Method::Binding, Class::Request)
        .with_message_integrity_sha1(key)
        .with_message_integrity_sha256(key);
    let text = format!("{builder:?}");
    assert!(text.contains("message_integrity_sha1: true"), "{text}");
    assert!(text.contains("message_integrity_sha256: true"), "{text}");
    let rendered = format!("{:?}", key.to_vec());
    assert!(!text.contains(&rendered[1..rendered.len() - 1]), "{text}");
}
