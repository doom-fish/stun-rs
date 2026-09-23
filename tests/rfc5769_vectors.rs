//! RFC 5769 canonical STUN test vectors.
//!
//! Every sample message from RFC 5769 §2 is decoded, its attributes checked,
//! and its `MESSAGE-INTEGRITY` / `FINGERPRINT` verified against the published
//! bytes. Because RFC 5769 §2.1–2.3 pad with ASCII spaces while this crate
//! pads with zero bytes (both legal per RFC 5389 §15), verification is done
//! against the *original* wire bytes; exact re-encoding equality is asserted
//! only for §2.4, which pads with zeros like we do.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use stun::{auth, Attribute, Class, Message, Method};

/// Parse a whitespace-separated hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(cleaned.len() % 2 == 0, "odd number of hex digits");
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
        .collect()
}

const SHORT_TERM_PASSWORD: &str = "VOkJxbRl1RmTxUk/WvJxBt";

/// RFC 5769 §2.1 — Sample Request.
#[test]
fn sample_request() {
    let bytes = hex(
        "
        00 01 00 58
        21 12 a4 42
        b7 e7 a7 01
        bc 34 d6 86
        fa 87 df ae
        80 22 00 10
        53 54 55 4e
        20 74 65 73
        74 20 63 6c
        69 65 6e 74
        00 24 00 04
        6e 00 01 ff
        80 29 00 08
        93 2f f9 b1
        51 26 3b 36
        00 06 00 09
        65 76 74 6a
        3a 68 36 76
        59 20 20 20
        00 08 00 14
        9a ea a7 0c
        bf d8 cb 56
        78 1e f2 b5
        b2 d3 f2 49
        c1 b5 71 a2
        80 28 00 04
        e5 7a 3b cf
        ",
    );

    let msg = Message::decode(&bytes).expect("decode request");
    assert_eq!(msg.method(), Method::Binding);
    assert_eq!(msg.class(), Class::Request);

    let mut saw_software = false;
    let mut saw_priority = false;
    let mut saw_ice_controlled = false;
    let mut saw_username = false;
    for attr in msg.attributes() {
        match attr {
            Attribute::Software(s) => {
                assert_eq!(s, "STUN test client");
                saw_software = true;
            }
            Attribute::Priority(p) => {
                assert_eq!(*p, 0x6e00_01ff);
                saw_priority = true;
            }
            Attribute::IceControlled(tie) => {
                assert_eq!(*tie, 0x932f_f9b1_5126_3b36);
                saw_ice_controlled = true;
            }
            Attribute::Username(u) => {
                assert_eq!(u, "evtj:h6vY");
                saw_username = true;
            }
            _ => {}
        }
    }
    assert!(saw_software && saw_priority && saw_ice_controlled && saw_username);

    let key = auth::short_term_key(SHORT_TERM_PASSWORD);
    msg.verify_message_integrity(&key)
        .expect("MESSAGE-INTEGRITY must verify");
    msg.verify_fingerprint().expect("FINGERPRINT must verify");

    // Rebuilt message is self-consistent (padding differs, so bytes won't be
    // identical, but the integrity/fingerprint we compute must verify).
    let rebuilt = Message::builder(Method::Binding, Class::Request)
        .transaction_id(*msg.transaction_id())
        .attribute(Attribute::Software("STUN test client".to_owned()))
        .attribute(Attribute::Priority(0x6e00_01ff))
        .attribute(Attribute::IceControlled(0x932f_f9b1_5126_3b36))
        .attribute(Attribute::Username("evtj:h6vY".to_owned()))
        .with_message_integrity_sha1(&key)
        .with_fingerprint()
        .build()
        .unwrap();
    rebuilt.verify_message_integrity(&key).unwrap();
    rebuilt.verify_fingerprint().unwrap();
}

/// RFC 5769 §2.2 — Sample IPv4 Response.
#[test]
fn sample_ipv4_response() {
    let bytes = hex(
        "
        01 01 00 3c
        21 12 a4 42
        b7 e7 a7 01
        bc 34 d6 86
        fa 87 df ae
        80 22 00 0b
        74 65 73 74
        20 76 65 63
        74 6f 72 20
        00 20 00 08
        00 01 a1 47
        e1 12 a6 43
        00 08 00 14
        2b 91 f5 99
        fd 9e 90 c3
        8c 74 89 f9
        2a f9 ba 53
        f0 6b e7 d7
        80 28 00 04
        c0 7d 4c 96
        ",
    );

    let msg = Message::decode(&bytes).expect("decode ipv4 response");
    assert_eq!(msg.method(), Method::Binding);
    assert_eq!(msg.class(), Class::SuccessResponse);

    let expected = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 32853);
    let mut saw_addr = false;
    for attr in msg.attributes() {
        if let Attribute::XorMappedAddress(addr) = attr {
            assert_eq!(*addr, expected);
            saw_addr = true;
        }
        if let Attribute::Software(s) = attr {
            assert_eq!(s, "test vector");
        }
    }
    assert!(saw_addr, "XOR-MAPPED-ADDRESS present");

    let key = auth::short_term_key(SHORT_TERM_PASSWORD);
    msg.verify_message_integrity(&key).unwrap();
    msg.verify_fingerprint().unwrap();
}

/// RFC 5769 §2.3 — Sample IPv6 Response.
#[test]
fn sample_ipv6_response() {
    let bytes = hex(
        "
        01 01 00 48
        21 12 a4 42
        b7 e7 a7 01
        bc 34 d6 86
        fa 87 df ae
        80 22 00 0b
        74 65 73 74
        20 76 65 63
        74 6f 72 20
        00 20 00 14
        00 02 a1 47
        01 13 a9 fa
        a5 d3 f1 79
        bc 25 f4 b5
        be d2 b9 d9
        00 08 00 14
        a3 82 95 4e
        4b e6 7b f1
        17 84 c9 7c
        82 92 c2 75
        bf e3 ed 41
        80 28 00 04
        c8 fb 0b 4c
        ",
    );

    let msg = Message::decode(&bytes).expect("decode ipv6 response");
    assert_eq!(msg.class(), Class::SuccessResponse);

    let expected_ip: Ipv6Addr = "2001:db8:1234:5678:11:2233:4455:6677".parse().unwrap();
    let expected = SocketAddr::new(expected_ip.into(), 32853);
    let mut saw_addr = false;
    for attr in msg.attributes() {
        if let Attribute::XorMappedAddress(addr) = attr {
            assert_eq!(*addr, expected);
            saw_addr = true;
        }
    }
    assert!(saw_addr, "XOR-MAPPED-ADDRESS present");

    let key = auth::short_term_key(SHORT_TERM_PASSWORD);
    msg.verify_message_integrity(&key).unwrap();
    msg.verify_fingerprint().unwrap();
}

/// RFC 5769 §2.4 — Sample Request with Long-Term Authentication.
///
/// This message pads with zero bytes, exactly as our encoder does, so the
/// rebuilt message must reproduce the published bytes exactly.
#[test]
fn sample_long_term_auth() {
    let bytes = hex(
        "
        00 01 00 60
        21 12 a4 42
        78 ad 34 33
        c6 ad 72 c0
        29 da 41 2e
        00 06 00 12
        e3 83 9e e3
        83 88 e3 83
        aa e3 83 83
        e3 82 af e3
        82 b9 00 00
        00 15 00 1c
        66 2f 2f 34
        39 39 6b 39
        35 34 64 36
        4f 4c 33 34
        6f 4c 39 46
        53 54 76 79
        36 34 73 41
        00 14 00 0b
        65 78 61 6d
        70 6c 65 2e
        6f 72 67 00
        00 08 00 14
        f6 70 24 65
        6d d6 4a 3e
        02 b8 e0 71
        2e 85 c9 a2
        8c a8 96 66
        ",
    );

    let msg = Message::decode(&bytes).expect("decode long-term request");
    assert_eq!(msg.method(), Method::Binding);
    assert_eq!(msg.class(), Class::Request);

    let username = "マトリックス";
    let realm = "example.org";
    let password = "TheMatrIX";
    let nonce = "f//499k954d6OL34oL9FSTvy64sA";

    let mut saw_user = false;
    let mut saw_realm = false;
    let mut saw_nonce = false;
    for attr in msg.attributes() {
        match attr {
            Attribute::Username(u) => {
                assert_eq!(u, username);
                saw_user = true;
            }
            Attribute::Realm(r) => {
                assert_eq!(r, realm);
                saw_realm = true;
            }
            Attribute::Nonce(n) => {
                assert_eq!(n, nonce);
                saw_nonce = true;
            }
            _ => {}
        }
    }
    assert!(saw_user && saw_realm && saw_nonce);

    let key = auth::long_term_key(username, realm, password);
    msg.verify_message_integrity(&key)
        .expect("long-term MESSAGE-INTEGRITY must verify");

    // Padding matches (zeros), so the rebuilt bytes must be identical.
    let rebuilt = Message::builder(Method::Binding, Class::Request)
        .transaction_id(*msg.transaction_id())
        .attribute(Attribute::Username(username.to_owned()))
        .attribute(Attribute::Nonce(nonce.to_owned()))
        .attribute(Attribute::Realm(realm.to_owned()))
        .with_message_integrity_sha1(&key)
        .build()
        .unwrap();
    assert_eq!(rebuilt.encode(), bytes, "rebuilt long-term request bytes");
}
