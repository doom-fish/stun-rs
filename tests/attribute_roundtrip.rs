//! Round-trip encode/decode tests for every supported attribute.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use stun::{Attribute, Class, Message, Method, TransactionId};

fn roundtrip(attrs: Vec<Attribute>) -> Vec<Attribute> {
    let mut builder = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::from_bytes([7u8; 12]));
    for a in attrs {
        builder = builder.attribute(a);
    }
    let bytes = builder.build().unwrap().encode();
    let decoded = Message::decode(&bytes).expect("decode");
    decoded.attributes().to_vec()
}

#[test]
fn mapped_and_xor_mapped_ipv4() {
    let addr = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 9).into(), 50000);
    let out = roundtrip(vec![
        Attribute::MappedAddress(addr),
        Attribute::XorMappedAddress(addr),
    ]);
    assert_eq!(out[0], Attribute::MappedAddress(addr));
    assert_eq!(out[1], Attribute::XorMappedAddress(addr));
}

#[test]
fn mapped_and_xor_mapped_ipv6() {
    let ip: Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
    let addr = SocketAddr::new(ip.into(), 443);
    let out = roundtrip(vec![
        Attribute::MappedAddress(addr),
        Attribute::XorMappedAddress(addr),
    ]);
    assert_eq!(out[0], Attribute::MappedAddress(addr));
    assert_eq!(out[1], Attribute::XorMappedAddress(addr));
}

#[test]
fn text_attributes() {
    let out = roundtrip(vec![
        Attribute::Username("alice:bob".to_owned()),
        Attribute::Realm("realm.example".to_owned()),
        Attribute::Nonce("nonce-value-123".to_owned()),
        Attribute::Software("stun-rs/0.1".to_owned()),
    ]);
    assert_eq!(out[0], Attribute::Username("alice:bob".to_owned()));
    assert_eq!(out[1], Attribute::Realm("realm.example".to_owned()));
    assert_eq!(out[2], Attribute::Nonce("nonce-value-123".to_owned()));
    assert_eq!(out[3], Attribute::Software("stun-rs/0.1".to_owned()));
}

#[test]
fn unknown_attributes_list() {
    let out = roundtrip(vec![Attribute::UnknownAttributes(vec![0x0001, 0x8022, 0x0024])]);
    assert_eq!(
        out[0],
        Attribute::UnknownAttributes(vec![0x0001, 0x8022, 0x0024])
    );
}

#[test]
fn unknown_passthrough_attribute() {
    let out = roundtrip(vec![Attribute::Unknown {
        attribute_type: 0x7fff,
        value: vec![1, 2, 3, 4, 5],
    }]);
    assert_eq!(
        out[0],
        Attribute::Unknown {
            attribute_type: 0x7fff,
            value: vec![1, 2, 3, 4, 5],
        }
    );
}

#[test]
fn attribute_type_codes() {
    assert_eq!(
        Attribute::Software(String::new()).attribute_type(),
        0x8022
    );
    assert_eq!(Attribute::Priority(0).attribute_type(), 0x0024);
    assert_eq!(Attribute::UseCandidate.attribute_type(), 0x0025);
    assert_eq!(Attribute::IceControlled(0).attribute_type(), 0x8029);
    assert_eq!(Attribute::IceControlling(0).attribute_type(), 0x802a);
}
