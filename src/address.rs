//! `MAPPED-ADDRESS` and `XOR-MAPPED-ADDRESS` value codecs (RFC 5389 §15.1,
//! §15.2).
//!
//! Both attributes share a layout: one reserved byte, a one-byte address
//! family (`0x01` for IPv4, `0x02` for IPv6), a 16-bit port, then the address.
//! For the XOR variant the port is XORed with the top 16 bits of the magic
//! cookie and the address is XORed with the magic cookie (IPv4) or the
//! magic-cookie-concatenated-with-transaction-ID (IPv6).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{Error, Result};

/// Address family value for IPv4.
const FAMILY_IPV4: u8 = 0x01;

/// Address family value for IPv6.
const FAMILY_IPV6: u8 = 0x02;

/// The 16-byte XOR key (`magic-cookie || transaction-id`) taken from a STUN
/// header. Bytes `0..4` are the magic cookie; bytes `4..16` are the
/// transaction ID.
pub type XorKey = [u8; 16];

/// Encode a plain (`MAPPED-ADDRESS`) socket address into `out`.
pub(crate) fn encode_mapped(addr: SocketAddr, out: &mut Vec<u8>) {
    out.push(0); // reserved
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(FAMILY_IPV4);
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(FAMILY_IPV6);
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Decode a plain (`MAPPED-ADDRESS`) socket address.
pub(crate) fn decode_mapped(value: &[u8]) -> Result<SocketAddr> {
    if value.len() < 4 {
        return Err(Error::MalformedAttribute("MAPPED-ADDRESS too short"));
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        FAMILY_IPV4 => {
            let octets: [u8; 4] = value
                .get(4..8)
                .ok_or(Error::MalformedAttribute("IPv4 address truncated"))?
                .try_into()
                .expect("slice is 4 bytes");
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            let octets: [u8; 16] = value
                .get(4..20)
                .ok_or(Error::MalformedAttribute("IPv6 address truncated"))?
                .try_into()
                .expect("slice is 16 bytes");
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(Error::BadAddressFamily(other)),
    }
}

/// Encode an `XOR-MAPPED-ADDRESS` socket address into `out`.
pub(crate) fn encode_xor(addr: SocketAddr, key: &XorKey, out: &mut Vec<u8>) {
    let xport = addr.port() ^ u16::from_be_bytes([key[0], key[1]]);
    out.push(0); // reserved
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(FAMILY_IPV4);
            out.extend_from_slice(&xport.to_be_bytes());
            let mut octets = v4.octets();
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            out.extend_from_slice(&octets);
        }
        IpAddr::V6(v6) => {
            out.push(FAMILY_IPV6);
            out.extend_from_slice(&xport.to_be_bytes());
            let mut octets = v6.octets();
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            out.extend_from_slice(&octets);
        }
    }
}

/// Decode an `XOR-MAPPED-ADDRESS` socket address.
pub(crate) fn decode_xor(value: &[u8], key: &XorKey) -> Result<SocketAddr> {
    if value.len() < 4 {
        return Err(Error::MalformedAttribute("XOR-MAPPED-ADDRESS too short"));
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ u16::from_be_bytes([key[0], key[1]]);
    match family {
        FAMILY_IPV4 => {
            let raw: [u8; 4] = value
                .get(4..8)
                .ok_or(Error::MalformedAttribute("IPv4 address truncated"))?
                .try_into()
                .expect("slice is 4 bytes");
            let mut octets = raw;
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            let raw: [u8; 16] = value
                .get(4..20)
                .ok_or(Error::MalformedAttribute("IPv6 address truncated"))?
                .try_into()
                .expect("slice is 16 bytes");
            let mut octets = raw;
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(Error::BadAddressFamily(other)),
    }
}
