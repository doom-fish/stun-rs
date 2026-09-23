# stun

[![crates.io](https://img.shields.io/badge/crates.io-unpublished-lightgrey.svg)](https://github.com/doom-fish/stun-rs)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A pure-Rust **STUN** (Session Traversal Utilities for NAT) message codec and
synchronous client, implementing [RFC 5389] (updated by [RFC 8489]) with the
full set of attributes used by ICE ([RFC 8445]) connectivity checks.

It is built for WebRTC peers and other ICE-compliant endpoints that need to
build and parse STUN messages and discover their server-reflexive address
through a NAT.

## Features

- **Message codec** — 20-byte header and TLV attributes with correct 4-byte
  padding semantics, including the method/class bit-interleaving of
  RFC 5389 §6.
- **Addresses** — `MAPPED-ADDRESS` and `XOR-MAPPED-ADDRESS` for both IPv4 and
  IPv6.
- **Integrity** — `MESSAGE-INTEGRITY` (HMAC-SHA1) and
  `MESSAGE-INTEGRITY-SHA256`, computed and verified over the exact wire bytes
  (RFC 5389 §15.4 / RFC 8489 §14.5).
- **Fingerprint** — `FINGERPRINT` (CRC-32) with a built-in, dependency-free
  CRC-32 implementation.
- **Credentials** — short-term and long-term key derivation
  (`MD5(username:realm:password)`).
- **ICE attributes** — `PRIORITY`, `USE-CANDIDATE`, `ICE-CONTROLLED`, and
  `ICE-CONTROLLING`.
- **Client** — a synchronous [`StunClient`] over Network.framework UDP with
  RFC 5389 retransmission (RTO doubling, 7 retransmits).
- **RFC 5769 verified** — every canonical test vector from RFC 5769 is checked
  in the test suite.

Cryptography is provided entirely by Apple system libraries — HMAC-SHA256 via
CryptoKit, and HMAC-SHA1 / MD5 via CommonCrypto — and the transaction-ID RNG
uses `SecRandomCopyBytes`. There are **no third-party runtime dependencies**.

## Quick start

Build and encode a Binding request, then decode it and verify it:

```rust
use stun::{auth, Attribute, Class, Message, Method, TransactionId};

let key = auth::short_term_key("ice-password");

let message = Message::builder(Method::Binding, Class::Request)
    .transaction_id(TransactionId::random())
    .attribute(Attribute::Software("doomfish-stun/0.1".to_owned()))
    .attribute(Attribute::Priority(0x6e00_01ff))
    .with_message_integrity_sha1(&key)
    .with_fingerprint()
    .build()
    .unwrap();

let bytes = message.encode();
let decoded = Message::decode(&bytes).unwrap();
decoded.verify_message_integrity(&key).unwrap();
decoded.verify_fingerprint().unwrap();
```

Discover your server-reflexive address against a public STUN server:

```rust,no_run
use stun::{Endpoint, StunClient};

let client = StunClient::new().fingerprint(true);
let endpoint: Endpoint = "stun:stun.l.google.com:19302".parse().unwrap();
let reflexive = client.bind(&endpoint).unwrap();
println!("My public address is {reflexive}");
```

## Examples

```sh
# Build a request and hex-dump it (offline):
cargo run --example 01_binding_request

# Live query against a public STUN server (network access):
STUN_LIVE_TESTS=1 cargo run --example 02_stun_query
STUN_LIVE_TESTS=1 cargo run --example 02_stun_query -- stun:stun.l.google.com:19302
```

## Platform

This crate targets **macOS** (and other Apple platforms): it links against
`Security`, CommonCrypto (in `libSystem`), and uses Network.framework for UDP
via the sibling `networkframework` crate.

## Minimum Supported Rust Version

Rust **1.82**.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

[RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
[RFC 8489]: https://www.rfc-editor.org/rfc/rfc8489
[RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
[`StunClient`]: https://docs.rs/stun
