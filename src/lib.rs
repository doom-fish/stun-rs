//! `stun` — a pure-Rust STUN (Session Traversal Utilities for NAT) message
//! codec and synchronous client.
//!
//! This crate implements [RFC 5389] (updated by [RFC 8489]) with the full set
//! of attributes that ICE ([RFC 8445]) uses for connectivity checks, so that
//! WebRTC peers and other ICE-compliant endpoints can build and parse STUN
//! messages and discover their server-reflexive address.
//!
//! # Highlights
//!
//! * 20-byte header and TLV attribute [codec][message] with correct 4-byte
//!   padding semantics.
//! * `MAPPED-ADDRESS` / `XOR-MAPPED-ADDRESS` for IPv4 and IPv6.
//! * `MESSAGE-INTEGRITY` (HMAC-SHA1) and `MESSAGE-INTEGRITY-SHA256`, including
//!   the synthetic-header-length trick from RFC 5389 §15.4.
//! * `FINGERPRINT` (CRC-32) with no external CRC dependency.
//! * Short-term and long-term [credential][auth] key derivation.
//! * The ICE attributes `PRIORITY`, `USE-CANDIDATE`, `ICE-CONTROLLED`, and
//!   `ICE-CONTROLLING`.
//! * A synchronous [`StunClient`] over Network.framework UDP with RFC 5389
//!   retransmission.
//!
//! Cryptography is provided by Apple system libraries: HMAC-SHA256 via
//! CryptoKit, and HMAC-SHA1 / MD5 via CommonCrypto. The transaction-ID RNG
//! uses `SecRandomCopyBytes`. There are no third-party runtime dependencies.
//!
//! # Example
//!
//! ```no_run
//! use stun::{Attribute, Class, Endpoint, Message, Method, StunClient, TransactionId};
//!
//! // Build and encode a Binding request.
//! let request = Message::builder(Method::Binding, Class::Request)
//!     .transaction_id(TransactionId::random())
//!     .attribute(Attribute::Software("doomfish-stun/0.1".into()))
//!     .with_message_integrity_sha1(b"ice-password")
//!     .with_fingerprint()
//!     .build();
//! let bytes = request.encode();
//!
//! // Decode it again.
//! let decoded = Message::decode(&bytes).unwrap();
//! assert_eq!(decoded.method(), Method::Binding);
//!
//! // High-level query against a public STUN server.
//! let client = StunClient::new();
//! let endpoint: Endpoint = "stun:stun.l.google.com:19302".parse().unwrap();
//! let _mapped = client.bind(&endpoint);
//! ```
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
//! [RFC 8489]: https://www.rfc-editor.org/rfc/rfc8489
//! [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod address;
pub mod attribute;
pub mod auth;
pub mod client;
pub mod crc32;
pub mod error;
pub mod ffi;
pub mod fingerprint;
pub mod integrity;
pub mod message;
pub mod rng;
pub mod transaction;

pub use attribute::{Attribute, ErrorCode, PasswordAlgorithm};
pub use client::{Endpoint, MappedAddress, StunClient, StunUri};
pub use error::{Error, Result};
pub use message::{Class, MAGIC_COOKIE, Message, MessageBuilder, MessageType, Method};
pub use transaction::{RetransmitSchedule, TransactionId};
