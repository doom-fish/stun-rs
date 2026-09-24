# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Security

- `Message::get` and `Message::attributes` returned attributes that follow
  MESSAGE-INTEGRITY, which RFC 5389 §15.4 and RFC 8489 §9 say a receiver must
  ignore. An on-path attacker could append USE-CANDIDATE and a recomputed
  FINGERPRINT to an authentic check and make ice-rs nominate the pair. Only
  processed attributes are visible now (see Changed). Integrity verification
  uses the same rule.
- `integrity::hmac_sha256` returned an all-zero MAC when the CryptoKit bridge
  failed. It now returns an error.
- `MessageBuilder`'s `Debug` printed the MESSAGE-INTEGRITY keys. It is
  redacted now, and the builder's keys and the derived credential keys are
  zeroized on drop.

### Fixed

- `StunClient::bind` leaked a receiver thread and a socket on every call.
  The thread stayed blocked in a receive until another datagram arrived. The
  connection is now cancelled and the thread joined before `bind` returns.
- Each unrelated datagram used up one of `bind`'s retransmission waits, and
  error responses were ignored until the ~20 s timeout. Waits now run against
  a deadline, and an error response ends the transaction at once. Responses
  are matched by transaction ID, and the socket is connected to the server,
  so datagrams from other source addresses are never delivered.
- `bind` gave up after ~19.75 s and sent its last retransmission just as it
  gave up. The schedule now follows RFC 5389 §7.2.1: seven requests and a
  final wait of 16 RTOs, 39.5 s in total with a 500 ms RTO.
- With networkframework 0.14, an oversized datagram ended `bind`'s receive
  loop. Oversized datagrams, and responses whose FINGERPRINT does not verify,
  are now skipped.
- `ffi::commoncrypto::md5` panicked on inputs larger than 4 GiB. It now streams
  through `CC_MD5_Init` / `CC_MD5_Update` / `CC_MD5_Final`.
- `MessageBuilder::new` panicked if the system RNG failed. The random
  transaction ID is now drawn in `build` with `TransactionId::try_random`,
  and only when none was set.
- COVERAGE.md said ALTERNATE-SERVER was decoded as `Unknown`, and the README
  promised 7 retransmits. Both are corrected.
- The README states that binaries need macOS 14 or later, the deployment
  target of networkframework's Swift bridge; cryptokit-rs 0.3 also links
  security-rs and apple-cf, whose Swift bridges target macOS 12 and 13. 0.1.0
  had the same requirement, and the README claimed other Apple platforms,
  which none of the Swift bridges build for.

### Changed

- **Breaking:** `get` and `attributes` return only processed attributes:
  everything up to the first integrity attribute, then MESSAGE-INTEGRITY-SHA256
  (after MESSAGE-INTEGRITY) and FINGERPRINT. The rest are in
  `Message::ignored_attributes`.
- **Breaking:** `MessageBuilder::build` returns `Result<Message>` and
  `build_and_encode` returns `Result<Vec<u8>>`.
- **Breaking:** `integrity::hmac_sha256` returns `Result<[u8; 32]>`.
- **Breaking:** `Message::encode` returns the bytes a message was decoded
  from, so a decoded message keeps a peer's padding and its MAC stays valid.
  It used to re-serialize with zero padding.
- **Breaking:** `Message::decode` rejects a message length that is not a
  multiple of 4 (`Error::BadMessageLength`), any attribute after FINGERPRINT,
  and a MESSAGE-INTEGRITY-SHA256 value that is not 16–32 bytes and a multiple
  of 4. `build` rejects the same, and also bodies larger than 65 535 bytes.
- **Breaking:** `auth::short_term_key` and `auth::long_term_key` return
  `Zeroizing<Vec<u8>>`. `long_term_key` used to return `[u8; 16]`.
- **Breaking:** `RetransmitSchedule` yields seven waits (1, 2, 4, 8, 16, 32
  and 16 RTOs). Resend only when another wait follows. `DEFAULT_MAX_RETRANSMITS`
  is 6 (was 9, never reached), and `TOTAL_TIMEOUT_RTO_MULTIPLIER` is replaced by
  `FINAL_WAIT_RTO_MULTIPLIER`.
- **Breaking:** `StunClient::bind` fails immediately with
  `Error::ErrorResponse`, `Error::UnknownAttributes` (unknown
  comprehension-required attributes in the response, RFC 8489 §6.3.3; the
  attribute types RFC 5389 §18.2 reserves from RFC 3489 are ignored, as
  §12.1 requires) or
  `Error::Network` if the receive fails.
- **Breaking:** requires cryptokit-rs 0.3 (`>=0.3, <0.4`) and
  networkframework 0.14 (`>=0.14, <0.15`).
- `rust-version` is 1.82. The unused `libc` dependency is removed, and
  `zeroize` (`>=1.6, <1.9`) is added.

### Added

- `Message::ignored_attributes`, `Message::unknown_comprehension_required` and
  `Message::unknown_attribute_response` (the 420 Unknown Attribute response).
- `StunClient::rto` to set the initial retransmission timeout.
- `Error::{Crypto, BadMessageLength, ErrorResponse, UnknownAttributes}` and
  `transaction::FINAL_WAIT_RTO_MULTIPLIER`.
- Tests for attribute scope (including a USE-CANDIDATE injected after
  MESSAGE-INTEGRITY), validation and 420 handling, RFC 4231 HMAC-SHA256,
  RFC 1321 MD5, the retransmission schedule, and `StunClient::bind` against a
  local server on 127.0.0.1.

## [0.1.0] - 2026-06-04

Initial release.

### Added

- STUN message codec ([RFC 5389] / [RFC 8489]): 20-byte header, method/class
  bit-interleaving, and TLV attributes with 4-byte padding.
- `MAPPED-ADDRESS` and `XOR-MAPPED-ADDRESS` for IPv4 and IPv6.
- `MESSAGE-INTEGRITY` (HMAC-SHA1) and `MESSAGE-INTEGRITY-SHA256`, computed and
  verified over the original wire bytes per RFC 5389 §15.4.
- `FINGERPRINT` (CRC-32) with a dependency-free CRC-32 implementation.
- Short-term and long-term credential key derivation
  (`MD5(username:realm:password)`).
- ICE attributes ([RFC 8445]): `PRIORITY`, `USE-CANDIDATE`, `ICE-CONTROLLED`,
  `ICE-CONTROLLING`.
- `ERROR-CODE`, `UNKNOWN-ATTRIBUTES`, `REALM`, `NONCE`, `SOFTWARE`,
  `USERNAME`, and a pass-through `Unknown` variant for unrecognized attributes.
- Synchronous `StunClient` over Network.framework UDP with RFC 5389
  retransmission (RTO doubling, 7 retransmits, ~39.5×RTO total budget).
- `StunUri` / `Endpoint` parsing for `stun:` / `stuns:` URIs and `host:port`
  (including bracketed IPv6).
- Transaction-ID generation via `SecRandomCopyBytes`.
- All [RFC 5769] canonical test vectors pass.

### Known limitations

- **Blocking receiver thread on timeout.** Network.framework's UDP receive
  blocks indefinitely with no native timeout, so `StunClient` runs the receive
  loop on a background thread feeding an `mpsc` channel while the caller drives
  retransmission. When a request times out with no response, that background
  thread stays parked until the next inbound datagram or socket teardown
  unblocks it. This is harmless for one-shot queries but should be revisited if
  the client is reused for many concurrent transactions.
- **SASLprep is the identity function.** Short-term credential keys use the raw
  password bytes. RFC 8489 §9.1.1 specifies `SASLprep(password)`, which is the
  identity for the printable-ASCII `ice-pwd` mandated by RFC 8445 §5.3.
  Non-ASCII passwords are passed through unchanged rather than normalized.

[RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
[RFC 8489]: https://www.rfc-editor.org/rfc/rfc8489
[RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
[RFC 5769]: https://www.rfc-editor.org/rfc/rfc5769
[0.2.0]: https://github.com/doom-fish/stun-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/doom-fish/stun-rs/releases/tag/v0.1.0
