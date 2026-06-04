# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024

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
[0.1.0]: https://github.com/doom-fish/stun-rs/releases/tag/v0.1.0
