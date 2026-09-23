# Coverage

This document tracks which parts of the STUN family of specifications this
crate implements, and what is intentionally deferred.

## Specifications

| Spec | Title | Status |
| ---- | ----- | ------ |
| [RFC 5389] | Session Traversal Utilities for NAT (STUN) | Core implemented |
| [RFC 8489] | STUN (bis) | Integrity-SHA256, password algorithms partial |
| [RFC 8445] | Interactive Connectivity Establishment (ICE) | Check attributes implemented |
| [RFC 5769] | STUN Test Vectors | All vectors pass |

## Attributes

| Attribute | Type | Encode | Decode | Notes |
| --------- | ---- | ------ | ------ | ----- |
| `MAPPED-ADDRESS` | `0x0001` | ✅ | ✅ | IPv4 + IPv6 |
| `USERNAME` | `0x0006` | ✅ | ✅ | UTF-8 |
| `MESSAGE-INTEGRITY` | `0x0008` | ✅ | ✅ | HMAC-SHA1, verified over wire bytes; later attributes ignored (RFC 8489 §9) |
| `ERROR-CODE` | `0x0009` | ✅ | ✅ | class/number/reason |
| `UNKNOWN-ATTRIBUTES` | `0x000A` | ✅ | ✅ | list of `u16`; 420 response via `unknown_attribute_response` |
| `REALM` | `0x0014` | ✅ | ✅ | UTF-8 |
| `NONCE` | `0x0015` | ✅ | ✅ | UTF-8 |
| `MESSAGE-INTEGRITY-SHA256` | `0x001C` | ✅ | ✅ | HMAC-SHA256 via CryptoKit; 16–32 bytes, multiple of 4; verification needs the full 32 |
| `PASSWORD-ALGORITHM` | `0x001D` | ⚠️ | ⚠️ | struct present; not negotiated by client |
| `XOR-MAPPED-ADDRESS` | `0x0020` | ✅ | ✅ | IPv4 + IPv6 |
| `PRIORITY` | `0x0024` | ✅ | ✅ | ICE |
| `USE-CANDIDATE` | `0x0025` | ✅ | ✅ | ICE, zero-length |
| `SOFTWARE` | `0x8022` | ✅ | ✅ | UTF-8 |
| `ALTERNATE-SERVER` | `0x8023` | ✅ | ✅ | IPv4 + IPv6; the client does not follow redirects |
| `FINGERPRINT` | `0x8028` | ✅ | ✅ | CRC-32; must be the last attribute |
| `ICE-CONTROLLED` | `0x8029` | ✅ | ✅ | ICE tie-breaker |
| `ICE-CONTROLLING` | `0x802A` | ✅ | ✅ | ICE tie-breaker |
| _any other_ | — | ✅ | ✅ | preserved via `Attribute::Unknown`; comprehension-required ones reported by `unknown_comprehension_required` |

✅ implemented · ⚠️ partial / passthrough

## Deferred

The following are out of scope for `0.2.0` and are decoded as
`Attribute::Unknown` (preserving their bytes) rather than rejected:

- `PADDING`, `RESPONSE-PORT`, `RESPONSE-ORIGIN`, `OTHER-ADDRESS`,
  `CHANGE-REQUEST` and the other RFC 5780 NAT-behavior-discovery attributes.
- TURN attributes (RFC 5766 / RFC 8656): `CHANNEL-NUMBER`, `LIFETIME`,
  `XOR-PEER-ADDRESS`, `DATA`, `XOR-RELAYED-ADDRESS`, `REQUESTED-TRANSPORT`,
  etc. This crate is STUN-only; it is not a TURN client.
- Full `PASSWORD-ALGORITHM(S)` negotiation for the RFC 8489 long-term
  mechanism. The key-derivation primitives (`MD5`-based long-term key) are
  present; algorithm agility is not yet wired into the client.
- `ALTERNATE-SERVER` redirection handling in the client.

## Cryptographic backends

| Primitive | Source | Reason |
| --------- | ------ | ------ |
| HMAC-SHA1 | CommonCrypto `CCHmac` (`kCCHmacAlgSHA1`) | CryptoKit exposes SHA-1 only as an `Insecure` hash, with no HMAC-SHA1 |
| MD5 | CommonCrypto `CC_MD5_Init` / `CC_MD5_Update` / `CC_MD5_Final` | Required by RFC 5389 §15.4 long-term key; not in CryptoKit's safe surface |
| HMAC-SHA256 | CryptoKit (`cryptokit` crate) | Safe, modern HMAC for RFC 8489 |
| CRC-32 | in-crate table | No dependency needed |
| Random | `SecRandomCopyBytes` | CSPRNG for transaction IDs |

## Test coverage

- `tests/rfc5769_vectors.rs` — all four RFC 5769 canonical messages
  (request, IPv4 response, IPv6 response, long-term auth).
- `tests/attribute_roundtrip.rs` — encode/decode round trips for every
  supported attribute, IPv4 and IPv6.
- `tests/ice_attributes.rs` — wire-format checks for ICE attributes.
- `tests/padding_edge_cases.rs` — 0/1/2/3/4/7-byte values and padding rules.
- `tests/adversarial.rs` — truncation, bad cookie, bad type, overruns, bad
  UTF-8, integrity/fingerprint mismatch.
- `tests/integrity_scope.rs` — attributes after `MESSAGE-INTEGRITY` are
  ignored, including a `USE-CANDIDATE` appended with a recomputed
  `FINGERPRINT`.
- `tests/validation.rs` — length alignment, `FINGERPRINT` placement,
  `MESSAGE-INTEGRITY-SHA256` lengths, oversized messages, 420 handling.
- `tests/integrity_sha256.rs`, `tests/secrets.rs` — RFC 4231 HMAC-SHA256,
  RFC 1321 MD5, key derivation, constant-time compare, redacted `Debug`.
- `tests/retransmit_schedule.rs`, `tests/client_loopback.rs` — the RFC 5389
  schedule and `StunClient::bind` against a local server on 127.0.0.1
  (unrelated datagrams, error responses, a forged response from another
  port, timeouts, socket shutdown).

[RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
[RFC 8489]: https://www.rfc-editor.org/rfc/rfc8489
[RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
[RFC 5769]: https://www.rfc-editor.org/rfc/rfc5769
