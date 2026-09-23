# Coverage Audit

`stun` is a protocol implementation, not a 1:1 binding of an Apple framework,
so this audit is framed as an honest accounting of (a) the system symbols it
binds directly and (b) the STUN/ICE protocol surface it covers versus the
relevant RFCs.

## System symbols bound directly

| Symbol | Library | Used for | Bound |
| ------ | ------- | -------- | ----- |
| `SecRandomCopyBytes` | Security.framework | transaction-ID CSPRNG | ✅ |
| `kSecRandomDefault` | Security.framework | default RNG source | ✅ |
| `CC_MD5_Init`, `CC_MD5_Update`, `CC_MD5_Final` | CommonCrypto (libSystem) | long-term credential key | ✅ |
| `CCHmac` | CommonCrypto (libSystem) | HMAC-SHA1 message integrity | ✅ |

HMAC-SHA256 is **not** bound directly here; it is delegated to the sibling
`cryptokit` crate (`cryptokit::hmac::hmac_sha256`), which wraps CryptoKit's
`HMAC<SHA256>`. UDP transport is delegated to the sibling `networkframework`
crate (`Connection` with UDP parameters). Those frameworks are therefore out
of scope for this crate's symbol audit.

### Symbols deliberately not used

- `CC_SHA1` / CryptoKit `Insecure.SHA1` — we need HMAC-SHA1, not bare SHA-1,
  and `CCHmac(kCCHmacAlgSHA1, ...)` provides it in one call.
- `CCHmac(kCCHmacAlgMD5, ...)` — STUN uses MD5 only for key derivation, not as
  an HMAC, so plain MD5 is the correct primitive. The streaming
  `CC_MD5_Init`/`Update`/`Final` calls are used instead of one-shot `CC_MD5`,
  whose 32-bit length would limit the input.
- `arc4random_buf` — `SecRandomCopyBytes` is the documented CSPRNG and returns
  an explicit success/failure code, which we surface as `RngError`.

## Protocol surface vs. RFCs

| Area | RFC | Covered | Gaps |
| ---- | --- | ------- | ---- |
| Message framing | 5389 §6 | ✅ header, method/class, magic cookie | — |
| Attribute TLV + padding | 5389 §15 | ✅ length multiple of 4, `FINGERPRINT` last | — |
| Attributes after integrity | 8489 §9 | ✅ ignored by `get` / `attributes` | available via `ignored_attributes` |
| Unknown comprehension-required | 8489 §6.3 | ✅ detection, 420 response builder; client fails the transaction | servers must send the 420 themselves |
| `XOR-MAPPED-ADDRESS` | 5389 §15.2 | ✅ IPv4 + IPv6 | — |
| `MESSAGE-INTEGRITY` | 5389 §15.4 | ✅ compute + verify | — |
| `FINGERPRINT` | 5389 §15.5 | ✅ compute + verify | — |
| Long-term credentials | 5389 §10.2 | ⚠️ key derivation only | no `401` retry/nonce loop in client |
| Short-term credentials | 5389 §10.1 | ✅ key derivation | SASLprep = identity (ASCII only) |
| `MESSAGE-INTEGRITY-SHA256` | 8489 §14.6 | ✅ | — |
| Password algorithms | 8489 §18.5 | ⚠️ struct only | not negotiated |
| ICE check attributes | 8445 | ✅ `PRIORITY`/`USE-CANDIDATE`/`ICE-CONTROLLED(LING)` | — |
| Retransmission | 5389 §7.2.1 | ✅ 7 requests, RTO doubling, final 16 × RTO wait (39.5 s at 500 ms) | RTO fixed per client (`StunClient::rto`, default 500 ms), not RTT-estimated |
| NAT behavior discovery | 5780 | ❌ | decoded as `Unknown` |
| TURN | 5766 / 8656 | ❌ | out of scope (STUN-only) |

✅ complete · ⚠️ partial · ❌ not implemented (bytes preserved, not rejected)

## Honest notes

- The client does not implement the long-term-credential challenge/response
  loop (send unauthenticated → receive `401` with `REALM`/`NONCE` → retry with
  `MESSAGE-INTEGRITY`). The building blocks (`long_term_key`, `ERROR-CODE`,
  `REALM`, `NONCE`) are all present, but orchestration is left to the caller.
- Retransmission uses a fixed initial RTO (500 ms, the RFC 5389 default,
  unless set with `StunClient::rto`) rather than a measured RTT estimate;
  this is appropriate for one-shot Binding discovery but not for a
  long-lived agent.
- `StunClient::bind` opens its own connected UDP socket per call, so the
  reflexive address it learns belongs to that socket. An ICE agent that
  needs the mapping of its host-candidate socket must run the Binding
  transaction on that socket itself.
- Verification operates on the originally received bytes, so it interoperates
  with peers that pad attributes with non-zero bytes (as RFC 5769 §2.1–2.3 do
  with ASCII spaces). Our own encoder pads with zero bytes.
