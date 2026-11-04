# KeySafe dual-client scenarios (phase 4)

Automatic merge/publish stays denied until these scenarios are evidenced.
Android↔Go loopback protocol coverage (`KEYSAFE_INTEGRATION_TESTS.md`) is
**not** dual-client proof with KeePassXC, even when real AES-KDF ciphertext is used.

## Proven today (Android ↔ Go)

- Exclusive lease, read-only observer, successive writes, lock handoff (dummy bytes)
- Concurrent lease acquisition (one winner)
- External lease revocation blocks stale overwrite
- PUT committed but HTTP acknowledgement lost
- PUT interrupted before the coordinator sees the body
- Assembled AES-KDF KDBX publish + strict reload through the live Go coordinator
- Interrupted / lost-ack real AES-KDF upload fault cases (Android↔Go only)
- Truncated and reject-before-forward real AES-KDF download fault cases
  (Android↔Go only; retry/direct reader still reloads ciphertext)
- Second Android client sees busy lease on a real-ciphertext database id
  (`KdbxLiveRealCiphertextIntegrationTest`; still no KeePassXC)
- External lease revocation blocks a stale Android publish of real AES-KDF
  ciphertext; the new owner’s revision reloads (Android↔Go only)
- Two concurrent real AES-KDF PUTs on the same lease/If-Match base: exactly one
  winner, one stale (412); committed ciphertext reloads (Android↔Go only)
- Mismatched ETag on real AES-KDF download fails closed; direct reader still
  reloads server ciphertext (Android↔Go only)
- Failed lease renew after a real AES-KDF publish marks the lease lost and
  blocks further writes; server ciphertext stays (Android↔Go only)

## Still required before clearing the dual-client gate blocker

| Scenario | Status |
| --- | --- |
| KeePassXC opens and edits the shared KDBX against the real coordinator | open |
| Android opens the same revision the XC client just published | open |
| Lease expiry / lease loss during an edit on each client | partial (Android external revocation + renew failure after real AES-KDF publish; XC still open) |
| Interrupted upload with real KDBX ciphertext on XC and Android | partial (Android AES-KDF interrupt+lost-ack proven; XC still open) |
| Interrupted download with real KDBX ciphertext on XC and Android | partial (Android AES-KDF truncate+reject-before-forward proven; XC still open) |
| Second client detects an active lease held by the first | partial (Android↔Go busy lease proven; XC still open) |
| Offline edit on Android only, then reconnect | partial (cache/recovery unit tests; not XC) |
| Offline edit on desktop only, then reconnect | open |
| Two independent offline edits, reconnect in either order | open |
| Simultaneous publish attempts with real KDBX | partial (Android↔Go same-base race: one win / one 412; XC still open) |
| Crash during save + recovery reopen on the same client | partial (Android recovery unit tests) |
| Re-open every produced KDBX in **both** KeePassXC and KeySafe | open |
| Assembled ciphertext round-trip under AES-KDF (JVM) | proven (`KdbxAssembledCiphertextWriterTest`; does not authorize publish) |
| Assembled ciphertext round-trip under native Argon2 / forced-native AES | open (DX harness: `KdbxAssembledCiphertextArgon2InstrumentedTest`; not in default CI unit job; needs device/emulator) |

## XC checkout for interop

Use `/home/friseer/keepass-pr-submission-20261014/xc` at the coordinated-KDBX
feature tip `f8217b74` on `feature/coordinated-kdbx-20261014`: HTTP/file body
bounds, TLS 1.2+/fail-closed SSL, settings-UI validation, shared client config checks, unit-tested lease-response parsing, publish-ack matching,
download hash/ETag binding, shared JSON field extraction, and CoordinatorByteLimits (64 MiB KDBX / 16 KiB
control, aligned with KeySafe). Those XC-only changes are not dual-client proof.
