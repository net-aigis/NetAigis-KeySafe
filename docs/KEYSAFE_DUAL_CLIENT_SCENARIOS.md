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
  (`KdbxLiveRealCiphertextIntegrationTest`; still no KeePassXC)

## Still required before clearing the dual-client gate blocker

| Scenario | Status |
| --- | --- |
| KeePassXC opens and edits the shared KDBX against the real coordinator | open |
| Android opens the same revision the XC client just published | open |
| Second client detects an active lease held by the first | open |
| Lease expiry / lease loss during an edit on each client | open |
| Interrupted upload with real KDBX ciphertext on XC and Android | open (Android AES-KDF happy-path publish proven; interrupt+XC still open) |
| Interrupted download with real KDBX ciphertext on XC and Android | open (Android AES-KDF happy-path download/reload proven; interrupt+XC still open) |
| Offline edit on Android only, then reconnect | partial (cache/recovery unit tests; not XC) |
| Offline edit on desktop only, then reconnect | open |
| Two independent offline edits, reconnect in either order | open |
| Simultaneous publish attempts with real KDBX | open |
| Crash during save + recovery reopen on the same client | partial (Android recovery unit tests) |
| Re-open every produced KDBX in **both** KeePassXC and KeySafe | open |
| Assembled ciphertext round-trip under AES-KDF (JVM) | proven (`KdbxAssembledCiphertextWriterTest`; does not authorize publish) |
| Assembled ciphertext round-trip under native Argon2 / forced-native AES | open (DX harness: `KdbxAssembledCiphertextArgon2InstrumentedTest`; not in default CI unit job; needs device/emulator) |

## XC checkout for interop

Use `/home/friseer/keepass-pr-submission-20261014/xc` at the coordinated-KDBX
feature tip `a8466cce` on `feature/coordinated-kdbx-20261014`: HTTP/file body
bounds, TLS 1.2+/fail-closed SSL, and settings-UI validation of URL/ID/token
(64 MiB KDBX / 16 KiB control, aligned with KeySafe). Those XC-only changes are
not dual-client proof.
