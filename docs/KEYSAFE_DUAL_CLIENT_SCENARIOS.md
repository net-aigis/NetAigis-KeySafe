# KeySafe dual-client scenarios (phase 4)

Automatic merge/publish stays denied until these scenarios are evidenced.
Android↔Go loopback protocol coverage (`KEYSAFE_INTEGRATION_TESTS.md`) is
**not** dual-client proof: it uses dummy ciphertext and no KeePassXC.

## Proven today (Android ↔ Go, dummy bytes only)

- Exclusive lease, read-only observer, successive writes, lock handoff
- Concurrent lease acquisition (one winner)
- External lease revocation blocks stale overwrite
- PUT committed but HTTP acknowledgement lost
- PUT interrupted before the coordinator sees the body

## Still required before clearing the dual-client gate blocker

| Scenario | Status |
| --- | --- |
| KeePassXC opens and edits the shared KDBX against the real coordinator | open |
| Android opens the same revision the XC client just published | open |
| Second client detects an active lease held by the first | open |
| Lease expiry / lease loss during an edit on each client | open |
| Interrupted upload with real KDBX ciphertext on XC and Android | open |
| Interrupted download with real KDBX ciphertext on XC and Android | open |
| Offline edit on Android only, then reconnect | partial (cache/recovery unit tests; not XC) |
| Offline edit on desktop only, then reconnect | open |
| Two independent offline edits, reconnect in either order | open |
| Simultaneous publish attempts with real KDBX | open |
| Crash during save + recovery reopen on the same client | partial (Android recovery unit tests) |
| Re-open every produced KDBX in **both** KeePassXC and KeySafe | open |
| Assembled ciphertext round-trip under native AES/Argon2 | open (JVM unit tests cannot load `libaes`/`libargon2`) |

## XC checkout for interop

Use `/home/friseer/keepass-pr-submission-20261014/xc` at the coordinated-KDBX
feature tip. Phase-5 HTTP body bounds for `KdbxCoordinatorClient` live on
`security/kdbx-bound-http-bodies-4b2a3ce6` (64 MiB KDBX / 16 KiB control,
aligned with KeySafe). That change is not dual-client proof and is not yet
fast-forwarded onto `feature/coordinated-kdbx-20261014` until XC CI confirms it.
