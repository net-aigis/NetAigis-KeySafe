# KeySafe dual-client scenarios (phase 4)

Automatic merge/publish stays denied until these scenarios are evidenced.
Android↔Go loopback protocol coverage (`KEYSAFE_INTEGRATION_TESTS.md`) is
**not** dual-client proof with KeePassXC, even when real AES-KDF ciphertext is used.

## Phase status (2026-11-21)

| Slice | Status |
| --- | --- |
| Android↔Go live protocol with real AES-KDF ciphertext + fault matrix | **closed** for this phase (CI on KeySafe `main`) |
| KeePassXC client hardening unit tests (config/lease/ack/limits/status) | **closed** locally (QtTest/podman); GitHub Actions minutes exhausted until month end — local QtTest is the proof path |
| KeePassXC `KdbxCoordinatorClient` live HTTP vs Go coordinator | **closed** locally (`testkdbxcoordinatorclientlive` 9 PASS: round-trip, busy, successive, lease-loss, stale 412, truncated download, rejected publish+retry; Ubuntu podman + host coordinator) |
| XC publish → KeySafe `downloadReadOnly` same tip/SHA-256 | **closed** locally (`xc_ks_bridge_1`; see `.local-dual-client-result.txt`) |
| KeySafe publish → XC `KdbxCoordinatorClient` acquire/download same tip | **closed** locally, PASS (`ks_xc_bridge_1` opaque; `real_kdbx_bridge_1` real AES-KDF — reconfirmed by `.local-dual-client-suite.sh` / `ALL_SUITE_PASS 20261107T140804Z`) |
| Phone KeySafe via `adb reverse` reloads published tip | **closed** locally (opaque XC tip earlier; real AES-KDF tip `real_kdbx_bridge_1` sha `0ceb3ea2…` via `KdbxCoordinatorLoopbackInstrumentedTest` on OnePlus 13R CPH2645 — `.local-phone-real-kdbx-run.txt`) |
| KeePassXC GUI coordinated save / KeySafe app UI reopen | **open** (manual click-through; agent cannot open host DISPLAY=:0 / xhost; fork `--version` PASS under xvfb) |
| Native Argon2 assemble→write→reload on device/emulator | **closed** locally (OnePlus 13R `androidTest` PASS; no CI push) |
| Auto-publish / merge authorization | **denied** (unchanged) |

## Proven today (Android ↔ Go)

- Exclusive lease, read-only observer, successive writes, lock handoff (dummy bytes)
- Concurrent lease acquisition (one winner)
- External lease revocation blocks stale overwrite
- PUT committed but HTTP acknowledgement lost
- PUT interrupted before the coordinator sees the body
- Assembled AES-KDF KDBX publish + strict reload through the live Go coordinator
- Same-owner successive real AES-KDF publishes advance the tip without releasing
  the lease (Android↔Go only)
- Interrupted / lost-ack real AES-KDF upload fault cases (Android↔Go only)
- Truncated and reject-before-forward real AES-KDF download fault cases
  (Android↔Go only; retry/direct reader still reloads ciphertext)
- Second Android client sees busy lease on a real-ciphertext database id
  (`KdbxLiveRealCiphertextIntegrationTest`; still no KeePassXC)
- Read-only observer still reloads the tip while the exclusive holder keeps a
  real AES-KDF lease (Android↔Go only)
- Wrong bearer token cannot acquire or read a real AES-KDF database id
  (Android↔Go only)
- Empty ciphertext publish is refused before contacting the live coordinator
  (Android↔Go only)
- Oversized ciphertext publish (>64 MiB) is refused before contacting the live
  coordinator (Android↔Go only)
- Concurrent read-only observers reload the same real AES-KDF tip
  (Android↔Go only)
- Coordinator client rejects traversal database ids, short tokens, and
  cleartext non-loopback URLs before contacting the network
- Publish without an acquired lease fails closed and leaves no tip
  (Android↔Go only)
- Real AES-KDF tips stay isolated across distinct database ids
  (Android↔Go only)
- Exclusive lease on one database id does not busy another (Android↔Go only)
- close() releases a real AES-KDF lease so the next owner can acquire immediately
  (Android↔Go only)
- Empty tip download returns null; first real AES-KDF publish creates the tip
  (Android↔Go only)
- Double acquire on the same client fails closed while the lease stays held
  (Android↔Go only)
- Leased download without acquire fails closed; read-only tip still reloads
  (Android↔Go only)
- Writer download after real AES-KDF publish reloads under the same lease
  (Android↔Go only)
- currentRevision advances from empty ("0") to the real AES-KDF tip hash
  (Android↔Go only)
- Concurrent acquire on an empty real AES-KDF database id: one winner, one busy
  (Android↔Go only)
- External lease revocation blocks a stale Android publish of real AES-KDF
  ciphertext; the new owner’s revision reloads (Android↔Go only)
- Two concurrent real AES-KDF PUTs on the same lease/If-Match base: exactly one
  winner, one stale (412); committed ciphertext reloads (Android↔Go only)
- Mismatched ETag on real AES-KDF download fails closed; direct reader still
  reloads server ciphertext (Android↔Go only)
- Failed lease renew after a real AES-KDF publish marks the lease lost and
  blocks further writes; server ciphertext stays (Android↔Go only)
- Substituted download body with an intact real AES-KDF ETag fails closed;
  direct reader still reloads (Android↔Go only)
- Clean real AES-KDF lease handoff: second owner publishes and tip reloads (Android↔Go only)
- Real AES-KDF exclusive write returns after A→B→A handoff; tip reloads (Android↔Go only)
- Released real AES-KDF lease token cannot overwrite after handoff (Android↔Go only)
- Wrong publish acknowledgement (lying revision/ETag) after a committed real
  AES-KDF PUT fails closed for the writer; observer still reloads (Android↔Go)
- After failed renew, `revisionForRecovery` still exposes the last tip while
  `currentRevision` / publish stay lost (Android↔Go only)

## Still required before clearing the dual-client gate blocker

| Scenario | Status |
| --- | --- |
| KeePassXC opens and edits the shared KDBX against the real coordinator | partial (`KdbxCoordinatorClient` live HTTP closed; GUI save path still open) |
| Android opens the same revision the XC client just published | partial (JVM + phone instrumented `downloadReadOnly` of opaque and real AES-KDF tips closed; app UI reopen still open) |
| Lease expiry / lease loss during an edit on each client | closed locally (Android external revocation + renew failure after real AES-KDF; XC `externalLeaseRevocationBlocksPublish`) |
| Interrupted upload with real KDBX ciphertext on XC and Android | closed for protocol path (Android AES-KDF interrupt+lost-ack; XC opaque `rejectedPublishLeavesTipUnchangedThenRetry` via fault proxy; GUI path still open) |
| Interrupted download with real KDBX ciphertext on XC and Android | closed for protocol path (Android AES-KDF truncate+reject-before-forward; XC opaque `truncatedDownloadFailsClosedThenRetry` via fault proxy; GUI path still open) |
| Second client detects an active lease held by the first | closed locally (Android↔Go + XC `secondClientSeesBusyLease` live QtTest) |
| Offline edit on Android only, then reconnect | closed for protocol path (`KdbxOfflineReconnectLiveIntegrationTest`: PUBLISH when base matches, CONFLICT when remote advanced, ALREADY_PUBLISHED after lost ack — `.local-offline-reconnect-run.txt`; GUI/app offline UX still open) |
| Offline edit on desktop only, then reconnect | open |
| Two independent offline edits, reconnect in either order | open |
| Simultaneous publish attempts with real KDBX | closed locally for protocol path (Android↔Go same-base race; XC `staleIfMatchPublishFailsClosed` + busy-second; GUI dual-writer click race still open) |
| Crash during save + recovery reopen on the same client | partial (Android recovery unit tests) |
| Re-open every produced KDBX in **both** KeePassXC and KeySafe | closed locally without GUI (KeySafe AES-KDF tip → `keepassxc-cli ls/show` PASS; XC-cli Argon2 DB → KeySafe `KdbxCrossClientReopenIntegrationTest` PASS — `.local-cross-open-reopen-run.txt`; GUI app reopen still open) |
| Assembled ciphertext round-trip under AES-KDF (JVM) | proven (`KdbxAssembledCiphertextWriterTest`; does not authorize publish) |
| Assembled ciphertext round-trip under native Argon2 / forced-native AES | closed locally (OnePlus 13R `KdbxAssembledCiphertextArgon2InstrumentedTest` PASS) |

## Desktop checkout for interop

Primary local tree: `/home/friseer/MyGIT/NetAigis-KeySafe-Desktop`
(NetAigis KeySafe desktop fork of KeePassXC; display name **NetAigis KeySafe**,
app id `de.netaigis.keysafe.desktop`, binary `keysafe`). Working branch tip on
`feature/coordinated-kdbx-20261014`. Older checkout
`/home/friseer/keepass-pr-submission-20261014/xc` may lag. Branding notes:
`docs/KEYSAFE_DESKTOP_FORK_NOTICES.md` in the desktop tree.

Coordinated-KDBX feature content includes: HTTP/file body bounds, TLS 1.2+/fail-closed
SSL, settings-UI validation, shared client config checks, unit-tested lease-response
parsing, publish-ack matching, download hash/ETag binding, shared JSON field
extraction, busy/lost/stale/renew/release/acquire/download/publish/empty-tip HTTP
status helpers, empty/oversized KDBX payload checks, and CoordinatorByteLimits
(64 MiB KDBX / 16 KiB control, aligned with KeySafe). GitHub Actions on
`net-aigis/NetAigis-KeySafe-Desktop` still rejects new runs (`Actions has been disabled`) despite
repo permissions `enabled:true`; last successful XC Actions run remains `f8217b74`
(2026-11-04). Helpers are checked locally via QtTest in Ubuntu 24.04/podman.
Those XC-only changes are not dual-client proof.
