# KeySafe dual-client scenarios (phase 4)

Dual-client GUI inventory is cleared locally (2026-11-21). Automatic
merge/publish is authorized only for attested conflict-free reports
(`refuseUnknownExtensions`, no record conflicts, no append-order preview).
Android↔Go loopback protocol coverage (`KEYSAFE_INTEGRATION_TESTS.md`) is
**not** by itself dual-client proof with KeePassXC.

## Phase status (2026-11-21)

| Slice | Status |
| --- | --- |
| Android↔Go live protocol with real AES-KDF ciphertext + fault matrix | **closed** for this phase (CI on KeySafe `main`) |
| KeePassXC client hardening unit tests (config/lease/ack/limits/status) | **closed** locally (QtTest/podman); GitHub Actions minutes exhausted until month end — local QtTest is the proof path |
| KeePassXC `KdbxCoordinatorClient` live HTTP vs Go coordinator | **closed** locally (`testkdbxcoordinatorclientlive` 9 PASS: round-trip, busy, successive, lease-loss, stale 412, truncated download, rejected publish+retry; Ubuntu podman + host coordinator) |
| XC publish → KeySafe `downloadReadOnly` same tip/SHA-256 | **closed** locally (`xc_ks_bridge_1`; see `.local-dual-client-result.txt`) |
| KeySafe publish → XC `KdbxCoordinatorClient` acquire/download same tip | **closed** locally, PASS (`ks_xc_bridge_1` opaque; `real_kdbx_bridge_1` real AES-KDF — reconfirmed by `.local-dual-client-suite.sh` / `ALL_SUITE_PASS 20261107T140804Z`) |
| Phone KeySafe via `adb reverse` reloads published tip | **closed** locally (opaque XC tip earlier; real AES-KDF tip `real_kdbx_bridge_1` sha `0ceb3ea2…` via `KdbxCoordinatorLoopbackInstrumentedTest` on OnePlus 13R CPH2645 — `.local-phone-real-kdbx-run.txt`) |
| KeePassXC GUI coordinated save / KeySafe app UI reopen | **closed** locally (Desktop Xvfb unlock+publish; Desktop edit+Ctrl+S tip advance + dual-writer 423 while GUI holds lease — `.local-desktop-xvfb-gui-edit-save-run.txt`; Android AVD UI reopen of pending/tip/coordinator tip — `.local-android-gui-reopen-run.txt`) |
| Native Argon2 assemble→write→reload on device/emulator | **closed** locally (OnePlus 13R `androidTest` PASS; no CI push) |
| Auto-publish / merge authorization | **open** for attested conflict-free reports (`KdbxDualClientProofStatus.incompleteProofs` empty; gate still denies missing attestation / conflicts / append-order) |

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

## Dual-client gate inventory (cleared 2026-11-21)

| Scenario | Status |
| --- | --- |
| KeePassXC opens and edits the shared KDBX against the real coordinator | **closed** locally (`KdbxCoordinatorClient` live HTTP; Desktop Xvfb unlock→publish; Desktop GUI edit+Ctrl+S tip advance — `.local-desktop-xvfb-gui-edit-save-run.txt`) |
| Android opens the same revision the XC client just published | **closed** locally (JVM/phone `downloadReadOnly`; Android AVD app UI reopen of coordinator tip — `.local-android-gui-reopen-run.txt`) |
| Lease expiry / lease loss during an edit on each client | closed locally (Android external revocation + renew failure after real AES-KDF; XC `externalLeaseRevocationBlocksPublish`) |
| Interrupted upload with real KDBX ciphertext on XC and Android | closed for protocol path (Android AES-KDF interrupt+lost-ack; XC opaque `rejectedPublishLeavesTipUnchangedThenRetry` via fault proxy) |
| Interrupted download with real KDBX ciphertext on XC and Android | closed for protocol path (Android AES-KDF truncate+reject-before-forward; XC opaque `truncatedDownloadFailsClosedThenRetry` via fault proxy) |
| Second client detects an active lease held by the first | **closed** locally (Android↔Go + XC `secondClientSeesBusyLease`; Desktop GUI holds lease → second acquire HTTP 423 — `.local-desktop-xvfb-gui-edit-save-run.txt`) |
| Offline edit on Android only, then reconnect | closed for protocol path (`KdbxOfflineReconnectLiveIntegrationTest` — `.local-offline-reconnect-run.txt`) |
| Offline edit on desktop only, then reconnect | closed for protocol path (`testcoordinatedrecoverystore` live — `.local-offline-reconnect-xc-run.txt`) |
| Two independent offline edits, reconnect in either order | closed for protocol path (`KdbxDualOfflineReconnectLiveIntegrationTest` — `.local-dual-offline-run.txt`) |
| Simultaneous publish attempts with real KDBX | **closed** locally (Android↔Go same-base race; XC busy-second; Desktop GUI dual-writer 423) |
| Crash during save + recovery reopen on the same client | **closed** locally (protocol/cli + Desktop Xvfb GUI + Android AVD UI — `.local-crash-recovery-run.txt`, `.local-desktop-xvfb-gui-crash-reopen-run.txt`, `.local-android-gui-reopen-run.txt`) |
| Re-open every produced KDBX in **both** KeePassXC and KeySafe | **closed** locally (cli + Desktop Xvfb + Android AVD UI; `.local-cross-open-reopen-run.txt`, `.local-android-gui-reopen-run.txt`) |
| Conflict-free lossless merge writer (dual-entry) | closed for AES-KDF JVM + XC-cli and native Argon2 emulator + XC-cli; gate authorizes attested conflict-free reports |
| Assembled ciphertext round-trip under AES-KDF (JVM) | proven (`KdbxAssembledCiphertextWriterTest`) |
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
