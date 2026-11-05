# NetAigis KeySafe: live Kotlin ↔ Go integration checks

GitHub Actions builds `tests/integration/coordinator` and starts it with
**only loopback HTTP**, disposable storage, and a fixed TEST-ONLY bearer token.
The normal `:app:testLibreDebugUnitTest` task then runs the actual Android
network client (`KdbxCoordinatorClient`) over HTTP to the Go implementation.
All other Android unit tests and `:app:assembleLibreDebug` still run.

## Covered

1. Exclusive writer, read-only observer, two successive writes, and lock handoff.
2. Eight concurrent Kotlin clients: one successful editing lease.
3. External lease revocation: old client cannot overwrite new writer.
4. Go server commits a PUT but proxy **closes the connection before the
   successful HTTP acknowledgement**. Client sees an error; a new client
   verifies the committed content; stale retry is rejected.
5. Proxy blocks first PUT before contacting Go. Existing remote version remains
   unchanged; subsequent valid save succeeds.
6. Assembled AES-KDF KDBX ciphertext (not dummy bytes) publishes through the
   live Go coordinator, survives reject-before-forward and lost-ack upload
   fault proxies, truncated and reject-before-forward download fault proxies,
   and reloads under strict unknown-extension refusal. Busy-lease detection is
   covered for a second Android client, external lease revocation blocks a stale
   real AES-KDF publish while the new owner’s ciphertext reloads, and two
   concurrent same-base real AES-KDF PUTs yield exactly one winner (412 for the
   loser), a mismatched download ETag fails closed while a direct reader still
   reloads, a failed lease renew after real AES-KDF publish blocks further
   writes, a substituted download body with an intact ETag fails closed, and a
   lying publish acknowledgement after commit fails closed for the writer, and
   exclusive real AES-KDF lease handoff plus A→B→A return of write ownership
   reload under strict load, a released lease token cannot overwrite after
   handoff, same-owner successive real AES-KDF publishes advance the tip, and a
   read-only observer reloads while the exclusive holder keeps the lease, and a
   wrong bearer token cannot acquire or read the tip, empty or oversized
   ciphertext publishes are refused before contacting the coordinator, and
   concurrent observers reload the same real AES-KDF tip, and the client
   rejects traversal database ids, short tokens, and cleartext non-loopback URLs,
   publish without an acquired lease fails closed, and distinct database ids
   keep isolated real AES-KDF tips.
   Still Android↔Go only; KeePassXC dual-client proofs remain open.
7. Existing Go reference tests cover concurrent same-revision writes, a
   streaming body failure, expired leases during upload, backups, and renewal.
   They run under Go's race detector.

## Reproduce

The `.github/workflows/coordinated-kdbx-build.yml` workflow is the canonical
reproducer. It provides `KEYSAFE_INTEGRATION_URL`, starts/stops the fixture and
runs the Gradle test task without installing the coordinator on user machines.
`KdbxLiveProtocolIntegrationTest` skips when manually running normal unit
checks without a coordinator. The CI step sets the URL **and checks its JUnit
XML report**, rejecting missing/skipped integration coverage.

Native Argon2id assemble→write→reload (DX only):

```bash
./gradlew :app:connectedLibreDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=\
com.kunzisoft.keepass.coordination.KdbxAssembledCiphertextArgon2InstrumentedTest
```

CI compiles the instrumented sources (`:app:compileLibreDebugAndroidTestKotlin`)
without running them on an emulator.

Requires a device/emulator with `libaes`/`libargon2`. This is separate from
KeePassXC dual-client proofs and is not part of the default CI unit job.

## Not proved by these tests

- Android device lifecycle, process death, filesystem durability, or recovery
  persistence under power loss.
- Large KDBX streaming, or TLS certificate verification by Android (test
  traffic is loopback-only). AES-KDF assemble/publish/reload is covered; native
  Argon2 is not.
- Real KeePassXC ↔ Android interoperation, distributed deployments or server
  restart persistence. In particular, Go lease state is process-local.
- Universal data-loss prevention. Do not use production password databases yet.
