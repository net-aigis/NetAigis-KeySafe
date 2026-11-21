# NetAigis KeySafe — release notes

Upstream KeePassDX changelog history remains in the repository as heritage, not as KeySafe store release notes.

## 1.0.0 (2026-11-21)

**versionCode:** 10000  
**Android packages:** `de.netaigis.keysafe.libre`, `de.netaigis.keysafe.free`  
**Desktop:** `.version` `1.0.0` (`de.netaigis.keysafe.desktop`)

First public NetAigis KeySafe release line (supersedes the interim `0.1.0` / `0.1.0-dev` numbering).

### Highlights

- Independent NetAigis KeySafe branding and application ids
- Optional HTTPS-coordinated KDBX sync (exclusive lease, revision checks, offline recovery)
- Conflict-free three-copy review; merge gate authorizes attested conflict-free reports
- Dual-client proofs closed locally (Desktop Xvfb edit+save + dual-writer busy; Android UI reopen)
- Privacy policy, threat model, third-party notices, signing pipeline, Fastlane KeySafe listings
- No separate Pro unlock SKU

### Signing

Release APKs are signed with the NetAigis KeySafe release keystore (CN=NetAigis KeySafe).  
Certificate SHA-256: `D9:DE:67:CD:BC:A6:48:8E:6B:47:C3:E3:35:4A:A7:8A:2A:9F:E5:D2:3C:19:C9:15:F4:F5:63:5B:8C:02:EC:CD`

Keystore material is **not** in git (`keysafe-release.jks`, `keystore.properties`). Back up offline. CI uses optional secrets documented in `docs/KEYSAFE_SIGNING.md`.

### Security / safety notes

- Coordinator protocol is not a certified security product; validate hosting before real secrets
- Automatic merge/publish only for attested conflict-free reports
- Android backup excludes Keystore-bound coordinator preferences

### Store assets

- Fastlane en-US / de-DE descriptions + changelog `10000`
- Phone screenshots under `fastlane/metadata/android/*/images/phoneScreenshots/`

## 0.1.0 (superseded)

Interim tag during packaging; product line continues as **1.0.0**.
