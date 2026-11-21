# NetAigis KeySafe — release signing

Independent of upstream KeePassDX keys. Production keystore material must **never** be committed.

## Local / CI setup

1. Create a dedicated KeySafe upload keystore (example):

```bash
keytool -genkeypair -v \
  -keystore keysafe-release.jks \
  -alias keysafe \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -storetype PKCS12
```

2. Copy `keystore.properties.example` to `keystore.properties` (gitignored) and fill paths/passwords.

3. `./gradlew :app:assembleLibreRelease` signs with that config when the properties file exists; otherwise release builds stay unsigned.

## CI secrets (recommended)

Store as GitHub Actions secrets (never in the repo):

- `KEYSAFE_RELEASE_STORE_FILE` (base64 of the `.jks` / `.keystore`)
- `KEYSAFE_RELEASE_STORE_PASSWORD`
- `KEYSAFE_RELEASE_KEY_ALIAS`
- `KEYSAFE_RELEASE_KEY_PASSWORD`

Decode the store onto the runner ephemeral disk in the release workflow; wipe after upload.

## Local 0.1.0 keystore

Generated on the release builder for 0.1.0 (gitignored):

- Files: `keysafe-release.jks`, `keystore.properties`
- Alias: `keysafe`
- Certificate SHA-256: `D9:DE:67:CD:BC:A6:48:8E:6B:47:C3:E3:35:4A:A7:8A:2A:9F:E5:D2:3C:19:C9:15:F4:F5:63:5B:8C:02:EC:CD`

**Back up those two files offline immediately.** They are not in git.

CI secrets for `.github/workflows/release-apk.yml`:

- `KEYSAFE_RELEASE_STORE_FILE_B64`
- `KEYSAFE_RELEASE_STORE_PASSWORD`
- `KEYSAFE_RELEASE_KEY_ALIAS`
- `KEYSAFE_RELEASE_KEY_PASSWORD`

## Checklist

- [x] Keystore generated locally for 0.1.0
- [ ] Offline escrow/backup completed by operator
- [ ] CI secrets loaded for tag builds
- [ ] Play App Signing / F-Droid signing policy decided
- [ ] Desktop codesigning (Linux package / Windows / macOS) tracked separately in the Desktop tree
