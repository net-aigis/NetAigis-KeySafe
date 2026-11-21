# NetAigis KeySafe — release checklist

## Closed for 0.1.0

- [x] Independent display name and Android application identifiers per flavor
- [x] Project version `0.1.0` / versionCode `1001` (Desktop `.version` `0.1.0`)
- [x] HTTPS coordinator preserved (protocol NOT certified secure)
- [x] Replace upstream donation/Pro ownership identification (no Pro SKU)
- [x] Preserve upstream copyright/license notices and credit
- [x] Brand + neutralize Pro/theme-unlock leftovers across locales; About/privacy non-translatable
- [x] Remove incorrect offline-only statement from all languages
- [x] Update GitHub Actions display/artifact names + signed release workflow
- [x] Replace app launcher icons for Libre and Free
- [x] CI Android build + unit tests on NetAigis `main`
- [x] Rename GitHub repository; `main` default branch
- [x] Privacy policy (`docs/PRIVACY.md`) + in-app About text
- [x] Threat model (`docs/KEYSAFE_THREAT_MODEL.md`)
- [x] Release notes (`docs/KEYSAFE_RELEASE_NOTES.md`)
- [x] Help index (`docs/KEYSAFE_HELP.md`)
- [x] Third-party / GPL notices (`docs/THIRD_PARTY_NOTICES.md`, `KEYSAFE_FORK_NOTICES.md`, `LICENSES/`)
- [x] Backup rules exclude `coordinated_kdbx.xml`
- [x] Independent release keystore generated locally + Gradle signing + CI secret scaffolding
- [x] Signed Libre/Free release APKs built and verified (`apksigner`)
- [x] AVD install + same-cert reinstall (update) of signed Libre APK
- [x] Autofill + Magikeyboard + CredentialProvider registered on AVD
- [x] AVD GUI reopen E2E 3/3 PASS
- [x] Dual-client GUI proofs + merge gate for attested conflict-free reports
- [x] Fastlane package id + en-US/de-DE store text + phoneScreenshots (branded composites; AVD live screencap blocked by System UI ANR/black frames)
- [x] Desktop release notes (`docs/KEYSAFE_DESKTOP_RELEASE.md`) + `.version` 0.1.0
- [x] Ship-source secret / identity audit script

## Operator follow-ups (outside the repo)

- [ ] Offline escrow/backup of `keysafe-release.jks` + `keystore.properties` (never commit)
- [ ] Load CI secrets `KEYSAFE_RELEASE_*` for tag builds
- [ ] Mirror `docs/PRIVACY.md` on https://net-aigis.de if desired
- [ ] Optional external penetration test
- [ ] Physical-device soak / store submission when you choose a channel
- [ ] Desktop platform codesigning for distributed installers

## Commands

```bash
./scripts/audit-release-identity.sh
./gradlew :app:assembleLibreRelease :app:assembleFreeRelease
```

Note: Kotlin/Java namespaces (`com.kunzisoft.keepass`) remain intentionally.
