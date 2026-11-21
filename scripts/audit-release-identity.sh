#!/usr/bin/env bash
# Fail closed if shipped identity / placeholders look wrong.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }

grep -Fq 'applicationId = "de.netaigis.keysafe"' app/build.gradle.kts \
  || fail "applicationId missing"
grep -Fq 'NetAigis KeySafe' app/src/main/res/values/donottranslate.xml \
  || fail "display name missing"
grep -Fq 'android:authorities="${applicationId}.coordinator"' app/src/main/AndroidManifest.xml \
  || fail "coordinator authority placeholder missing"
grep -Fq 'android:permission="android.permission.BIND_AUTOFILL_SERVICE"' app/src/main/AndroidManifest.xml \
  || fail "autofill service missing"
grep -Fq 'android.view.InputMethod' app/src/main/AndroidManifest.xml \
  || fail "IME registration missing"
grep -Fq 'path="coordinated_kdbx.xml"' app/src/main/res/xml/backup_rules.xml \
  || fail "backup exclusion for coordinated_kdbx missing"
grep -Fq 'path="coordinated_kdbx.xml"' app/src/main/res/xml/old_backup_rules.xml \
  || fail "legacy backup exclusion missing"
grep -Fq 'manifestPlaceholders["googleAndroidBackupAPIKey"] = "unused"' app/build.gradle.kts \
  || fail "backup API key placeholder must stay unused"
! grep -RInE 'AIza[0-9A-Za-z_-]{20,}|sk_live_|-----BEGIN PRIVATE KEY-----' \
  app/src/main app/src/libre app/src/free --include='*.xml' --include='*.properties' --include='*.json' \
  && ok "no private-key / live API patterns in ship source" \
  || fail "possible secret material in ship source"

# Merged manifest (requires Gradle)
if [ "${SKIP_GRADLE:-}" != 1 ]; then
  ./gradlew -q :app:processLibreReleaseMainManifest
  MERGED=$(find app/build/intermediates -path '*libreRelease*' -name AndroidManifest.xml | head -1)
  [ -n "$MERGED" ] || fail "merged libreRelease manifest not found"
  grep -Eq 'android:authorities="de\.netaigis\.keysafe\.libre\.coordinator"' "$MERGED" \
    || fail "merged authority not de.netaigis.keysafe.libre.coordinator"
  grep -Eq 'android:name="com.kunzisoft.keepass.credentialprovider.autofill.KeeAutofillService"' "$MERGED" \
    || fail "autofill service missing in merged manifest"
  grep -Eq 'android:name="com.kunzisoft.keepass.credentialprovider.magikeyboard.MagikeyboardService"' "$MERGED" \
    || fail "IME service missing in merged manifest"
  ok "merged libreRelease manifest authorities/services"
fi

ok "release identity audit passed"
