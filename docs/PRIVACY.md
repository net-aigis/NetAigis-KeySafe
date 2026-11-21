# NetAigis KeySafe — Privacy Policy

**Product:** NetAigis KeySafe (Android) and NetAigis KeySafe Desktop  
**Last updated:** 2026-11-21  
**Contact:** https://net-aigis.de · https://github.com/net-aigis/NetAigis-KeySafe

This policy describes what the KeySafe clients process. It is not legal advice.

## Summary

- Password databases (KDBX) are encrypted on the device or workstation with credentials you supply.
- KeySafe does **not** require a NetAigis cloud account.
- Optional HTTPS coordination sends **encrypted** KDBX ciphertext and coordination metadata to a server **you** configure.
- The protocol and hosting are **not** certified secure for production secrets until you complete your own validation.

## Data processed on the device

| Data | Purpose | Storage |
| --- | --- | --- |
| KDBX database files | Store credentials you manage | User-chosen storage (app storage, SAF documents, Desktop files) |
| Master password / key file / hardware key material | Unlock and protect the database | Not uploaded by KeySafe; held in memory while unlocked; optional device-unlock wrapping uses Android Keystore / platform APIs |
| App preferences | UI, autofill, keyboard, timeouts | SharedPreferences / Desktop config |
| Coordinator URL, database id, access token | Optional coordinated sync | Android: AndroidKeyStore-wrapped prefs (`coordinated_kdbx`); Desktop: encrypted KDBX custom data / settings |
| Recent file locations | Convenience | Local preferences (can be disabled) |

Clipboard, autofill, Magikeyboard, and passkey features process credential fields only when you enable them and interact with those features.

## Optional HTTPS coordination

When you configure a coordinator:

- The client uploads and downloads **encrypted** KDBX bodies over HTTPS (loopback HTTP only for explicit test fixtures).
- The server can observe: database identifier, lease/lock metadata, content hashes/revisions, connection metadata (IP, TLS metadata, timing), and ciphertext size.
- The server **must not** be assumed unable to store, log, or correlate that metadata.
- Do not point a coordinator at an untrusted host for databases that contain real secrets.

Android cloud backup / device transfer **excludes** `coordinated_kdbx.xml` so Keystore-bound tokens are not restored without their keys.

## Data KeySafe does not collect by default

- No analytics SDK is bundled for product telemetry in the NetAigis packaging described in this repository.
- No advertising identifier collection is part of the Libre/Free KeySafe product configuration.
- Crash reports are not automatically uploaded by KeySafe itself (platform OS crash tooling is outside this policy).

## Third parties

- **Upstream heritage:** KeySafe is a GPLv3-or-later fork of KeePassDX. See `docs/KEYSAFE_FORK_NOTICES.md`.
- **Your document providers / cloud storage:** If you store KDBX files in Google Drive, Nextcloud, USB storage, etc., those providers’ policies apply to the files you place there.
- **Your coordinator operator:** Whoever runs the HTTPS coordinator is an independent controller/processor for coordination metadata and ciphertext at rest on that server.

## Children

KeySafe is not directed at children and is not intended for use by minors without appropriate adult supervision of credentials and devices.

## Retention

Local data remains until you delete databases, clear app data, or uninstall. Coordinated server retention is controlled by the operator of that server.

## Your choices

- Do not enable coordination for databases you are not willing to expose as ciphertext + metadata to that server.
- Disable autofill, keyboard, clipboard features, and recent-file memory if you do not need them.
- Export and back up KDBX files under your own key management procedures.

## Changes

Material changes to this policy will be reflected in this document and in the in-app About privacy text (`html_about_privacy`).

## Source

Corresponding Source for shipped binaries is available from the project repository under GPL-3.0-or-later.
