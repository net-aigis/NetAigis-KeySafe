# NetAigis KeySafe — threat model (coordination + clients)

**Status:** living document for release readiness. Not a penetration-test report.  
**Scope:** Android KeySafe, Desktop KeySafe (KeePassXC fork), self-hosted KDBX coordinator.  
**Updated:** 2026-11-21

## Assets

1. KDBX plaintext (entries, attachments, history) while unlocked
2. KDBX ciphertext at rest and in transit
3. Master credentials (password, key file, hardware challenge responses)
4. Coordinator bearer token and lease tokens
5. Device-unlock wrapped credentials (biometrics / device credential)
6. Clipboard / autofill / Magikeyboard / passkey transient secrets

## Actors

| Actor | Capability |
| --- | --- |
| Device owner | Full local access when unlocked |
| Local malware / accessibility abuse | May observe UI, clipboard, autofill |
| Network attacker (on-path) | Sees TLS metadata; cannot read HTTPS bodies if PKI holds |
| Coordinator operator / compromised server | Reads ciphertext, ids, lease metadata; can withhold, roll back, or serve stale tips |
| Second legitimate client | Contends for exclusive lease; may race publishes |
| Upstream package confusion | Wrong APK/binary signing can replace the app |

## Trust boundaries

- Unlocked database memory ↔ locked / encrypted storage
- Client ↔ coordinator (HTTPS + bearer + lease + If-Match)
- Android Keystore-wrapped prefs ↔ cloud backup / device transfer
- Libre/Free APK signing identity ↔ install/update path

## Key threats and mitigations

| Threat | Mitigation (implemented / expected) | Residual risk |
| --- | --- | --- |
| Silent overwrite of tip | Exclusive lease, If-Match revision, busy 423, stale 412 | Misconfigured clients ignoring protocol |
| Lost publish acknowledgement | `ALREADY_PUBLISHED` / recovery stores; tip reopen proofs | Operator deletes tip out-of-band |
| Merge data loss | Three-copy review, refuseUnknownExtensions, gated publisher + lease revalidation | Conflicts still require human resolution; append-order is analysis-only |
| Token exfiltration via backup | `coordinated_kdbx.xml` excluded from backup/transfer rules | Rooted device / malware with Keystore access |
| Cleartext coordination | Non-loopback HTTP refused; TLS 1.2+ policy | User forces unsafe custom builds |
| Supply-chain / wrong binary | Independent applicationIds; release signing checklist | Signing key not yet production-held in CI |
| Clipboard leakage | Timeouts / optional features | OS clipboard managers |

## Data-loss and recovery scenarios (evidenced locally)

Documented under `KEYSAFE_DUAL_CLIENT_SCENARIOS.md` / offline coordination docs:

- Crash during save → pending + tip reopen (Desktop Xvfb + Android UI)
- Offline edit → reconnect PUBLISH / CONFLICT / ALREADY_PUBLISHED
- Dual offline edits → ordered CONFLICT
- Dual-writer while GUI holds lease → HTTP 423
- Truncated / rejected upload-download fault paths (protocol)

## Explicit non-goals (current)

- Formal third-party penetration test
- Certification of coordinator hosting
- Guaranteeing safety of user-chosen remote document providers
- Automatic resolution of content conflicts

## Release gate implication

Ship only with: attested conflict-free merge path, backup exclusions, independent signing key, published privacy text, and operator guidance that the coordinator sees ciphertext + metadata.
