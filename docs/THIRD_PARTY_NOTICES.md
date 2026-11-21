# NetAigis KeySafe — third-party notices

This file summarizes major third-party components. License texts live under `LICENSES/` and in upstream headers. Conveying binaries requires Corresponding Source under GPL-3.0-or-later (see top-level `LICENSE` and `docs/KEYSAFE_FORK_NOTICES.md`).

## Primary upstream

| Component | Upstream | License |
| --- | --- | --- |
| KeePassDX (Android) | https://github.com/Kunzisoft/KeePassDX | GPL-3.0-or-later |
| KeePassXC (Desktop fork base) | https://github.com/keepassxreboot/keepassxc | GPL-2.0 / GPL-3.0 as upstream |

## Notable bundled / linked components (Android tree)

See also individual files in `LICENSES/`:

| Notice file | Subject |
| --- | --- |
| `LICENSE_APACHE` | Apache-licensed dependencies |
| `LICENSE_BOUNCY_CASTLE` | Bouncy Castle |
| `LICENSE_ANDROID_BACKUP_SERVICE` | Android backup service notice |
| `LICENSE_FONT_FIRA_MONO_REGULAR` | Fira Mono |
| `LICENSE_ICON_PACK_CLASSIC` | Classic icon pack |
| `LICENSE_ICON_PACK_MATERIAL_FONT_AWESOME` | Material / Font Awesome icon pack |
| `LICENSE_MOZILLA_COMPONENTS` | Mozilla components |

Gradle module dependencies (AndroidX, Material, Room, Joda-Time, etc.) retain their upstream licenses as declared by those artifacts.

## Coordinator test fixture

The Go loopback coordinator under `tests/integration/coordinator` is a development/integration fixture, not a certified production server.

## Corresponding Source

When NetAigis distributes KeySafe binaries, Corresponding Source for the shipped version (including build scripts needed to generate the binaries) must remain available from https://github.com/net-aigis/NetAigis-KeySafe (and the Desktop repository for Desktop builds).
