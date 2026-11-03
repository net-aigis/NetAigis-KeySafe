/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Explicit inventory of KeePassXC ↔ KeySafe ↔ coordinator proofs that still
 * block automatic merge/publish. Android↔Go dummy-byte protocol tests do not
 * clear these entries. See docs/KEYSAFE_DUAL_CLIENT_SCENARIOS.md.
 */
internal object KdbxDualClientProofStatus {
    val incompleteProofs: List<String> = listOf(
        "KeePassXC open/edit against the shared coordinator KDBX",
        "Android reopen of the same revision published by KeePassXC",
        "cross-client active-lease detection",
        "lease expiry or loss during edit on each client",
        "interrupted real-KDBX upload/download on XC and Android",
        "offline edits on both clients with reconnect in either order",
        "simultaneous real-KDBX publish attempts",
        "crash-during-save recovery reopened in both KeePassXC and KeySafe",
        "assembled ciphertext round-trip under native AES/Argon2"
    )

    val gateBlocker: String =
        "KeePassXC and KeySafe dual-client crash/recovery proofs are incomplete " +
            "(${incompleteProofs.size} scenarios open; see KEYSAFE_DUAL_CLIENT_SCENARIOS.md)"
}
