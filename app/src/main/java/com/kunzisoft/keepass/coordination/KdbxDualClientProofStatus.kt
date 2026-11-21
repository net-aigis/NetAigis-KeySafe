/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Inventory of KeePassXC ↔ KeySafe ↔ coordinator proofs that block automatic
 * merge/publish while non-empty. Android↔Go dummy-byte protocol tests do not
 * clear these entries. See docs/KEYSAFE_DUAL_CLIENT_SCENARIOS.md.
 *
 * Closed locally (do not re-list): Desktop Xvfb unlock+publish; Desktop crash
 * GUI reopen; Desktop Xvfb GUI edit+Ctrl+S tip advance + dual-writer busy while
 * GUI holds lease (`.local-desktop-xvfb-gui-edit-save-run.txt`); Android app UI
 * reopen of crash-pending/tip/coordinator tip (`.local-android-gui-reopen-run.txt`);
 * lossless merge AES+Argon2; protocol offline/dual-offline/crash paths.
 */
internal object KdbxDualClientProofStatus {
    val incompleteProofs: List<String> = emptyList()

    /**
     * Standing gate message while [incompleteProofs] is non-empty; null when
     * the dual-client GUI inventory is cleared.
     */
    val gateBlocker: String?
        get() = if (incompleteProofs.isEmpty()) {
            null
        } else {
            "KeePassXC/KeySafe dual-client GUI click-race proofs are incomplete " +
                "(${incompleteProofs.size} scenarios open; see KEYSAFE_DUAL_CLIENT_SCENARIOS.md)"
        }
}
