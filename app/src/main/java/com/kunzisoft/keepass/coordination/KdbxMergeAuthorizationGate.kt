/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Explicit fail-closed gate for automatic KDBX merge/publish.
 *
 * Authorization requires an empty dual-client proof inventory, attested
 * refuseUnknownExtensions load, no unresolved record conflicts, and no
 * append-order-only preview. A conflict-free three-copy report alone is never
 * enough without those conditions.
 */
internal object KdbxMergeAuthorizationGate {
    data class Decision(
        val authorized: Boolean,
        val blockers: List<String>
    ) {
        init {
            require(!authorized || blockers.isEmpty()) {
                "Authorized merge decision cannot retain blockers"
            }
            require(authorized || blockers.isNotEmpty()) {
                "Denied merge decision must list blockers"
            }
        }
    }

    /** Remaining integrity and safety blockers known at this KeySafe revision. */
    val standingBlockers: List<String>
        get() = listOfNotNull(KdbxDualClientProofStatus.gateBlocker)

    /**
     * Authorizes automatic merge/publish only when [blockers] is empty after
     * combining standing dual-client inventory with report-level attestations.
     */
    fun evaluate(report: KdbxThreeCopyReview.Report? = null): Decision {
        val blockers = ArrayList(standingBlockers)
        if (report == null || !report.unknownExtensionsRefused) {
            blockers.add(
                "KDBX copies were not attested as loaded with refuseUnknownExtensions"
            )
        }
        if (report != null && report.conflictIds.isNotEmpty()) {
            blockers.add("three-copy review still reports unresolved record conflicts")
        }
        if (report?.appendOrder != null) {
            blockers.add(
                "append-order preview is analysis-only and does not authorize rewriting group membership"
            )
        }
        return Decision(authorized = blockers.isEmpty(), blockers = blockers.toList())
    }

    fun requireDenied(report: KdbxThreeCopyReview.Report? = null): Decision {
        val decision = evaluate(report)
        require(!decision.authorized) { "KDBX merge must remain unauthorized" }
        return decision
    }
}
