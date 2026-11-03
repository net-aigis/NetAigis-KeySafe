/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Explicit fail-closed gate for any future automatic KDBX merge/publish path.
 *
 * A conflict-free three-copy report is never sufficient authorization: missing
 * unknown-extension attestation, missing writer/lease proofs and incomplete
 * interoperability tests remain hard blockers.
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
    val standingBlockers: List<String> = listOf(
        "no validated lossless KDBX merge writer exists",
        "KeePassXC and KeySafe dual-client crash/recovery proofs are incomplete"
    )

    /**
     * Always denies automatic merge/publish. [report] is accepted only to make
     * call sites explicit; its contents never clear standing blockers.
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
        return Decision(authorized = false, blockers = blockers.toList())
    }

    fun requireDenied(report: KdbxThreeCopyReview.Report? = null): Decision {
        val decision = evaluate(report)
        require(!decision.authorized) { "KDBX merge must remain unauthorized" }
        return decision
    }
}
