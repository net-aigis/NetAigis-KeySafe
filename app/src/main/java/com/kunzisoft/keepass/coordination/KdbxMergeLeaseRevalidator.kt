/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.security.MessageDigest

/**
 * Exclusive-lease revalidation of the merge target revision before any PUT.
 *
 * Re-reads the server file under a live lease and requires the content hash to
 * still equal the expected base revision. This never publishes and never
 * clears [KdbxMergeAuthorizationGate] standing blockers by itself.
 */
internal object KdbxMergeLeaseRevalidator {
    data class Outcome(val ok: Boolean, val reason: String?) {
        init {
            require(ok || !reason.isNullOrBlank()) { "Failed revalidation must explain why" }
            require(!ok || reason == null) { "Successful revalidation must not retain a failure reason" }
        }
    }

    private val revisionPattern = Regex("[a-f0-9]{64}")

    fun revalidate(
        expectedBaseRevision: String,
        hasLiveLease: () -> Boolean,
        leasedDownload: () -> ByteArray?
    ): Outcome {
        if (!hasLiveLease()) {
            return Outcome(false, "no live exclusive lease for merge-target revalidation")
        }
        if (expectedBaseRevision != "0" && !revisionPattern.matches(expectedBaseRevision)) {
            return Outcome(false, "invalid expected base revision for merge-target revalidation")
        }
        val bytes = try {
            leasedDownload()
        } catch (error: Exception) {
            return Outcome(
                false,
                "lease-bound download failed during merge-target revalidation: ${error.message ?: error.javaClass.simpleName}"
            )
        }
        if (!hasLiveLease()) {
            return Outcome(false, "exclusive lease lost during merge-target revalidation")
        }
        if (expectedBaseRevision == "0") {
            return if (bytes == null) {
                Outcome(true, null)
            } else {
                Outcome(false, "expected empty merge target but coordinator returned bytes")
            }
        }
        if (bytes == null) {
            return Outcome(false, "merge target missing for non-zero base revision")
        }
        if (bytes.isEmpty()) {
            return Outcome(false, "refusing empty merge-target KDBX payload")
        }
        val hash = sha256Hex(bytes)
        if (hash != expectedBaseRevision) {
            return Outcome(false, "server revision no longer matches the merge base")
        }
        if (!hasLiveLease()) {
            return Outcome(false, "exclusive lease lost after merge-target hash check")
        }
        return Outcome(true, null)
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
