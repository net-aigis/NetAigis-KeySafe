/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Gated merge publish path (phase 3). Preserves base/local/remote ciphertext,
 * revalidates the server under an exclusive lease, and refuses every PUT while
 * [KdbxMergeAuthorizationGate] denies authorization.
 *
 * This is not a lossless plaintext merge writer: the caller must already hold
 * a candidate merged ciphertext. Automatic publication stays off until the
 * gate's standing blockers are cleared with evidence.
 */
internal object KdbxGatedMergePublisher {
    data class Request(
        val report: KdbxThreeCopyReview.Report,
        val baseCiphertext: ByteArray,
        val localCiphertext: ByteArray,
        val remoteCiphertext: ByteArray,
        val mergedCiphertext: ByteArray,
        val expectedBaseRevision: String,
        val hasLiveLease: () -> Boolean,
        val leasedDownload: () -> ByteArray?,
        val publish: (ByteArray) -> String
    )

    data class Result(
        val published: Boolean,
        val blockers: List<String>,
        val confirmedRevision: String?
    ) {
        init {
            require(!published || blockers.isEmpty()) {
                "Published merge cannot retain blockers"
            }
            require(published || blockers.isNotEmpty()) {
                "Unpublished merge must list blockers"
            }
            require(published == (confirmedRevision != null)) {
                "Confirmed revision only when published"
            }
        }
    }

    /**
     * Never deletes the supplied original ciphertexts. On denial or failure the
     * caller retains recovery material; this API does not clear dirty state.
     */
    fun attempt(request: Request): Result {
        require(request.baseCiphertext.isNotEmpty()) { "Base ciphertext must be retained" }
        require(request.localCiphertext.isNotEmpty()) { "Local ciphertext must be retained" }
        require(request.remoteCiphertext.isNotEmpty()) { "Remote ciphertext must be retained" }
        require(request.mergedCiphertext.isNotEmpty()) { "Merged ciphertext must be non-empty" }

        val decision = KdbxMergeAuthorizationGate.evaluate(request.report)
        if (!decision.authorized) {
            return Result(
                published = false,
                blockers = decision.blockers,
                confirmedRevision = null
            )
        }

        val revalidation = KdbxMergeLeaseRevalidator.revalidate(
            expectedBaseRevision = request.expectedBaseRevision,
            hasLiveLease = request.hasLiveLease,
            leasedDownload = request.leasedDownload
        )
        if (!revalidation.ok) {
            return Result(
                published = false,
                blockers = listOf(revalidation.reason!!),
                confirmedRevision = null
            )
        }

        // Unreachable while standing blockers keep authorization denied.
        // When that changes, publish only after the lease-bound revalidation above.
        val confirmed = request.publish(request.mergedCiphertext)
        require(confirmed.isNotBlank()) { "Coordinator publish acknowledgement missing" }
        return Result(published = true, blockers = emptyList(), confirmedRevision = confirmed)
    }
}
