/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
import com.kunzisoft.keepass.hardware.HardwareKey
import java.io.File

/**
 * End-to-end gated merge pipeline (still fail-closed / no auto-publish).
 *
 * Order: strict-load three ciphertexts → three-copy review → conflict-free
 * assemble → ciphertext write+strict reload → [KdbxGatedMergePublisher].
 * The publisher refuses every PUT while [KdbxMergeAuthorizationGate] denies.
 */
internal object KdbxGatedMergePipeline {
    data class Inputs(
        val baseCiphertext: ByteArray,
        val localCiphertext: ByteArray,
        val remoteCiphertext: ByteArray,
        val masterCredential: MasterCredential,
        val binaryCacheDirectory: File,
        val expectedBaseRevision: String,
        val hasLiveLease: () -> Boolean,
        val leasedDownload: () -> ByteArray?,
        val publish: (ByteArray) -> String,
        val challengeResponseRetriever: (HardwareKey, ByteArray?) -> ByteArray = { _, _ -> ByteArray(0) }
    )

    data class Outcome(
        val published: Boolean,
        val blockers: List<String>,
        val confirmedRevision: String?,
        val report: KdbxThreeCopyReview.Report?
    )

    fun attempt(inputs: Inputs): Outcome {
        val base = KdbxCoordinationStrictLoad.openEncrypted(
            inputs.baseCiphertext,
            inputs.masterCredential,
            inputs.binaryCacheDirectory,
            inputs.challengeResponseRetriever
        )
        val local = KdbxCoordinationStrictLoad.openEncrypted(
            inputs.localCiphertext,
            inputs.masterCredential,
            inputs.binaryCacheDirectory,
            inputs.challengeResponseRetriever
        )
        val remote = KdbxCoordinationStrictLoad.openEncrypted(
            inputs.remoteCiphertext,
            inputs.masterCredential,
            inputs.binaryCacheDirectory,
            inputs.challengeResponseRetriever
        )
        require(base.unknownExtensionsRefused && local.unknownExtensionsRefused && remote.unknownExtensionsRefused)

        val report = KdbxThreeCopyReview.read(
            base.database,
            local.database,
            remote.database,
            unknownExtensionsRefused = true
        )
        if (report.conflictIds.isNotEmpty() || report.metadata.conflictKeys.isNotEmpty()) {
            return Outcome(
                published = false,
                blockers = listOf("three-copy review still reports unresolved conflicts") +
                    report.mergeAuthorization.blockers,
                confirmedRevision = null,
                report = report
            )
        }

        val assembled = KdbxConflictFreeSelectedAssembler.assemble(
            base.database,
            local.database,
            remote.database,
            report
        )
        val written = KdbxAssembledCiphertextWriter.writeAndStrictReload(
            assembled = assembled,
            masterCredential = inputs.masterCredential,
            binaryCacheDirectory = inputs.binaryCacheDirectory,
            challengeResponseRetriever = inputs.challengeResponseRetriever
        )
        val publishResult = KdbxGatedMergePublisher.attempt(
            KdbxGatedMergePublisher.Request(
                report = report,
                baseCiphertext = inputs.baseCiphertext,
                localCiphertext = inputs.localCiphertext,
                remoteCiphertext = inputs.remoteCiphertext,
                mergedCiphertext = written.ciphertext,
                expectedBaseRevision = inputs.expectedBaseRevision,
                hasLiveLease = inputs.hasLiveLease,
                leasedDownload = inputs.leasedDownload,
                publish = inputs.publish
            )
        )
        return Outcome(
            published = publishResult.published,
            blockers = publishResult.blockers,
            confirmedRevision = publishResult.confirmedRevision,
            report = report
        )
    }
}
