/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.file.input.DatabaseInputKDBX
import com.kunzisoft.keepass.database.file.output.DatabaseOutputKDBX
import com.kunzisoft.keepass.hardware.HardwareKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Serializes a conflict-free assembled [DatabaseKDBX], reloads it with
 * [KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS], and returns the
 * ciphertext plus reopened model (phase 3C).
 *
 * This never publishes, never clears [KdbxMergeAuthorizationGate], and must not
 * be treated as automatic merge authorization. Dual-client proofs remain
 * independent standing blockers.
 */
internal object KdbxAssembledCiphertextWriter {
    data class Result(
        val ciphertext: ByteArray,
        val reloaded: DatabaseKDBX
    )

    fun writeAndStrictReload(
        assembled: DatabaseKDBX,
        masterCredential: MasterCredential,
        binaryCacheDirectory: File,
        challengeResponseRetriever: (HardwareKey, ByteArray?) -> ByteArray = { _, _ -> ByteArray(0) }
    ): Result {
        require(binaryCacheDirectory.isDirectory || binaryCacheDirectory.mkdirs()) {
            "Binary cache directory must be creatable"
        }
        assembled.binaryCache.cacheDirectory = binaryCacheDirectory

        val output = ByteArrayOutputStream()
        DatabaseOutputKDBX(assembled).writeDatabase(output) {
            assembled.deriveMasterKey(masterCredential, challengeResponseRetriever)
        }
        val ciphertext = output.toByteArray()
        require(ciphertext.isNotEmpty()) { "Assembled KDBX ciphertext must be non-empty" }

        val reloaded = DatabaseKDBX().also {
            it.binaryCache.cacheDirectory = binaryCacheDirectory
        }
        DatabaseInputKDBX(reloaded).apply {
            setRefuseUnknownExtensions(KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS)
            openDatabase(ByteArrayInputStream(ciphertext), null) {
                reloaded.deriveMasterKey(masterCredential, challengeResponseRetriever)
            }
        }
        KdbxModelSnapshotReader.read(reloaded)
        return Result(ciphertext = ciphertext, reloaded = reloaded)
    }
}
