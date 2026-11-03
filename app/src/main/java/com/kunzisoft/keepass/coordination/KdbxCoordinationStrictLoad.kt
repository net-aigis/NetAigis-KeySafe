/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.file.input.DatabaseInputKDBX
import com.kunzisoft.keepass.hardware.HardwareKey
import java.io.ByteArrayInputStream
import java.io.File

/**
 * Opens encrypted KDBX candidates for three-copy review / gated merge with
 * [KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS]. Everyday UI password
 * entry must not use this path.
 *
 * Returns an attestation flag suitable for [KdbxThreeCopyReview.read]. Does not
 * authorize merge or publish.
 */
internal object KdbxCoordinationStrictLoad {
    data class Opened(
        val database: DatabaseKDBX,
        val unknownExtensionsRefused: Boolean = KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS
    ) {
        init {
            require(unknownExtensionsRefused) {
                "Coordination strict load must attest refuseUnknownExtensions"
            }
        }
    }

    fun openEncrypted(
        encryptedKdbx: ByteArray,
        masterCredential: MasterCredential,
        binaryCacheDirectory: File,
        challengeResponseRetriever: (HardwareKey, ByteArray?) -> ByteArray = { _, _ -> ByteArray(0) }
    ): Opened {
        require(encryptedKdbx.isNotEmpty()) { "Encrypted KDBX candidate must be non-empty" }
        require(encryptedKdbx.size <= CoordinatorByteLimits.MAX_KDBX_BYTES) {
            "Encrypted KDBX candidate exceeds permitted in-memory size"
        }
        require(binaryCacheDirectory.isDirectory || binaryCacheDirectory.mkdirs()) {
            "Binary cache directory must be creatable"
        }

        val database = DatabaseKDBX().also {
            it.binaryCache.cacheDirectory = binaryCacheDirectory
        }
        DatabaseInputKDBX(database).apply {
            setRefuseUnknownExtensions(KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS)
            openDatabase(ByteArrayInputStream(encryptedKdbx), null) {
                database.deriveMasterKey(masterCredential, challengeResponseRetriever)
            }
        }
        // Structural fail-closed before any three-copy review.
        KdbxModelSnapshotReader.read(database)
        return Opened(database = database)
    }
}
