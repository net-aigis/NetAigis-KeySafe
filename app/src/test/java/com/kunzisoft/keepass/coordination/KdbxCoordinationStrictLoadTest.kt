/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class KdbxCoordinationStrictLoadTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `empty ciphertext is rejected before crypto`() {
        try {
            KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = byteArrayOf(),
                masterCredential = MasterCredential("x".toCharArray()),
                binaryCacheDirectory = tempFolder.newFolder("bin")
            )
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // fail closed without native crypto
        }
    }

    @Test
    fun `oversized ciphertext is rejected before crypto`() {
        val oversized = ByteArray(CoordinatorByteLimits.MAX_KDBX_BYTES + 1) { 1 }
        try {
            KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = oversized,
                masterCredential = MasterCredential("x".toCharArray()),
                binaryCacheDirectory = tempFolder.newFolder("bin")
            )
            fail("expected IllegalArgumentException")
        } catch (error: IllegalArgumentException) {
            assertTrue(error.message!!.contains("exceeds"))
        }
    }

    @Test
    fun `opened attestation always refuses unknown extensions`() {
        val opened = KdbxCoordinationStrictLoad.Opened(
            database = com.kunzisoft.keepass.database.element.database.DatabaseKDBX()
        )
        assertTrue(opened.unknownExtensionsRefused)
        assertTrue(KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS)
    }
}
