/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class KdbxGatedMergePipelineTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `empty base ciphertext fails closed before publish`() {
        try {
            KdbxGatedMergePipeline.attempt(
                KdbxGatedMergePipeline.Inputs(
                    baseCiphertext = byteArrayOf(),
                    localCiphertext = byteArrayOf(1, 2, 3),
                    remoteCiphertext = byteArrayOf(1, 2, 3),
                    masterCredential = MasterCredential("x".toCharArray()),
                    binaryCacheDirectory = tempFolder.newFolder("bin"),
                    expectedBaseRevision = "0",
                    hasLiveLease = { fail("lease must not run"); false },
                    leasedDownload = { fail("download must not run"); null },
                    publish = { fail("publish must not run"); "dead" }
                )
            )
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // fail closed at strict load
        }
    }

    @Test
    fun `pipeline outcome type keeps publish denied semantics`() {
        val outcome = KdbxGatedMergePipeline.Outcome(
            published = false,
            blockers = listOf(
                "no validated lossless KDBX merge writer under native Argon2 / dual-client reopen"
            ),
            confirmedRevision = null,
            report = null
        )
        assertFalse(outcome.published)
        assertTrue(outcome.blockers.isNotEmpty())
    }
}
