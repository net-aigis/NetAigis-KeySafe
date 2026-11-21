/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest

/**
 * Publishes a real AES-KDF assembled KDBX tip to the live Go coordinator and
 * reloads it read-only. Pair with XC `KEYSAFE_INTEGRATION_REVERSE` after setting
 * KEYSAFE_INTEGRATION_EXPECTED_SHA256 from stderr KEYSAFE_BRIDGE_SHA256.
 * Does not authorize auto-publish.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxRealKdbxBridgeIntegrationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun publishesAndReloadsRealAesKdfKdbxTip() {
        val url = System.getenv("KEYSAFE_INTEGRATION_URL")
        assumeTrue("KEYSAFE_INTEGRATION_URL required", !url.isNullOrBlank())
        val token = System.getenv("KEYSAFE_INTEGRATION_TOKEN")
            ?: System.getenv("KDBX_COORDINATOR_TOKEN")
        assumeTrue("integration token ≥32 chars", !token.isNullOrBlank() && token.length >= 32)
        val dbId = System.getenv("KEYSAFE_INTEGRATION_DB_ID")
            ?: "real_kdbx_bridge_1"

        val cache = tempFolder.newFolder("real-kdbx-bridge-bin")
        val assembled = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(cache)
        val sha = MessageDigest.getInstance("SHA-256").digest(assembled.ciphertext)
            .joinToString("") { b -> "%02x".format(b) }

        val writer = KdbxCoordinatorClient(
            url!!,
            dbId,
            token!!,
            "KdbxRealKdbxBridgeIntegrationTest",
            allowInsecureLoopbackForTests = true,
        )
        writer.acquire()
        try {
            val rev = writer.publish(assembled.ciphertext)
            assertEquals(sha, rev.lowercase())
            assertArrayEquals(assembled.ciphertext, writer.download()!!)
        } finally {
            writer.close()
        }

        val tip = KdbxCoordinatorClient(
            url,
            dbId,
            token,
            "KdbxRealKdbxBridgeIntegrationTest-reader",
            allowInsecureLoopbackForTests = true,
        ).downloadReadOnly()
        assertNotNull(tip)
        assertTrue(tip!!.contentEquals(assembled.ciphertext))
        System.err.println("KEYSAFE_BRIDGE_DB_ID=$dbId")
        System.err.println("KEYSAFE_BRIDGE_SHA256=$sha")
    }
}
