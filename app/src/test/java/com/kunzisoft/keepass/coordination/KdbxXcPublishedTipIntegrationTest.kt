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
 * Dual-client bridge: KeySafe reads a tip previously published by the XC
 * KdbxCoordinatorClient live QtTest (same Go coordinator, same DB id).
 *
 * Requires KEYSAFE_INTEGRATION_URL, KEYSAFE_INTEGRATION_TOKEN (≥32 chars),
 * KEYSAFE_INTEGRATION_DB_ID matching the XC live run, and optional
 * KEYSAFE_INTEGRATION_EXPECTED_SHA256 (hex) of the opaque payload.
 * Does not authorize auto-publish.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxXcPublishedTipIntegrationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun keySafeReloadsTipPublishedByXcCoordinatorClient() {
        val url = System.getenv("KEYSAFE_INTEGRATION_URL")
        assumeTrue("KEYSAFE_INTEGRATION_URL required", !url.isNullOrBlank())
        val token = System.getenv("KEYSAFE_INTEGRATION_TOKEN")
            ?: System.getenv("KDBX_COORDINATOR_TOKEN")
        assumeTrue("integration token ≥32 chars", !token.isNullOrBlank() && token.length >= 32)
        val dbId = System.getenv("KEYSAFE_INTEGRATION_DB_ID")
        assumeTrue("KEYSAFE_INTEGRATION_DB_ID required", !dbId.isNullOrBlank())

        val reader = KdbxCoordinatorClient(
            url!!,
            dbId!!,
            token!!,
            "KdbxXcPublishedTipIntegrationTest",
            allowInsecureLoopbackForTests = true,
        )
        // Read-only path: XC holds the lease while publishing; after release another
        // client must not call download() (lease required). Tip read uses GET /file only.
        val tip = reader.downloadReadOnly()
        assertNotNull("XC-published tip must exist for $dbId", tip)
        assertTrue(tip!!.isNotEmpty())
        val expectedSha = System.getenv("KEYSAFE_INTEGRATION_EXPECTED_SHA256")
        if (!expectedSha.isNullOrBlank()) {
            val actual = MessageDigest.getInstance("SHA-256").digest(tip)
                .joinToString("") { b -> "%02x".format(b) }
            assertEquals(expectedSha.lowercase(), actual)
        }
    }

    @Test
    fun keySafePublishesTipForXcCoordinatorClient() {
        val url = System.getenv("KEYSAFE_INTEGRATION_URL")
        assumeTrue("KEYSAFE_INTEGRATION_URL required", !url.isNullOrBlank())
        val token = System.getenv("KEYSAFE_INTEGRATION_TOKEN")
            ?: System.getenv("KDBX_COORDINATOR_TOKEN")
        assumeTrue("integration token ≥32 chars", !token.isNullOrBlank() && token.length >= 32)
        val dbId = System.getenv("KEYSAFE_INTEGRATION_DB_ID")
        assumeTrue("KEYSAFE_INTEGRATION_DB_ID required", !dbId.isNullOrBlank())

        val payload = ByteArray(2048) { i -> ((i * 19 + 7) and 0xff).toByte() }
        payload[0] = 0x03
        payload[1] = 0xd9.toByte()
        val expectedSha = MessageDigest.getInstance("SHA-256").digest(payload)
            .joinToString("") { b -> "%02x".format(b) }

        val writer = KdbxCoordinatorClient(
            url!!,
            dbId!!,
            token!!,
            "KdbxXcPublishedTipIntegrationTest-writer",
            allowInsecureLoopbackForTests = true,
        )
        writer.acquire()
        try {
            val rev = writer.publish(payload)
            assertEquals(expectedSha, rev.lowercase())
            assertArrayEquals(payload, writer.download()!!)
        } finally {
            writer.close()
        }
        System.err.println("KEYSAFE_BRIDGE_SHA256=$expectedSha")
    }

    /**
     * Dual-client bridge with assembled AES-KDF KDBX (not opaque random bytes).
     * Keysafe publishes; XC [KEYSAFE_INTEGRATION_REVERSE] acquires and checks SHA-256.
     */
    @Test
    fun keySafePublishesRealAesKdfKdbxForXcCoordinatorClient() {
        val url = System.getenv("KEYSAFE_INTEGRATION_URL")
        assumeTrue("KEYSAFE_INTEGRATION_URL required", !url.isNullOrBlank())
        val token = System.getenv("KEYSAFE_INTEGRATION_TOKEN")
            ?: System.getenv("KDBX_COORDINATOR_TOKEN")
        assumeTrue("integration token ≥32 chars", !token.isNullOrBlank() && token.length >= 32)
        val dbId = System.getenv("KEYSAFE_INTEGRATION_DB_ID") ?: "real_kdbx_bridge_1"

        val cache = tempFolder.newFolder("real-kdbx-bridge-bin")
        val assembled = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(cache)
        val payload = assembled.ciphertext
        val expectedSha = MessageDigest.getInstance("SHA-256").digest(payload)
            .joinToString("") { b -> "%02x".format(b) }

        val writer = KdbxCoordinatorClient(
            url!!,
            dbId,
            token!!,
            "KdbxXcPublishedTipIntegrationTest-real-kdbx",
            allowInsecureLoopbackForTests = true,
        )
        writer.acquire()
        try {
            val rev = writer.publish(payload)
            assertEquals(expectedSha, rev.lowercase())
            assertArrayEquals(payload, writer.download()!!)
        } finally {
            writer.close()
        }
        val tip = KdbxCoordinatorClient(
            url,
            dbId,
            token,
            "KdbxXcPublishedTipIntegrationTest-real-kdbx-reader",
            allowInsecureLoopbackForTests = true,
        ).downloadReadOnly()
        assertNotNull(tip)
        assertArrayEquals(payload, tip!!)
        System.err.println("KEYSAFE_BRIDGE_SHA256=$expectedSha")
        System.err.println("KEYSAFE_BRIDGE_KDBX_BYTES=${payload.size}")
    }

}
