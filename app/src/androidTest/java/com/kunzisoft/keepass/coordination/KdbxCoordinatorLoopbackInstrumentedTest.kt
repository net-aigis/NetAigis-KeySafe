/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * Device/emulator smoke: KeySafe coordinator client over loopback via `adb reverse`.
 * Pass runner args: integration_url, integration_token (≥32), integration_db_id,
 * optional integration_expected_sha256 (hex). Not part of default CI unit job.
 */
class KdbxCoordinatorLoopbackInstrumentedTest {
    @Test
    fun downloadsPublishedTipThroughReverseLoopback() {
        val args = InstrumentationRegistry.getArguments()
        val url = args.getString("integration_url")?.trim()
        assumeTrue("integration_url runner arg required", !url.isNullOrEmpty())
        val token = args.getString("integration_token")?.trim()
        assumeTrue("integration_token ≥32 chars", !token.isNullOrEmpty() && token.length >= 32)
        val dbId = args.getString("integration_db_id")?.trim()
        assumeTrue("integration_db_id runner arg required", !dbId.isNullOrEmpty())

        val reader = KdbxCoordinatorClient(
            url!!,
            dbId!!,
            token!!,
            "KdbxCoordinatorLoopbackInstrumentedTest",
            allowInsecureLoopbackForTests = true,
        )
        val tip = reader.downloadReadOnly()
        assertNotNull("tip must exist for $dbId", tip)
        assertTrue(tip!!.isNotEmpty())

        val expectedSha = args.getString("integration_expected_sha256")?.trim()
        if (!expectedSha.isNullOrEmpty()) {
            val actual = MessageDigest.getInstance("SHA-256").digest(tip)
                .joinToString("") { b -> "%02x".format(b) }
            assertEquals(expectedSha.lowercase(), actual)
        }
    }
}
