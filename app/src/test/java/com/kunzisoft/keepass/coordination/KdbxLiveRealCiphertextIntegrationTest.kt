/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

/**
 * Android↔Go live protocol with assembled AES-KDF ciphertext (not dummy bytes).
 * Does not clear XC dual-client or native-Argon2 gate blockers.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxLiveRealCiphertextIntegrationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `assembled AES-KDF ciphertext publishes and reloads through the live Go coordinator`() {
        val url = System.getenv("KEYSAFE_INTEGRATION_URL")
        assumeTrue("Live coordinator not configured", !url.isNullOrBlank())
        check(java.net.URI(url!!).host in listOf("127.0.0.1", "localhost"))

        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("binaries")
        )
        val database = "real" + UUID.randomUUID().toString().replace("-", "")
        val token = "integration-test-only-secret-0123456789abcdef"

        KdbxCoordinatorClient(url, database, token, "alpha", allowInsecureLoopbackForTests = true).use { writer ->
            writer.acquire()
            val revision = writer.publish(fixture.ciphertext)
            check(revision.length == 64)
            KdbxCoordinatorClient(url, database, token, "beta", allowInsecureLoopbackForTests = true).use { reader ->
                val downloaded = reader.downloadReadOnly()
                check(downloaded != null && downloaded.contentEquals(fixture.ciphertext))
                val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                    encryptedKdbx = downloaded,
                    masterCredential = com.kunzisoft.keepass.database.element.MasterCredential(
                        KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                    ),
                    binaryCacheDirectory = tempFolder.newFolder("reload")
                )
                assertTrue(
                    reloaded.database.getEntryById(fixture.entryId)!!.password
                        .contentEquals(fixture.entryPassword.toCharArray())
                )
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }
}
