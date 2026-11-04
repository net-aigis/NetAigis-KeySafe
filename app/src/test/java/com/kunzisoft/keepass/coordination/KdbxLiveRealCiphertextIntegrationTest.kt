/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
import java.io.IOException
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Android↔Go live protocol with assembled AES-KDF ciphertext (not dummy bytes).
 * Does not clear XC dual-client or native-Argon2 gate blockers.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxLiveRealCiphertextIntegrationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    private val token = "integration-test-only-secret-0123456789abcdef"

    private fun requireLiveUrl(): String {
        val url = System.getenv("KEYSAFE_INTEGRATION_URL")
        assumeTrue("Live coordinator not configured", !url.isNullOrBlank())
        check(java.net.URI(url!!).host in listOf("127.0.0.1", "localhost"))
        return url
    }

    private fun client(url: String, database: String, owner: String) =
        KdbxCoordinatorClient(url, database, token, owner, allowInsecureLoopbackForTests = true)

    private fun databaseId(prefix: String) = prefix + UUID.randomUUID().toString().replace("-", "")

    private inline fun <reified T : Throwable> mustThrow(noinline call: () -> Unit) {
        try {
            call()
        } catch (e: Throwable) {
            if (e is T) return
            throw AssertionError(
                "Expected ${T::class.java.simpleName}, got ${e.javaClass.simpleName}: ${e.message}",
                e
            )
        }
        throw AssertionError("Expected ${T::class.java.simpleName} but call succeeded")
    }

    @Test
    fun `assembled AES-KDF ciphertext publishes and reloads through the live Go coordinator`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("binaries")
        )
        val database = databaseId("real")
        client(url, database, "alpha").use { writer ->
            writer.acquire()
            val revision = writer.publish(fixture.ciphertext)
            check(revision.length == 64)
            client(url, database, "beta").use { reader ->
                val downloaded = reader.downloadReadOnly()
                check(downloaded != null && downloaded.contentEquals(fixture.ciphertext))
                val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                    encryptedKdbx = downloaded,
                    masterCredential = MasterCredential(
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

    @Test
    fun `interrupted real AES-KDF upload leaves server unchanged then retry succeeds`() {
        val url = requireLiveUrl()
        val rejected = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("reject-bin"),
            localPassword = "reject-secret"
        )
        val accepted = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("accept-bin"),
            localPassword = "accept-secret"
        )
        val database = databaseId("intr")
        val attempts = AtomicInteger(0)
        KdbxLiveFaultProxy(url, interceptPut = { _, _ ->
            if (attempts.getAndIncrement() == 0) {
                KdbxLiveFaultProxy.Mode.REJECT_BEFORE_FORWARD
            } else {
                KdbxLiveFaultProxy.Mode.NORMAL
            }
        }).use { proxy ->
            client(proxy.url, database, "retry").use { writer ->
                writer.acquire()
                mustThrow<IOException> { writer.publish(rejected.ciphertext) }
                client(url, database, "observer").use { observer ->
                    check(observer.downloadReadOnly() == null) {
                        "Rejected real-KDBX upload changed server"
                    }
                }
                writer.publish(accepted.ciphertext)
                client(url, database, "observer").use { observer ->
                    val downloaded = observer.downloadReadOnly()
                    check(downloaded != null && downloaded.contentEquals(accepted.ciphertext))
                }
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `lost acknowledgement after real AES-KDF commit is visible to a fresh reader`() {
        val url = requireLiveUrl()
        val first = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("ack-bin"),
            localPassword = "ack-secret"
        )
        val stale = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("stale-bin"),
            localPassword = "stale-secret"
        )
        val database = databaseId("ack")
        val attempts = AtomicInteger(0)
        KdbxLiveFaultProxy(url, interceptPut = { _, _ ->
            if (attempts.getAndIncrement() == 0) {
                KdbxLiveFaultProxy.Mode.ACK_LOST
            } else {
                KdbxLiveFaultProxy.Mode.NORMAL
            }
        }).use { proxy ->
            client(proxy.url, database, "ambiguous").use { writer ->
                writer.acquire()
                mustThrow<IOException> { writer.publish(first.ciphertext) }
                client(url, database, "observer").use { observer ->
                    val downloaded = observer.downloadReadOnly()
                    check(downloaded != null && downloaded.contentEquals(first.ciphertext))
                }
                mustThrow<KdbxCoordinatorClient.StaleRevisionException> {
                    writer.publish(stale.ciphertext)
                }
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `second Android client stays busy while first holds lease on real AES-KDF database id`() {
        val url = requireLiveUrl()
        val database = databaseId("busy")
        client(url, database, "holder").use { holder ->
            holder.acquire()
            client(url, database, "waiter").use { waiter ->
                mustThrow<KdbxCoordinatorClient.BusyException> { waiter.acquire() }
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }
}
