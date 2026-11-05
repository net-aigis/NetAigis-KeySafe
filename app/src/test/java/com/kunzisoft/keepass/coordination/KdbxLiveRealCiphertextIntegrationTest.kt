/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
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
    fun `double acquire on same real AES-KDF client fails closed`() {
        val url = requireLiveUrl()
        val database = databaseId("dblacq")
        client(url, database, "writer").use { writer ->
            writer.acquire()
            mustThrow<IllegalStateException> { writer.acquire() }
            check(writer.hasLease())
            client(url, database, "waiter").use { waiter ->
                mustThrow<KdbxCoordinatorClient.BusyException> { waiter.acquire() }
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `empty tip download returns null then first real AES-KDF publish creates tip`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("emptytip-bin"),
            localPassword = "emptytip-secret"
        )
        val database = databaseId("emptytip")
        client(url, database, "observer").use { observer ->
            check(observer.downloadReadOnly() == null) {
                "Fresh database id must have no tip"
            }
        }
        client(url, database, "writer").use { writer ->
            writer.acquire()
            writer.publish(fixture.ciphertext)
        }
        client(url, database, "observer").use { observer ->
            val tip = observer.downloadReadOnly()
            check(tip != null && tip.contentEquals(fixture.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = tip,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("emptytip-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(fixture.entryId)!!.password
                    .contentEquals(fixture.entryPassword.toCharArray())
            )
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `close releases real AES-KDF lease so the next owner can acquire immediately`() {
        val url = requireLiveUrl()
        val first = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("closerel-a-bin"),
            localPassword = "closerel-a-secret"
        )
        val second = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("closerel-b-bin"),
            localPassword = "closerel-b-secret"
        )
        val database = databaseId("closerel")
        client(url, database, "alpha").use { alpha ->
            alpha.acquire()
            alpha.publish(first.ciphertext)
            check(alpha.hasLease())
        }
        client(url, database, "beta").use { beta ->
            beta.acquire()
            check(beta.hasLease())
            beta.publish(second.ciphertext)
            val tip = beta.download()
            check(tip != null && tip.contentEquals(second.ciphertext))
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `exclusive lease on one database id does not busy another`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("leaseiso-bin"),
            localPassword = "leaseiso-secret"
        )
        val dbA = databaseId("leaseisoa")
        val dbB = databaseId("leaseisob")
        client(url, dbA, "holder").use { holder ->
            holder.acquire()
            holder.publish(fixture.ciphertext)
            client(url, dbA, "waiter").use { waiter ->
                mustThrow<KdbxCoordinatorClient.BusyException> { waiter.acquire() }
            }
            client(url, dbB, "other").use { other ->
                other.acquire()
                check(other.hasLease())
                other.publish(fixture.ciphertext)
                check(other.download()!!.contentEquals(fixture.ciphertext))
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `real AES-KDF tips stay isolated across database ids`() {
        val url = requireLiveUrl()
        val first = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("iso-a-bin"),
            localPassword = "iso-a-secret"
        )
        val second = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("iso-b-bin"),
            localPassword = "iso-b-secret"
        )
        val dbA = databaseId("isoa")
        val dbB = databaseId("isob")
        client(url, dbA, "alpha").use { a ->
            a.acquire()
            a.publish(first.ciphertext)
        }
        client(url, dbB, "beta").use { b ->
            b.acquire()
            b.publish(second.ciphertext)
        }
        client(url, dbA, "obs-a").use { observer ->
            val tip = observer.downloadReadOnly()
            check(tip != null && tip.contentEquals(first.ciphertext))
            check(!tip.contentEquals(second.ciphertext))
        }
        client(url, dbB, "obs-b").use { observer ->
            val tip = observer.downloadReadOnly()
            check(tip != null && tip.contentEquals(second.ciphertext))
            check(!tip.contentEquals(first.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = tip,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("iso-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(second.entryId)!!.password
                    .contentEquals(second.entryPassword.toCharArray())
            )
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `publish without acquire fails closed on live coordinator`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("nolease-bin"),
            localPassword = "nolease-secret"
        )
        val database = databaseId("nolease")
        client(url, database, "writer").use { writer ->
            mustThrow<IOException> { writer.publish(fixture.ciphertext) }
            client(url, database, "observer").use { observer ->
                check(observer.downloadReadOnly() == null) {
                    "Publish without lease must not create a tip"
                }
            }
            writer.acquire()
            writer.publish(fixture.ciphertext)
            client(url, database, "observer").use { observer ->
                val tip = observer.downloadReadOnly()
                check(tip != null && tip.contentEquals(fixture.ciphertext))
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `coordinator client rejects traversal database id short token and cleartext remote`() {
        mustThrow<IllegalArgumentException> {
            KdbxCoordinatorClient(
                "http://127.0.0.1:9/",
                "../evil",
                token,
                "owner",
                allowInsecureLoopbackForTests = true
            )
        }
        mustThrow<IllegalArgumentException> {
            KdbxCoordinatorClient(
                "http://127.0.0.1:9/",
                "ok-db",
                "too-short-token",
                "owner",
                allowInsecureLoopbackForTests = true
            )
        }
        mustThrow<IllegalArgumentException> {
            KdbxCoordinatorClient(
                "http://example.org/",
                "ok-db",
                token,
                "owner",
                allowInsecureLoopbackForTests = true
            )
        }
        mustThrow<IllegalArgumentException> {
            KdbxCoordinatorClient(
                "http://127.0.0.1:9/",
                "ok-db",
                token,
                "bad/owner",
                allowInsecureLoopbackForTests = true
            )
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
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
    fun `same owner successive real AES-KDF publishes advance tip without releasing lease`() {
        val url = requireLiveUrl()
        val first = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("succ-a-bin"),
            localPassword = "succ-a-secret"
        )
        val second = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("succ-b-bin"),
            localPassword = "succ-b-secret"
        )
        val database = databaseId("succ")
        client(url, database, "writer").use { writer ->
            writer.acquire()
            val rev1 = writer.publish(first.ciphertext)
            check(rev1.length == 64)
            check(writer.download()!!.contentEquals(first.ciphertext))
            val rev2 = writer.publish(second.ciphertext)
            check(rev2.length == 64 && rev2 != rev1)
            check(writer.download()!!.contentEquals(second.ciphertext))
        }
        client(url, database, "observer").use { observer ->
            val tip = observer.downloadReadOnly()
            check(tip != null && tip.contentEquals(second.ciphertext))
            check(!tip.contentEquals(first.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = tip,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("succ-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(second.entryId)!!.password
                    .contentEquals(second.entryPassword.toCharArray())
            )
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

    @Test
    fun `concurrent observers reload the same real AES-KDF tip`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("multi-obs-bin"),
            localPassword = "multi-obs-secret"
        )
        val database = databaseId("multiobs")
        client(url, database, "writer").use { writer ->
            writer.acquire()
            writer.publish(fixture.ciphertext)
        }
        val ready = CountDownLatch(4)
        val start = CountDownLatch(1)
        val ok = AtomicInteger(0)
        val errors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
        val pool = Executors.newFixedThreadPool(4)
        try {
            val tasks = (0 until 4).map { idx ->
                pool.submit {
                    ready.countDown()
                    check(start.await(10, TimeUnit.SECONDS))
                    try {
                        client(url, database, "obs$idx").use { observer ->
                            val tip = observer.downloadReadOnly()
                            check(tip != null && tip.contentEquals(fixture.ciphertext))
                            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                                encryptedKdbx = tip,
                                masterCredential = MasterCredential(
                                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                                ),
                                binaryCacheDirectory = tempFolder.newFolder("multi-obs-reload-$idx")
                            )
                            check(
                                reloaded.database.getEntryById(fixture.entryId)!!.password
                                    .contentEquals(fixture.entryPassword.toCharArray())
                            )
                            ok.incrementAndGet()
                        }
                    } catch (e: Throwable) {
                        errors.add(e)
                    }
                }
            }
            check(ready.await(10, TimeUnit.SECONDS))
            start.countDown()
            tasks.forEach { it.get(60, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }
        check(errors.isEmpty()) {
            "Observer failures: ${errors.joinToString { it.javaClass.simpleName + ": " + it.message }}"
        }
        check(ok.get() == 4) { "Expected 4 concurrent observers, got ${ok.get()}" }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `oversized ciphertext publish is refused before contacting live coordinator`() {
        val url = requireLiveUrl()
        val database = databaseId("oversize")
        val oversized = ByteArray(CoordinatorByteLimits.MAX_KDBX_BYTES + 1)
        client(url, database, "writer").use { writer ->
            writer.acquire()
            mustThrow<IOException> { writer.publish(oversized) }
            client(url, database, "observer").use { observer ->
                check(observer.downloadReadOnly() == null) {
                    "Oversized publish must not create a server tip"
                }
            }
            val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
                tempFolder.newFolder("oversize-ok-bin"),
                localPassword = "oversize-ok-secret"
            )
            writer.publish(fixture.ciphertext)
            client(url, database, "observer").use { observer ->
                val tip = observer.downloadReadOnly()
                check(tip != null && tip.contentEquals(fixture.ciphertext))
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `empty ciphertext publish is refused before contacting live coordinator`() {
        val url = requireLiveUrl()
        val database = databaseId("empty")
        client(url, database, "writer").use { writer ->
            writer.acquire()
            mustThrow<IllegalArgumentException> { writer.publish(ByteArray(0)) }
            client(url, database, "observer").use { observer ->
                check(observer.downloadReadOnly() == null) {
                    "Empty publish must not create a server tip"
                }
            }
            val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
                tempFolder.newFolder("empty-ok-bin"),
                localPassword = "empty-ok-secret"
            )
            writer.publish(fixture.ciphertext)
            client(url, database, "observer").use { observer ->
                val tip = observer.downloadReadOnly()
                check(tip != null && tip.contentEquals(fixture.ciphertext))
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `wrong bearer token cannot acquire or read real AES-KDF database id`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("auth-bin"),
            localPassword = "auth-secret"
        )
        val database = databaseId("auth")
        val badToken = "integration-test-WRONG-secret-0123456789ab"
        client(url, database, "owner").use { owner ->
            owner.acquire()
            owner.publish(fixture.ciphertext)
        }
        KdbxCoordinatorClient(
            url,
            database,
            badToken,
            "intruder",
            allowInsecureLoopbackForTests = true
        ).use { intruder ->
            mustThrow<IOException> { intruder.acquire() }
            mustThrow<IOException> { intruder.downloadReadOnly() }
        }
        client(url, database, "observer").use { observer ->
            val tip = observer.downloadReadOnly()
            check(tip != null && tip.contentEquals(fixture.ciphertext))
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `observer still reads tip while exclusive holder keeps real AES-KDF lease`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("obs-busy-bin"),
            localPassword = "obs-busy-secret"
        )
        val database = databaseId("obsbusy")
        client(url, database, "holder").use { holder ->
            holder.acquire()
            holder.publish(fixture.ciphertext)
            client(url, database, "waiter").use { waiter ->
                mustThrow<KdbxCoordinatorClient.BusyException> { waiter.acquire() }
            }
            client(url, database, "observer").use { observer ->
                val tip = observer.downloadReadOnly()
                check(tip != null && tip.contentEquals(fixture.ciphertext))
                val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                    encryptedKdbx = tip,
                    masterCredential = MasterCredential(
                        KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                    ),
                    binaryCacheDirectory = tempFolder.newFolder("obs-busy-reload")
                )
                assertTrue(
                    reloaded.database.getEntryById(fixture.entryId)!!.password
                        .contentEquals(fixture.entryPassword.toCharArray())
                )
            }
            check(holder.hasLease())
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `simultaneous real AES-KDF publishes on the same base leave exactly one winner`() {
        val url = requireLiveUrl()
        val first = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("race-a-bin"),
            localPassword = "race-a-secret"
        )
        val second = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("race-b-bin"),
            localPassword = "race-b-secret"
        )
        val database = databaseId("race")
        val primary = client(url, database, "primary")
        val racer = client(url, database, "racer")
        try {
            primary.acquire()
            // Test-only: share one lease/revision so both PUTs race the same If-Match base,
            // matching the Go concurrent-publish check. Production clients never clone leases.
            val leaseField = KdbxCoordinatorClient::class.java.getDeclaredField("lease")
            val revisionField = KdbxCoordinatorClient::class.java.getDeclaredField("revision")
            leaseField.isAccessible = true
            revisionField.isAccessible = true
            leaseField.set(racer, leaseField.get(primary))
            revisionField.set(racer, revisionField.get(primary))

            val ready = CountDownLatch(2)
            val start = CountDownLatch(1)
            val ok = AtomicInteger(0)
            val stale = AtomicInteger(0)
            val errors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
            val pool = Executors.newFixedThreadPool(2)
            try {
                val tasks = listOf(primary to first.ciphertext, racer to second.ciphertext).map { (writer, body) ->
                    pool.submit {
                        ready.countDown()
                        check(start.await(10, TimeUnit.SECONDS))
                        try {
                            writer.publish(body)
                            ok.incrementAndGet()
                        } catch (_: KdbxCoordinatorClient.StaleRevisionException) {
                            stale.incrementAndGet()
                        } catch (e: Throwable) {
                            errors.add(e)
                        }
                    }
                }
                check(ready.await(10, TimeUnit.SECONDS))
                start.countDown()
                tasks.forEach { it.get(40, TimeUnit.SECONDS) }
            } finally {
                pool.shutdownNow()
            }
            check(errors.isEmpty()) {
                "Unexpected publish failures: ${errors.joinToString { it.javaClass.simpleName + ": " + it.message }}"
            }
            check(ok.get() == 1 && stale.get() == 1) {
                "Exactly one concurrent real-KDBX publish must win: ok=${ok.get()} stale=${stale.get()}"
            }
            client(url, database, "observer").use { observer ->
                val downloaded = observer.downloadReadOnly()
                check(
                    downloaded != null &&
                        (downloaded.contentEquals(first.ciphertext) ||
                            downloaded.contentEquals(second.ciphertext))
                )
                val expected = if (downloaded.contentEquals(first.ciphertext)) first else second
                val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                    encryptedKdbx = downloaded,
                    masterCredential = MasterCredential(
                        KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                    ),
                    binaryCacheDirectory = tempFolder.newFolder("race-reload")
                )
                assertTrue(
                    reloaded.database.getEntryById(expected.entryId)!!.password
                        .contentEquals(expected.entryPassword.toCharArray())
                )
            }
        } finally {
            runCatching { primary.close() }
            runCatching { racer.close() }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `truncated real AES-KDF download fails closed then direct retry reloads ciphertext`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("dl-bin"),
            localPassword = "download-secret"
        )
        val database = databaseId("dlintr")
        client(url, database, "publisher").use { publisher ->
            publisher.acquire()
            publisher.publish(fixture.ciphertext)
        }
        val attempts = AtomicInteger(0)
        KdbxLiveFaultProxy(
            backend = url,
            interceptGetFile = {
                if (attempts.getAndIncrement() == 0) {
                    KdbxLiveFaultProxy.GetMode.TRUNCATE_HALF
                } else {
                    KdbxLiveFaultProxy.GetMode.NORMAL
                }
            }
        ).use { proxy ->
            client(proxy.url, database, "broken").use { broken ->
                mustThrow<IOException> { broken.downloadReadOnly() }
            }
            client(proxy.url, database, "retry").use { retry ->
                val downloaded = retry.downloadReadOnly()
                check(downloaded != null && downloaded.contentEquals(fixture.ciphertext))
                val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                    encryptedKdbx = downloaded,
                    masterCredential = MasterCredential(
                        KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                    ),
                    binaryCacheDirectory = tempFolder.newFolder("dl-reload")
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
    fun `external lease revocation blocks stale real AES-KDF publish then new owner wins`() {
        val url = requireLiveUrl()
        val stale = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("stale-lease-bin"),
            localPassword = "stale-lease-secret"
        )
        val winner = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("winner-lease-bin"),
            localPassword = "winner-lease-secret"
        )
        val database = databaseId("lloss")
        val old = client(url, database, "old")
        try {
            old.acquire()
            val leaseField = KdbxCoordinatorClient::class.java.getDeclaredField("lease")
            leaseField.isAccessible = true
            val oldLease = leaseField.get(old) as String
            val connection = URI("$url/v1/databases/$database/lock").toURL()
                .openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "DELETE"
                connection.setRequestProperty("Authorization", "Bearer $token")
                connection.setRequestProperty("X-KDBX-Lease", oldLease)
                check(connection.responseCode == 204) { "Could not revoke lease" }
            } finally {
                connection.disconnect()
            }
            client(url, database, "new").use { current ->
                current.acquire()
                current.publish(winner.ciphertext)
                mustThrow<KdbxCoordinatorClient.LostLeaseException> {
                    old.publish(stale.ciphertext)
                }
                val downloaded = current.downloadReadOnly()
                check(downloaded != null && downloaded.contentEquals(winner.ciphertext))
                val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                    encryptedKdbx = downloaded,
                    masterCredential = MasterCredential(
                        KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                    ),
                    binaryCacheDirectory = tempFolder.newFolder("lloss-reload")
                )
                assertTrue(
                    reloaded.database.getEntryById(winner.entryId)!!.password
                        .contentEquals(winner.entryPassword.toCharArray())
                )
            }
        } finally {
            runCatching { old.close() }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `rejected real AES-KDF download leaves server ciphertext intact for later readers`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("dlrej-bin"),
            localPassword = "dl-reject-secret"
        )
        val database = databaseId("dlrej")
        client(url, database, "publisher").use { publisher ->
            publisher.acquire()
            publisher.publish(fixture.ciphertext)
        }
        KdbxLiveFaultProxy(
            backend = url,
            interceptGetFile = { KdbxLiveFaultProxy.GetMode.REJECT_BEFORE_FORWARD }
        ).use { proxy ->
            client(proxy.url, database, "blocked").use { blocked ->
                mustThrow<IOException> { blocked.downloadReadOnly() }
            }
        }
        client(url, database, "observer").use { observer ->
            val downloaded = observer.downloadReadOnly()
            check(downloaded != null && downloaded.contentEquals(fixture.ciphertext))
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `failed lease renew after real AES-KDF publish blocks further writes`() {
        val url = requireLiveUrl()
        val published = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("renew-bin"),
            localPassword = "renew-secret"
        )
        val blocked = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("renew-blocked-bin"),
            localPassword = "renew-blocked-secret"
        )
        val database = databaseId("renew")
        KdbxLiveFaultProxy(backend = url, rejectRenew = { true }).use { proxy ->
            client(proxy.url, database, "editor").use { editor ->
                editor.acquire()
                editor.publish(published.ciphertext)
                val renew = KdbxCoordinatorClient::class.java.getDeclaredMethod("renew")
                renew.isAccessible = true
                try {
                    renew.invoke(editor)
                    throw AssertionError("Expected LostLeaseException from renew")
                } catch (e: java.lang.reflect.InvocationTargetException) {
                    val cause = e.cause
                    if (cause !is KdbxCoordinatorClient.LostLeaseException) {
                        throw AssertionError(
                            "Expected LostLeaseException, got ${cause?.javaClass?.simpleName}: ${cause?.message}",
                            cause
                        )
                    }
                }
                assertFalse(editor.hasLease())
                mustThrow<KdbxCoordinatorClient.LostLeaseException> {
                    editor.publish(blocked.ciphertext)
                }
            }
        }
        client(url, database, "observer").use { observer ->
            val downloaded = observer.downloadReadOnly()
            check(downloaded != null && downloaded.contentEquals(published.ciphertext))
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `mismatched ETag on real AES-KDF download fails closed then direct reader reloads`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("dletag-bin"),
            localPassword = "dl-etag-secret"
        )
        val database = databaseId("dletag")
        client(url, database, "publisher").use { publisher ->
            publisher.acquire()
            publisher.publish(fixture.ciphertext)
        }
        KdbxLiveFaultProxy(
            backend = url,
            interceptGetFile = { KdbxLiveFaultProxy.GetMode.WRONG_ETAG }
        ).use { proxy ->
            client(proxy.url, database, "tampered").use { tampered ->
                mustThrow<IOException> { tampered.downloadReadOnly() }
            }
        }
        client(url, database, "observer").use { observer ->
            val downloaded = observer.downloadReadOnly()
            check(downloaded != null && downloaded.contentEquals(fixture.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = downloaded,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("dletag-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(fixture.entryId)!!.password
                    .contentEquals(fixture.entryPassword.toCharArray())
            )
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `wrong publish acknowledgement after real AES-KDF commit fails closed for writer`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("ackmis-bin"),
            localPassword = "ack-mis-secret"
        )
        val database = databaseId("ackmis")
        KdbxLiveFaultProxy(
            backend = url,
            interceptPut = { _, _ -> KdbxLiveFaultProxy.Mode.ACK_WRONG_REVISION }
        ).use { proxy ->
            client(proxy.url, database, "writer").use { writer ->
                writer.acquire()
                mustThrow<IOException> { writer.publish(fixture.ciphertext) }
                assertFalse(writer.hasLease())
            }
        }
        client(url, database, "observer").use { observer ->
            val downloaded = observer.downloadReadOnly()
            check(downloaded != null && downloaded.contentEquals(fixture.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = downloaded,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("ackmis-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(fixture.entryId)!!.password
                    .contentEquals(fixture.entryPassword.toCharArray())
            )
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `real AES-KDF lease handoff lets second owner publish and first stays out`() {
        val url = requireLiveUrl()
        val first = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("handoff-a-bin"),
            localPassword = "handoff-a-secret"
        )
        val second = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("handoff-b-bin"),
            localPassword = "handoff-b-secret"
        )
        val database = databaseId("handoff")
        client(url, database, "alpha").use { alpha ->
            alpha.acquire()
            alpha.publish(first.ciphertext)
        }
        client(url, database, "beta").use { beta ->
            beta.acquire()
            beta.publish(second.ciphertext)
            val downloaded = beta.download()
            check(downloaded != null && downloaded.contentEquals(second.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = downloaded,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("handoff-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(second.entryId)!!.password
                    .contentEquals(second.entryPassword.toCharArray())
            )
        }
        client(url, database, "observer").use { observer ->
            val downloaded = observer.downloadReadOnly()
            check(downloaded != null && downloaded.contentEquals(second.ciphertext)) {
                "Handoff must leave the second owner's ciphertext as the tip"
            }
            check(!downloaded.contentEquals(first.ciphertext)) {
                "Handoff must not leave the first owner's ciphertext as the tip"
            }
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `real AES-KDF exclusive write returns after A to B to A handoff`() {
        val url = requireLiveUrl()
        val first = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("roundtrip-a1-bin"),
            localPassword = "roundtrip-a1-secret"
        )
        val second = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("roundtrip-b-bin"),
            localPassword = "roundtrip-b-secret"
        )
        val third = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("roundtrip-a2-bin"),
            localPassword = "roundtrip-a2-secret"
        )
        val database = databaseId("handoff2")
        client(url, database, "alpha").use { alpha ->
            alpha.acquire()
            alpha.publish(first.ciphertext)
        }
        client(url, database, "beta").use { beta ->
            beta.acquire()
            beta.publish(second.ciphertext)
            check(beta.download()!!.contentEquals(second.ciphertext))
        }
        client(url, database, "alpha").use { alpha ->
            alpha.acquire()
            alpha.publish(third.ciphertext)
            val downloaded = alpha.download()
            check(downloaded != null && downloaded.contentEquals(third.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = downloaded,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("roundtrip-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(third.entryId)!!.password
                    .contentEquals(third.entryPassword.toCharArray())
            )
        }
        client(url, database, "observer").use { observer ->
            val tip = observer.downloadReadOnly()
            check(tip != null && tip.contentEquals(third.ciphertext)) {
                "A→B→A handoff must leave alpha's second ciphertext as the tip"
            }
            check(!tip.contentEquals(first.ciphertext) && !tip.contentEquals(second.ciphertext))
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `released real AES-KDF lease token cannot overwrite after handoff`() {
        val url = requireLiveUrl()
        val first = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("zombie-a-bin"),
            localPassword = "zombie-a-secret"
        )
        val second = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("zombie-b-bin"),
            localPassword = "zombie-b-secret"
        )
        val stale = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("zombie-stale-bin"),
            localPassword = "zombie-stale-secret"
        )
        val database = databaseId("zombie")
        val leaseField = KdbxCoordinatorClient::class.java.getDeclaredField("lease")
        val revisionField = KdbxCoordinatorClient::class.java.getDeclaredField("revision")
        val lostField = KdbxCoordinatorClient::class.java.getDeclaredField("lost")
        leaseField.isAccessible = true
        revisionField.isAccessible = true
        lostField.isAccessible = true

        lateinit var capturedLease: String
        lateinit var capturedRevision: String
        client(url, database, "alpha").use { alpha ->
            alpha.acquire()
            alpha.publish(first.ciphertext)
            capturedLease = leaseField.get(alpha) as String
            capturedRevision = revisionField.get(alpha) as String
        }
        client(url, database, "beta").use { beta ->
            beta.acquire()
            beta.publish(second.ciphertext)
        }
        client(url, database, "zombie").use { zombie ->
            // Test-only: reinject the released owner's lease/revision after handoff.
            leaseField.set(zombie, capturedLease)
            revisionField.set(zombie, capturedRevision)
            (lostField.get(zombie) as java.util.concurrent.atomic.AtomicBoolean).set(false)
            mustThrow<KdbxCoordinatorClient.LostLeaseException> {
                zombie.publish(stale.ciphertext)
            }
        }
        client(url, database, "observer").use { observer ->
            val tip = observer.downloadReadOnly()
            check(tip != null && tip.contentEquals(second.ciphertext)) {
                "Zombie lease must not overwrite the handoff tip"
            }
            check(!tip.contentEquals(stale.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = tip,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("zombie-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(second.entryId)!!.password
                    .contentEquals(second.entryPassword.toCharArray())
            )
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }

    @Test
    fun `substituted body with real AES-KDF ETag fails closed then direct reader reloads`() {
        val url = requireLiveUrl()
        val fixture = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("dlbody-bin"),
            localPassword = "dl-body-secret"
        )
        val database = databaseId("dlbody")
        client(url, database, "publisher").use { publisher ->
            publisher.acquire()
            publisher.publish(fixture.ciphertext)
        }
        KdbxLiveFaultProxy(
            backend = url,
            interceptGetFile = { KdbxLiveFaultProxy.GetMode.WRONG_BODY }
        ).use { proxy ->
            client(proxy.url, database, "tampered").use { tampered ->
                mustThrow<IOException> { tampered.downloadReadOnly() }
            }
        }
        client(url, database, "observer").use { observer ->
            val downloaded = observer.downloadReadOnly()
            check(downloaded != null && downloaded.contentEquals(fixture.ciphertext))
            val reloaded = KdbxCoordinationStrictLoad.openEncrypted(
                encryptedKdbx = downloaded,
                masterCredential = MasterCredential(
                    KdbxLiveRealCiphertextFixtures.masterPassword.copyOf()
                ),
                binaryCacheDirectory = tempFolder.newFolder("dlbody-reload")
            )
            assertTrue(
                reloaded.database.getEntryById(fixture.entryId)!!.password
                    .contentEquals(fixture.entryPassword.toCharArray())
            )
        }
        assertFalse(KdbxMergeAuthorizationGate.evaluate().authorized)
    }
}
