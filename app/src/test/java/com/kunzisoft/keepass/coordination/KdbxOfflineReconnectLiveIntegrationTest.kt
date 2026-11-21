/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.security.MessageDigest

/**
 * Live offline→reconnect protocol path used by [CoordinatorSession]:
 * pending ciphertext bound to a base revision, then PUBLISH / CONFLICT /
 * ALREADY_PUBLISHED against the Go coordinator.
 *
 * Pending/cache files are seeded with the same naming scheme as production
 * (Robolectric cannot exercise Android `Os.rename`/`fsync` durability here).
 * Does not authorize auto-publish or GUI reopen.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxOfflineReconnectLiveIntegrationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { b -> "%02x".format(b) }

    private fun requireLive(): Triple<String, String, String> {
        val url = System.getenv("KEYSAFE_INTEGRATION_URL")
        assumeTrue("KEYSAFE_INTEGRATION_URL required", !url.isNullOrBlank())
        val token = System.getenv("KEYSAFE_INTEGRATION_TOKEN")
            ?: System.getenv("KDBX_COORDINATOR_TOKEN")
        assumeTrue("integration token ≥32 chars", !token.isNullOrBlank() && token.length >= 32)
        val dbId = System.getenv("KEYSAFE_INTEGRATION_DB_ID")
            ?: "offline_reconnect_${System.currentTimeMillis()}"
        return Triple(url!!, token!!, dbId)
    }

    private fun client(url: String, dbId: String, token: String, owner: String) =
        KdbxCoordinatorClient(
            url,
            dbId,
            token,
            owner,
            allowInsecureLoopbackForTests = true,
        )

    private fun writePending(dir: File, identity: String, baseRevision: String, bytes: ByteArray): File {
        val prefix = "coordinated-kdbx-${sha256(identity.toByteArray())}-"
        return File(dir, "$prefix$baseRevision-pending.kdbx").also { it.writeBytes(bytes) }
    }

    private fun writeCache(dir: File, identity: String, bytes: ByteArray): File {
        val revision = sha256(bytes)
        val prefix = "coordinated-kdbx-cache-${sha256(identity.toByteArray())}-"
        return File(dir, "$prefix$revision.kdbx").also { it.writeBytes(bytes) }
    }

    @Test
    fun offlinePendingPublishesOnReconnectWhenBaseMatches() {
        val (url, token, dbId) = requireLive()
        val tip1 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("off-bin"),
            localPassword = "offline-base",
        )
        val tip2 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("off-bin-2"),
            localPassword = "offline-edited",
        )
        val base = sha256(tip1.ciphertext)
        val identity = "$url\u0000$dbId"
        val filesDir = tempFolder.newFolder("files")

        client(url, dbId, token, "offline-seed").use { seed ->
            seed.acquire()
            assertEquals(base, seed.publish(tip1.ciphertext).lowercase())
        }

        writeCache(filesDir, identity, tip1.ciphertext)
        writePending(filesDir, identity, base, tip2.ciphertext)
        val offline = OfflineKdbxCache.readOffline(filesDir, identity)
        assertTrue(offline != null)
        assertArrayEquals(tip2.ciphertext, offline!!.bytes)
        assertEquals(base, offline.baseRevision)

        client(url, dbId, token, "offline-reconnect").use { editor ->
            editor.acquire()
            val remote = editor.download()!!
            assertArrayEquals(tip1.ciphertext, remote)
            val pending = AtomicRecoveryStore.find(filesDir, identity)!!
            assertEquals(
                AtomicRecoveryStore.RecoveryAction.PUBLISH,
                AtomicRecoveryStore.decide(pending, sha256(remote)),
            )
            val saved = CoordinatorByteLimits.readBounded(
                pending.file.inputStream(),
                CoordinatorByteLimits.MAX_KDBX_BYTES,
                pending.file.length(),
            )
            val confirmed = editor.publish(saved)
            assertEquals(sha256(tip2.ciphertext), confirmed.lowercase())
            assertTrue(pending.file.delete())
        }

        assertNull(AtomicRecoveryStore.find(filesDir, identity))
        val tip = client(url, dbId, token, "offline-reader").downloadReadOnly()
        assertTrue(tip != null && tip.contentEquals(tip2.ciphertext))
    }

    @Test
    fun offlinePendingConflictsWhenRemoteAdvanced() {
        val (url, token, dbPrefix) = requireLive()
        val dbId = "${dbPrefix}_conflict"
        val tip1 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("c1"),
            localPassword = "conflict-base",
        )
        val localEdit = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("c2"),
            localPassword = "conflict-local",
        )
        val remoteEdit = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("c3"),
            localPassword = "conflict-remote",
        )
        val base = sha256(tip1.ciphertext)
        val identity = "$url\u0000$dbId"
        val filesDir = tempFolder.newFolder("files-conflict")

        client(url, dbId, token, "conflict-seed").use { seed ->
            seed.acquire()
            seed.publish(tip1.ciphertext)
        }
        writePending(filesDir, identity, base, localEdit.ciphertext)

        client(url, dbId, token, "conflict-peer").use { peer ->
            peer.acquire()
            peer.publish(remoteEdit.ciphertext)
        }

        client(url, dbId, token, "conflict-reconnect").use { editor ->
            editor.acquire()
            val remote = editor.download()!!
            assertArrayEquals(remoteEdit.ciphertext, remote)
            val pending = AtomicRecoveryStore.find(filesDir, identity)!!
            assertEquals(
                AtomicRecoveryStore.RecoveryAction.CONFLICT,
                AtomicRecoveryStore.decide(pending, sha256(remote)),
            )
            assertTrue(AtomicRecoveryStore.find(filesDir, identity) != null)
        }
        val tip = client(url, dbId, token, "conflict-reader").downloadReadOnly()
        assertTrue(tip != null && tip.contentEquals(remoteEdit.ciphertext))
    }

    @Test
    fun lostAckTreatsMatchingRemoteAsAlreadyPublished() {
        val (url, token, dbPrefix) = requireLive()
        val dbId = "${dbPrefix}_ack"
        val tip1 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("a1"),
            localPassword = "ack-base",
        )
        val tip2 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("a2"),
            localPassword = "ack-committed",
        )
        val base = sha256(tip1.ciphertext)
        val identity = "$url\u0000$dbId"
        val filesDir = tempFolder.newFolder("files-ack")

        client(url, dbId, token, "ack-writer").use { writer ->
            writer.acquire()
            writer.publish(tip1.ciphertext)
            writePending(filesDir, identity, base, tip2.ciphertext)
            writer.publish(tip2.ciphertext)
        }

        client(url, dbId, token, "ack-reconnect").use { editor ->
            editor.acquire()
            val remote = editor.download()!!
            assertArrayEquals(tip2.ciphertext, remote)
            val pending = AtomicRecoveryStore.find(filesDir, identity)!!
            assertEquals(
                AtomicRecoveryStore.RecoveryAction.ALREADY_PUBLISHED,
                AtomicRecoveryStore.decide(pending, sha256(remote)),
            )
            assertTrue(pending.file.delete())
        }
        assertNull(AtomicRecoveryStore.find(filesDir, identity))
    }
}
