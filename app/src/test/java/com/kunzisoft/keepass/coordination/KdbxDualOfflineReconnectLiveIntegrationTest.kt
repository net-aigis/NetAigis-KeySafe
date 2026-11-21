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
 * Two independent offline edits against the same tip, then reconnect in either order.
 *
 * First reconnect with matching base PUBLISHes; second sees CONFLICT (remote advanced).
 * Does not authorize auto-publish or GUI merge.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxDualOfflineReconnectLiveIntegrationTest {
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
            ?: "dual_offline_${System.currentTimeMillis()}"
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

    @Test
    fun dualOfflineEdits_firstReconnectPublishes_secondConflicts() {
        val (url, token, dbPrefix) = requireLive()
        val dbId = "${dbPrefix}_either_order"
        val tip1 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("d0"),
            localPassword = "dual-base",
        )
        val editA = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("da"),
            localPassword = "dual-edit-a",
        )
        val editB = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("db"),
            localPassword = "dual-edit-b",
        )
        val base = sha256(tip1.ciphertext)
        val identity = "$url\u0000$dbId"
        val filesA = tempFolder.newFolder("files-a")
        val filesB = tempFolder.newFolder("files-b")

        client(url, dbId, token, "dual-seed").use { seed ->
            seed.acquire()
            assertEquals(base, seed.publish(tip1.ciphertext).lowercase())
        }

        writePending(filesA, identity, base, editA.ciphertext)
        writePending(filesB, identity, base, editB.ciphertext)

        // Reconnect A first → PUBLISH
        client(url, dbId, token, "dual-a").use { editorA ->
            editorA.acquire()
            val remote = editorA.download()!!
            assertArrayEquals(tip1.ciphertext, remote)
            val pending = AtomicRecoveryStore.find(filesA, identity)!!
            assertEquals(
                AtomicRecoveryStore.RecoveryAction.PUBLISH,
                AtomicRecoveryStore.decide(pending, sha256(remote)),
            )
            val saved = CoordinatorByteLimits.readBounded(
                pending.file.inputStream(),
                CoordinatorByteLimits.MAX_KDBX_BYTES,
                pending.file.length(),
            )
            val confirmed = editorA.publish(saved)
            assertEquals(sha256(editA.ciphertext), confirmed.lowercase())
            assertTrue(pending.file.delete())
        }
        assertNull(AtomicRecoveryStore.find(filesA, identity))

        // Reconnect B second → CONFLICT (remote advanced to A's tip)
        client(url, dbId, token, "dual-b").use { editorB ->
            editorB.acquire()
            val remote = editorB.download()!!
            assertArrayEquals(editA.ciphertext, remote)
            val pending = AtomicRecoveryStore.find(filesB, identity)!!
            assertEquals(
                AtomicRecoveryStore.RecoveryAction.CONFLICT,
                AtomicRecoveryStore.decide(pending, sha256(remote)),
            )
            assertTrue(AtomicRecoveryStore.find(filesB, identity) != null)
        }

        val tip = client(url, dbId, token, "dual-reader").downloadReadOnly()
        assertTrue(tip != null && tip.contentEquals(editA.ciphertext))
    }

    @Test
    fun dualOfflineEdits_reverseOrder_firstBThenAConflicts() {
        val (url, token, dbPrefix) = requireLive()
        val dbId = "${dbPrefix}_reverse"
        val tip1 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("r0"),
            localPassword = "dual-base-r",
        )
        val editA = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("ra"),
            localPassword = "dual-edit-a-r",
        )
        val editB = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("rb"),
            localPassword = "dual-edit-b-r",
        )
        val base = sha256(tip1.ciphertext)
        val identity = "$url\u0000$dbId"
        val filesA = tempFolder.newFolder("files-a-r")
        val filesB = tempFolder.newFolder("files-b-r")

        client(url, dbId, token, "dual-seed-r").use { seed ->
            seed.acquire()
            seed.publish(tip1.ciphertext)
        }
        writePending(filesA, identity, base, editA.ciphertext)
        writePending(filesB, identity, base, editB.ciphertext)

        client(url, dbId, token, "dual-b-first").use { editorB ->
            editorB.acquire()
            val remote = editorB.download()!!
            val pending = AtomicRecoveryStore.find(filesB, identity)!!
            assertEquals(
                AtomicRecoveryStore.RecoveryAction.PUBLISH,
                AtomicRecoveryStore.decide(pending, sha256(remote)),
            )
            editorB.publish(
                CoordinatorByteLimits.readBounded(
                    pending.file.inputStream(),
                    CoordinatorByteLimits.MAX_KDBX_BYTES,
                    pending.file.length(),
                ),
            )
            assertTrue(pending.file.delete())
        }

        client(url, dbId, token, "dual-a-second").use { editorA ->
            editorA.acquire()
            val remote = editorA.download()!!
            assertArrayEquals(editB.ciphertext, remote)
            val pending = AtomicRecoveryStore.find(filesA, identity)!!
            assertEquals(
                AtomicRecoveryStore.RecoveryAction.CONFLICT,
                AtomicRecoveryStore.decide(pending, sha256(remote)),
            )
        }
        val tip = client(url, dbId, token, "dual-reader-r").downloadReadOnly()
        assertTrue(tip != null && tip.contentEquals(editB.ciphertext))
    }
}
