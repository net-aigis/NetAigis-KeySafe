/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
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
 * Crash-during-save recovery: pending ciphertext bound to tip base survives,
 * reopens under StrictLoad, then reconnect PUBLISH clears pending.
 *
 * Tip/pending files are also written for KeePassXC-cli companion reopen.
 * Does not authorize auto-publish or GUI click-through.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxCrashRecoveryReopenLiveIntegrationTest {
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
            ?: "crash_recovery_${System.currentTimeMillis()}"
        return Triple(url!!, token!!, dbId)
    }

    private fun writePending(dir: File, identity: String, baseRevision: String, bytes: ByteArray): File {
        val prefix = "coordinated-kdbx-${sha256(identity.toByteArray())}-"
        return File(dir, "$prefix$baseRevision-pending.kdbx").also { it.writeBytes(bytes) }
    }

    @Test
    fun crashLeavesPendingReopenableThenPublishOnReconnect() {
        val (url, token, dbId) = requireLive()
        val tip1 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("crash-base"),
            localPassword = "crash-base-secret",
        )
        val tip2 = KdbxLiveRealCiphertextFixtures.assembledLocalEditCiphertext(
            tempFolder.newFolder("crash-edit"),
            localPassword = "crash-edit-secret",
        )
        val base = sha256(tip1.ciphertext)
        val identity = "$url\u0000$dbId"
        val filesDir = tempFolder.newFolder("crash-files")
        val master = MasterCredential(KdbxLiveRealCiphertextFixtures.masterPassword.copyOf())

        KdbxCoordinatorClient(
            url, dbId, token, "crash-seed", allowInsecureLoopbackForTests = true,
        ).use { seed ->
            seed.acquire()
            assertEquals(base, seed.publish(tip1.ciphertext).lowercase())
        }

        // Simulate crash after local encrypt/retain, before publish ack.
        writePending(filesDir, identity, base, tip2.ciphertext)
        val pending = AtomicRecoveryStore.find(filesDir, identity)!!
        assertTrue(pending.file.isFile)

        val pendingOpened = KdbxCoordinationStrictLoad.openEncrypted(
            encryptedKdbx = pending.file.readBytes(),
            masterCredential = master,
            binaryCacheDirectory = tempFolder.newFolder("crash-pending-reopen"),
        )
        assertTrue(
            pendingOpened.database.rootGroup?.getChildEntries()
                ?.any { it.password.contentEquals("crash-edit-secret".toCharArray()) } == true,
        )

        val tipOut = System.getenv("KEYSAFE_CRASH_PENDING_OUT")
            ?: File(tempFolder.root, "crash-pending.kdbx").absolutePath
        File(tipOut).writeBytes(tip2.ciphertext)

        KdbxCoordinatorClient(
            url, dbId, token, "crash-reconnect", allowInsecureLoopbackForTests = true,
        ).use { editor ->
            editor.acquire()
            val remote = editor.download()!!
            assertArrayEquals(tip1.ciphertext, remote)
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

        val tip = KdbxCoordinatorClient(
            url, dbId, token, "crash-reader", allowInsecureLoopbackForTests = true,
        ).downloadReadOnly()
        assertTrue(tip != null && tip.contentEquals(tip2.ciphertext))

        val tipOpened = KdbxCoordinationStrictLoad.openEncrypted(
            encryptedKdbx = tip!!,
            masterCredential = master,
            binaryCacheDirectory = tempFolder.newFolder("crash-tip-reopen"),
        )
        assertTrue(
            tipOpened.database.rootGroup?.getChildEntries()
                ?.any { it.password.contentEquals("crash-edit-secret".toCharArray()) } == true,
        )

        val publishedOut = System.getenv("KEYSAFE_CRASH_TIP_OUT")
            ?: File(tempFolder.root, "crash-tip.kdbx").absolutePath
        File(publishedOut).writeBytes(tip)
    }
}
