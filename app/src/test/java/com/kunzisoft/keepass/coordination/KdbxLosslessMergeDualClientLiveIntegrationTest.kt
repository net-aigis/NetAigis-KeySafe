/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.crypto.kdf.AesKdf
import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.MasterCredential
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.node.NodeKDBXInterface
import org.joda.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
import java.util.UUID

/**
 * Conflict-free dual-entry assemble → ciphertext → coordinator tip → StrictLoad
 * reopen, with tip bytes written for KeePassXC-cli reopen (shell companion).
 *
 * Local edits entry A only; remote edits entry B only. Does **not** authorize
 * auto-publish; gate must still deny. Evidence for the lossless-writer /
 * dual-client-reopen slice under AES-KDF on the JVM.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxLosslessMergeDualClientLiveIntegrationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    private val sharedAesSeed = ByteArray(32) { (it + 7).toByte() }
    private fun fixedTime() = DateInstant(Instant(1_700_000_200_000L))
    private fun fixNodeTimes(node: NodeKDBXInterface) {
        node.creationTime = fixedTime()
        node.lastModificationTime = fixedTime()
        node.lastAccessTime = fixedTime()
        node.locationChanged = fixedTime()
    }

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
            ?: "lossless_merge_${System.currentTimeMillis()}"
        return Triple(url!!, token!!, dbId)
    }

    private fun buildDb(
        rootId: UUID,
        entryAId: UUID,
        entryBId: UUID,
        passwordA: String,
        passwordB: String,
    ): DatabaseKDBX {
        val db = DatabaseKDBX()
        val engine = AesKdf()
        engine.parameters = engine.defaultParameters
        engine.parameters.setByteArray(AesKdf.PARAM_SEED, sharedAesSeed.copyOf())
        engine.setKeyRounds(10uL)
        db.kdfEngine = engine
        db.nameChanged = fixedTime()
        db.descriptionChanged = fixedTime()
        db.defaultUserNameChanged = fixedTime()
        db.settingsChanged = fixedTime()
        db.keyLastChanged = fixedTime()
        db.recycleBinChanged = fixedTime()
        db.entryTemplatesGroupChanged = fixedTime()
        val root = GroupKDBX().also { it.nodeId = NodeIdUUID(rootId); fixNodeTimes(it) }
        db.rootGroup = root
        val entryA = EntryKDBX().also {
            it.nodeId = NodeIdUUID(entryAId)
            fixNodeTimes(it)
            it.title = "MergeEntryA"
            it.password = passwordA.toCharArray()
        }
        val entryB = EntryKDBX().also {
            it.nodeId = NodeIdUUID(entryBId)
            fixNodeTimes(it)
            it.title = "MergeEntryB"
            it.password = passwordB.toCharArray()
        }
        db.addEntryTo(entryA, root)
        db.addEntryTo(entryB, root)
        return db
    }

    @Test
    fun conflictFreeDualEntryMergePublishesAndStrictReloadsBothEntries() {
        val (url, token, dbId) = requireLive()
        val rootId = UUID.randomUUID()
        val entryAId = UUID.randomUUID()
        val entryBId = UUID.randomUUID()
        val master = MasterCredential(KdbxLiveRealCiphertextFixtures.masterPassword.copyOf())
        val bin = tempFolder.newFolder("merge-bin")

        val base = buildDb(rootId, entryAId, entryBId, "base-a", "base-b")
        val local = buildDb(rootId, entryAId, entryBId, "local-a-secret", "base-b")
        val remote = buildDb(rootId, entryAId, entryBId, "base-a", "remote-b-secret")

        val report = KdbxThreeCopyReview.read(base, local, remote, unknownExtensionsRefused = true)
        assertTrue(report.conflictIds.isEmpty())
        assertTrue(report.metadata.conflictKeys.isEmpty())
        assertTrue(report.mergeAuthorization.authorized)
        assertTrue(KdbxMergeAuthorizationGate.evaluate(report).authorized)

        val assembled = KdbxConflictFreeSelectedAssembler.assemble(base, local, remote, report)
        val written = KdbxAssembledCiphertextWriter.writeAndStrictReload(
            assembled = assembled,
            masterCredential = master,
            binaryCacheDirectory = bin,
        )
        assertTrue(
            written.reloaded.getEntryById(entryAId)!!.password.contentEquals("local-a-secret".toCharArray()),
        )
        assertTrue(
            written.reloaded.getEntryById(entryBId)!!.password.contentEquals("remote-b-secret".toCharArray()),
        )

        val tipHash = sha256(written.ciphertext)
        KdbxCoordinatorClient(
            url,
            dbId,
            token,
            "lossless-merge-writer",
            allowInsecureLoopbackForTests = true,
        ).use { client ->
            client.acquire()
            val confirmed = client.publish(written.ciphertext)
            assertEquals(tipHash, confirmed.lowercase())
        }

        val tip = KdbxCoordinatorClient(
            url,
            dbId,
            token,
            "lossless-merge-reader",
            allowInsecureLoopbackForTests = true,
        ).downloadReadOnly()
        assertTrue(tip != null && tip.contentEquals(written.ciphertext))

        val reopened = KdbxCoordinationStrictLoad.openEncrypted(
            encryptedKdbx = tip!!,
            masterCredential = master,
            binaryCacheDirectory = tempFolder.newFolder("merge-reopen"),
        )
        assertTrue(
            reopened.database.getEntryById(entryAId)!!.password.contentEquals("local-a-secret".toCharArray()),
        )
        assertTrue(
            reopened.database.getEntryById(entryBId)!!.password.contentEquals("remote-b-secret".toCharArray()),
        )

        // Tip file for KeePassXC-cli companion script (.local-lossless-merge-xc-reopen.sh).
        val tipOut = System.getenv("KEYSAFE_MERGE_TIP_OUT")
            ?: File(tempFolder.root, "lossless-merge-tip.kdbx").absolutePath
        File(tipOut).writeBytes(written.ciphertext)
        File("$tipOut.sha256").writeText(tipHash)

        assertTrue(KdbxMergeAuthorizationGate.evaluate(report).authorized)
    }
}
