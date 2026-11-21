/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import android.content.Context
import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import com.kunzisoft.encrypt.NativeLib
import com.kunzisoft.keepass.database.crypto.kdf.Argon2Kdf
import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.MasterCredential
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.node.NodeKDBXInterface
import org.joda.time.Instant
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/**
 * Native Argon2id conflict-free dual-entry assemble→write→strict-reload on
 * device/emulator. Optional live publish when KEYSAFE_INTEGRATION_* is set
 * (adb reverse to host coordinator). Does not authorize auto-publish.
 */
class KdbxLosslessMergeArgon2InstrumentedTest {
    private val sharedSalt = ByteArray(32) { (it + 9).toByte() }
    private fun fixedTime() = DateInstant(Instant(1_700_000_300_000L))
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

    private fun buildDb(
        rootId: UUID,
        entryAId: UUID,
        entryBId: UUID,
        passwordA: String,
        passwordB: String,
    ): DatabaseKDBX {
        val db = DatabaseKDBX()
        val engine = Argon2Kdf(Argon2Kdf.Type.ARGON2_ID)
        engine.parameters = engine.defaultParameters
        engine.parameters.setByteArray("S", sharedSalt.copyOf())
        engine.setKeyRounds(2uL)
        engine.setMemoryUsage(8uL * 1024u * 1024u)
        engine.setParallelism(1)
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
        db.addEntryTo(
            EntryKDBX().also {
                it.nodeId = NodeIdUUID(entryAId)
                fixNodeTimes(it)
                it.title = "ArgonMergeA"
                it.password = passwordA.toCharArray()
            },
            root,
        )
        db.addEntryTo(
            EntryKDBX().also {
                it.nodeId = NodeIdUUID(entryBId)
                fixNodeTimes(it)
                it.title = "ArgonMergeB"
                it.password = passwordB.toCharArray()
            },
            root,
        )
        return db
    }

    @Test
    fun conflictFreeDualEntryMergeSurvivesNativeArgon2idStrictReload() {
        assumeTrue("libargon2 required", NativeLib.init())
        val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
        val cache = File(context.cacheDir, "kdbx-argon2-merge-${UUID.randomUUID()}").also {
            check(it.mkdirs())
        }
        try {
            val rootId = UUID.randomUUID()
            val entryAId = UUID.randomUUID()
            val entryBId = UUID.randomUUID()
            val base = buildDb(rootId, entryAId, entryBId, "base-a", "base-b")
            val local = buildDb(rootId, entryAId, entryBId, "argon-local-a", "base-b")
            val remote = buildDb(rootId, entryAId, entryBId, "base-a", "argon-remote-b")
            val report = KdbxThreeCopyReview.read(base, local, remote, unknownExtensionsRefused = true)
            assertTrue(report.conflictIds.isEmpty())
            assertTrue(report.mergeAuthorization.authorized)

            val assembled = KdbxConflictFreeSelectedAssembler.assemble(base, local, remote, report)
            val written = KdbxAssembledCiphertextWriter.writeAndStrictReload(
                assembled = assembled,
                masterCredential = MasterCredential("argon2-merge-master".toCharArray()),
                binaryCacheDirectory = cache,
            )
            assertTrue(
                written.reloaded.getEntryById(entryAId)!!.password
                    .contentEquals("argon-local-a".toCharArray()),
            )
            assertTrue(
                written.reloaded.getEntryById(entryBId)!!.password
                    .contentEquals("argon-remote-b".toCharArray()),
            )

            // Always export tip where adb can pull it for KeePassXC-cli reopen.
            val exportDir = context.getExternalFilesDir(null) ?: cache
            val tipFile = File(exportDir, "argon2-merge-tip.kdbx")
            tipFile.writeBytes(written.ciphertext)
            File(exportDir, "argon2-merge-tip.kdbx.sha256").writeText(sha256(written.ciphertext))

            val args: Bundle = InstrumentationRegistry.getArguments()
            fun argOrEnv(key: String, env: String): String? =
                args.getString(key)?.takeIf { it.isNotBlank() }
                    ?: System.getenv(env)?.takeIf { it.isNotBlank() }

            val url = argOrEnv("keysafe_url", "KEYSAFE_INTEGRATION_URL")
            val token = argOrEnv("keysafe_token", "KEYSAFE_INTEGRATION_TOKEN")
                ?: argOrEnv("keysafe_token", "KDBX_COORDINATOR_TOKEN")
            val dbId = argOrEnv("keysafe_db_id", "KEYSAFE_INTEGRATION_DB_ID")
                ?: "argon2_merge_${System.currentTimeMillis()}"
            if (!url.isNullOrBlank() && !token.isNullOrBlank() && token.length >= 32) {
                KdbxCoordinatorClient(
                    url,
                    dbId,
                    token,
                    "argon2-merge-device",
                    allowInsecureLoopbackForTests = true,
                ).use { client ->
                    client.acquire()
                    val confirmed = client.publish(written.ciphertext)
                    assertTrue(confirmed.equals(sha256(written.ciphertext), ignoreCase = true))
                }
                val tip = KdbxCoordinatorClient(
                    url,
                    dbId,
                    token,
                    "argon2-merge-reader",
                    allowInsecureLoopbackForTests = true,
                ).downloadReadOnly()
                assertTrue(tip != null && tip.contentEquals(written.ciphertext))
                val reopened = KdbxCoordinationStrictLoad.openEncrypted(
                    encryptedKdbx = tip!!,
                    masterCredential = MasterCredential("argon2-merge-master".toCharArray()),
                    binaryCacheDirectory = File(cache, "reopen").also { check(it.mkdirs()) },
                )
                assertTrue(
                    reopened.database.getEntryById(entryAId)!!.password
                        .contentEquals("argon-local-a".toCharArray()),
                )
                assertTrue(
                    reopened.database.getEntryById(entryBId)!!.password
                        .contentEquals("argon-remote-b".toCharArray()),
                )
            }

            assertTrue(KdbxMergeAuthorizationGate.evaluate(report).authorized)
        } finally {
            cache.deleteRecursively()
        }
    }
}
