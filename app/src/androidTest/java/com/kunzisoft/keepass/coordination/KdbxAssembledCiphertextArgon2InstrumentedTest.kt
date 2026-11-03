/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import android.content.Context
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
import java.util.UUID

/**
 * Native Argon2id assemble→write→strict-reload on device/emulator.
 * Not run by the default CI unit-test job; does not authorize auto-publish.
 */
class KdbxAssembledCiphertextArgon2InstrumentedTest {
    private val rootId = UUID.randomUUID()
    private val entryId = UUID.randomUUID()
    private val sharedSalt = ByteArray(32) { (it + 5).toByte() }
    private fun fixedTime() = DateInstant(Instant(1_700_000_200_000L))
    private fun fixNodeTimes(node: NodeKDBXInterface) {
        node.creationTime = fixedTime()
        node.lastModificationTime = fixedTime()
        node.lastAccessTime = fixedTime()
        node.locationChanged = fixedTime()
    }

    private fun copy(password: String): DatabaseKDBX {
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
        val entry = EntryKDBX().also {
            it.nodeId = NodeIdUUID(entryId)
            fixNodeTimes(it)
            it.title = "argon2-entry"
            it.password = password.toCharArray()
        }
        db.addEntryTo(entry, root)
        return db
    }

    @Test
    fun assembledLocalEditSurvivesStrictReloadUnderNativeArgon2id() {
        assumeTrue("libargon2 required", NativeLib.init())
        val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
        val cache = File(context.cacheDir, "kdbx-argon2-${UUID.randomUUID()}").also {
            check(it.mkdirs())
        }
        try {
            val base = copy("unchanged")
            val local = copy("argon2-secret")
            val remote = copy("unchanged")
            val report = KdbxThreeCopyReview.read(base, local, remote, unknownExtensionsRefused = true)
            assertFalse(report.mergeAuthorization.authorized)
            val assembled = KdbxConflictFreeSelectedAssembler.assemble(base, local, remote, report)
            val written = KdbxAssembledCiphertextWriter.writeAndStrictReload(
                assembled = assembled,
                masterCredential = MasterCredential("argon2-master".toCharArray()),
                binaryCacheDirectory = cache
            )
            assertTrue(written.ciphertext.isNotEmpty())
            assertTrue(
                written.reloaded.getEntryById(entryId)!!.password
                    .contentEquals("argon2-secret".toCharArray())
            )
            assertFalse(KdbxMergeAuthorizationGate.evaluate(report).authorized)
        } finally {
            cache.deleteRecursively()
        }
    }
}
