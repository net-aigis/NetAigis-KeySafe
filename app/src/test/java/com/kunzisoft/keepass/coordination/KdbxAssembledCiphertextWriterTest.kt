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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

/**
 * AES-KDF ciphertext round-trip on the JVM (Robolectric). This does **not**
 * clear the native Argon2 / dual-client gate blockers.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxAssembledCiphertextWriterTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    private val rootId = UUID.randomUUID()
    private val entryId = UUID.randomUUID()
    private val sharedAesSeed = ByteArray(32) { (it + 1).toByte() }
    private fun fixedTime() = DateInstant(Instant(1_700_000_000_000L))
    private fun fixNodeTimes(node: NodeKDBXInterface) {
        node.creationTime = fixedTime()
        node.lastModificationTime = fixedTime()
        node.lastAccessTime = fixedTime()
        node.locationChanged = fixedTime()
    }

    private fun copy(password: String = "unchanged"): DatabaseKDBX {
        val db = DatabaseKDBX()
        // Isolate KDF from the shared factory default and keep rounds cheap.
        // Apply after header timestamps so setKeyRounds cannot bump settingsChanged.
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
        val entry = EntryKDBX().also {
            it.nodeId = NodeIdUUID(entryId)
            fixNodeTimes(it)
            it.title = "entry"
            it.password = password.toCharArray()
        }
        db.addEntryTo(entry, root)
        return db
    }

    @Test
    fun `assembled local edit survives strict ciphertext reload under AES-KDF`() {
        val base = copy()
        val local = copy("secret-new")
        val remote = copy()
        val report = KdbxThreeCopyReview.read(base, local, remote, unknownExtensionsRefused = true)
        assertFalse(report.mergeAuthorization.authorized)
        val assembled = KdbxConflictFreeSelectedAssembler.assemble(base, local, remote, report)

        val written = KdbxAssembledCiphertextWriter.writeAndStrictReload(
            assembled = assembled,
            masterCredential = MasterCredential("master-pass".toCharArray()),
            binaryCacheDirectory = tempFolder.newFolder("binaries")
        )
        assertTrue(written.ciphertext.isNotEmpty())
        assertTrue(
            written.reloaded.getEntryById(entryId)!!.password.contentEquals("secret-new".toCharArray())
        )
        assertFalse(report.mergeAuthorization.authorized)
        assertFalse(KdbxMergeAuthorizationGate.evaluate(report).authorized)
    }
}
