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
import java.io.File
import java.util.UUID

/**
 * Builds small AES-KDF KDBX ciphertexts for live coordinator tests.
 * Does not authorize merge publish; XC dual-client proofs remain open.
 */
internal object KdbxLiveRealCiphertextFixtures {
    val masterPassword = "live-protocol-master".toCharArray()
    private val sharedAesSeed = ByteArray(32) { (it + 3).toByte() }
    private fun fixedTime() = DateInstant(Instant(1_700_000_100_000L))
    private fun fixNodeTimes(node: NodeKDBXInterface) {
        node.creationTime = fixedTime()
        node.lastModificationTime = fixedTime()
        node.lastAccessTime = fixedTime()
        node.locationChanged = fixedTime()
    }

    data class Assembled(
        val entryId: UUID,
        val ciphertext: ByteArray,
        val entryPassword: String
    )

    fun assembledLocalEditCiphertext(binaryCacheDirectory: File): Assembled {
        val rootId = UUID.randomUUID()
        val entryId = UUID.randomUUID()
        fun copy(password: String): DatabaseKDBX {
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
            val entry = EntryKDBX().also {
                it.nodeId = NodeIdUUID(entryId)
                fixNodeTimes(it)
                it.title = "live-entry"
                it.password = password.toCharArray()
            }
            db.addEntryTo(entry, root)
            return db
        }
        val base = copy("unchanged")
        val local = copy("live-secret")
        val remote = copy("unchanged")
        val report = KdbxThreeCopyReview.read(base, local, remote, unknownExtensionsRefused = true)
        check(!report.mergeAuthorization.authorized)
        val assembled = KdbxConflictFreeSelectedAssembler.assemble(base, local, remote, report)
        val written = KdbxAssembledCiphertextWriter.writeAndStrictReload(
            assembled = assembled,
            masterCredential = MasterCredential(masterPassword.copyOf()),
            binaryCacheDirectory = binaryCacheDirectory
        )
        check(written.ciphertext.isNotEmpty())
        return Assembled(entryId, written.ciphertext, "live-secret")
    }
}
