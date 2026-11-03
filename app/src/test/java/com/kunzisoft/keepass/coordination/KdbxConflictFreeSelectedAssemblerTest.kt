/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.DeletedObject
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.node.NodeKDBXInterface
import org.joda.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID

class KdbxConflictFreeSelectedAssemblerTest {
    private val rootId = UUID.randomUUID()
    private val entryId = UUID.randomUUID()

    private fun fixedTime() = DateInstant(Instant(1_700_000_000_000L))
    private fun fixNodeTimes(node: NodeKDBXInterface) {
        node.creationTime = fixedTime()
        node.lastModificationTime = fixedTime()
        node.lastAccessTime = fixedTime()
        node.locationChanged = fixedTime()
    }

    private fun copy(password: String? = "unchanged"): DatabaseKDBX {
        val db = DatabaseKDBX()
        val root = GroupKDBX().also { it.nodeId = NodeIdUUID(rootId); fixNodeTimes(it) }
        db.rootGroup = root
        if (password != null) {
            EntryKDBX().also {
                it.nodeId = NodeIdUUID(entryId)
                fixNodeTimes(it)
                it.parent = root
                it.title = "entry"
                it.password = password.toCharArray()
                root.addChildEntry(it)
            }
        } else {
            db.deletedObjects.add(DeletedObject(entryId, fixedTime()))
        }
        return db
    }

    private fun review(base: DatabaseKDBX, local: DatabaseKDBX, remote: DatabaseKDBX) =
        KdbxThreeCopyReview.read(base, local, remote, unknownExtensionsRefused = true)

    @Test
    fun `local-only entry edit is assembled from local`() {
        val base = copy()
        val local = copy("secret-new")
        val remote = copy()
        val report = review(base, local, remote)
        assertEquals(KdbxThreeCopyReview.Source.LOCAL,
            report.decisions.single { it.id == entryId.toString() }.source)
        assertFalse(report.mergeAuthorization.authorized)

        val assembled = KdbxConflictFreeSelectedAssembler.assemble(base, local, remote, report)
        val entry = assembled.getEntryById(entryId)
        assertNotNull(entry)
        assertTrue(entry!!.password.contentEquals("secret-new".toCharArray()))
        assertFalse(report.mergeAuthorization.authorized)
    }

    @Test
    fun `remote-only entry edit is assembled from remote`() {
        val base = copy()
        val report = review(base, copy(), copy("remote-only"))
        val assembled = KdbxConflictFreeSelectedAssembler.assemble(
            base, copy(), copy("remote-only"), report
        )
        assertTrue(
            assembled.getEntryById(entryId)!!.password.contentEquals("remote-only".toCharArray())
        )
    }

    @Test
    fun `identical parallel edits keep either equivalent password`() {
        val base = copy()
        val report = review(base, copy("both"), copy("both"))
        val assembled = KdbxConflictFreeSelectedAssembler.assemble(
            base, copy("both"), copy("both"), report
        )
        assertTrue(assembled.getEntryById(entryId)!!.password.contentEquals("both".toCharArray()))
    }

    @Test
    fun `one-sided tombstone becomes DeletedObject without a live entry`() {
        val base = copy()
        val local = copy(null)
        val remote = copy()
        val report = review(base, local, remote)
        val assembled = KdbxConflictFreeSelectedAssembler.assemble(base, local, remote, report)
        assertNull(assembled.getEntryById(entryId))
        assertTrue(assembled.deletedObjects.any { it.uuid == entryId })
    }

    @Test
    fun `record conflict refuses assembly`() {
        val base = copy()
        val report = review(base, copy("local"), copy("remote"))
        try {
            KdbxConflictFreeSelectedAssembler.assemble(base, copy("local"), copy("remote"), report)
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // fail closed
        }
    }

    @Test
    fun `missing unknown-extension attestation refuses assembly`() {
        val base = copy()
        val report = KdbxThreeCopyReview.read(base, copy(), copy())
        assertFalse(report.unknownExtensionsRefused)
        try {
            KdbxConflictFreeSelectedAssembler.assemble(base, copy(), copy(), report)
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // fail closed
        }
    }
}
