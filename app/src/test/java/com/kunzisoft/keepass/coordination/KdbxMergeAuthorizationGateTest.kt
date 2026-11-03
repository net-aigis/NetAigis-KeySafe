/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.node.NodeKDBXInterface
import org.joda.time.Instant
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class KdbxMergeAuthorizationGateTest {
    private fun fixedTime() = DateInstant(Instant(1_700_000_000_000L))
    private fun fixNodeTimes(node: NodeKDBXInterface) {
        node.creationTime = fixedTime()
        node.lastModificationTime = fixedTime()
        node.lastAccessTime = fixedTime()
        node.locationChanged = fixedTime()
    }

    private fun db(): DatabaseKDBX {
        val rootId = UUID.randomUUID()
        val db = DatabaseKDBX()
        db.rootGroup = GroupKDBX().also { it.nodeId = NodeIdUUID(rootId); fixNodeTimes(it) }
        return db
    }

    @Test fun `standing blockers always deny merge authorization`() {
        val decision = KdbxMergeAuthorizationGate.evaluate()
        assertFalse(decision.authorized)
        assertTrue(decision.blockers.any { it.contains("refuseUnknownExtensions") })
        assertTrue(decision.blockers.any { it.contains("merge writer") })
    }

    @Test fun `conflict-free three-copy review remains unauthorized`() {
        val copy = db()
        val report = KdbxThreeCopyReview.read(copy, copy, copy)
        assertTrue(report.conflictIds.isEmpty())
        assertFalse(report.unknownExtensionsRefused)
        assertFalse(report.mergeAuthorization.authorized)
        assertTrue(report.mergeAuthorization.blockers.any { it.contains("refuseUnknownExtensions") })
    }

    @Test fun `attested unknown-extension refusal still denies without writer and lease`() {
        val copy = db()
        val report = KdbxThreeCopyReview.read(
            copy, copy, copy,
            unknownExtensionsRefused = KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS
        )
        assertTrue(report.unknownExtensionsRefused)
        assertFalse(report.mergeAuthorization.authorized)
        assertFalse(report.mergeAuthorization.blockers.any { it.contains("refuseUnknownExtensions") })
        assertTrue(report.mergeAuthorization.blockers.any { it.contains("merge writer") })
        assertTrue(report.mergeAuthorization.blockers.any { it.contains("lease") })
    }

    @Test fun `append-order preview does not clear the authorization gate`() {
        val rootId = UUID.randomUUID()
        val baseEntry = UUID.randomUUID()
        val localEntry = UUID.randomUUID()
        val remoteEntry = UUID.randomUUID()
        fun copyWith(extra: UUID?): DatabaseKDBX {
            val db = DatabaseKDBX()
            val root = GroupKDBX().also { it.nodeId = NodeIdUUID(rootId); fixNodeTimes(it) }
            db.rootGroup = root
            EntryKDBX().also {
                it.nodeId = NodeIdUUID(baseEntry)
                fixNodeTimes(it)
                it.parent = root
                it.title = "base"
                root.addChildEntry(it)
            }
            if (extra != null) {
                EntryKDBX().also {
                    it.nodeId = NodeIdUUID(extra)
                    fixNodeTimes(it)
                    it.parent = root
                    it.title = extra.toString()
                    root.addChildEntry(it)
                }
            }
            return db
        }
        val report = KdbxThreeCopyReview.read(
            copyWith(null),
            copyWith(localEntry),
            copyWith(remoteEntry),
            unknownExtensionsRefused = true
        )
        assertTrue(report.appendOrder != null)
        assertFalse(report.mergeAuthorization.authorized)
        assertTrue(report.mergeAuthorization.blockers.any { it.contains("append-order") })
    }
}
