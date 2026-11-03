/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class KdbxConcurrentAppendOrderReviewTest {
    private fun group(id: String, parent: String? = "root", index: Int? = 1) =
        KdbxModelSnapshotReader.Node(id, KdbxModelSnapshotReader.Kind.GROUP, parent, indexInParent = index)
    private fun entry(id: String, parent: String = "root", index: Int = 1) =
        KdbxModelSnapshotReader.Node(id, KdbxModelSnapshotReader.Kind.ENTRY, parent, indexInParent = index)
    private val root = group("root", null, null)
    private fun inventory(vararg nodes: KdbxModelSnapshotReader.Node) =
        KdbxModelSnapshotReader.Inventory("root", (listOf(root) + nodes).associateBy { it.id }, emptyMap())
    private fun rejects(block: () -> Unit) {
        try { block(); fail("Unsafe append candidate was accepted") }
        catch (_: IllegalArgumentException) { /* expected */ }
    }

    @Test fun `same-position concurrent appends retain both new entries`() {
        val base = inventory(entry("old", index = 1))
        val local = inventory(entry("old", index = 1), entry("z", index = 2))
        val remote = inventory(entry("old", index = 1), entry("a", index = 2))
        val result = KdbxConcurrentAppendOrderReview.review(base, local, remote)
        assertEquals(listOf("root"), result.simultaneousGroupIds)
        val order = result.groups.single()
        assertEquals(listOf("old"), order.preservedBaseChildren)
        assertEquals(listOf("a", "z"), order.appended.map { it.entryId })
        assertEquals(listOf(2, 3), order.appended.map { it.proposedIndex })
        assertEquals(2, order.appended.map { it.side }.distinct().size)
    }

    @Test fun `switching source roles does not change final ordering`() {
        val b = inventory(entry("old", index = 1))
        val l = inventory(entry("old", index = 1), entry("z", index = 2))
        val r = inventory(entry("old", index = 1), entry("a", index = 2))
        val first = KdbxConcurrentAppendOrderReview.review(b, l, r).groups.single()
        val second = KdbxConcurrentAppendOrderReview.review(b, r, l).groups.single()
        assertEquals(first.appended.map { it.entryId to it.proposedIndex },
            second.appended.map { it.entryId to it.proposedIndex })
    }

    @Test fun `append candidate keeps existing group and entry positions`() {
        val b = inventory(group("folder", index = 1), entry("old", index = 3))
        val l = inventory(group("folder", index = 1), entry("old", index = 3), entry("new", index = 4))
        val result = KdbxConcurrentAppendOrderReview.review(b, l, b).groups.single()
        assertEquals(listOf("folder", "old"), result.preservedBaseChildren)
        assertEquals(4, result.appended.single().proposedIndex)
        assertTrue(KdbxConcurrentAppendOrderReview.review(b, l, b).simultaneousGroupIds.isEmpty())
    }

    @Test fun `independent additions to different parents stay separate`() {
        val b = inventory(group("g1", index = 1), group("g2", index = 2))
        val l = inventory(group("g1", index = 1), group("g2", index = 2), entry("l", "g1", 1))
        val r = inventory(group("g1", index = 1), group("g2", index = 2), entry("r", "g2", 1))
        val result = KdbxConcurrentAppendOrderReview.review(b, l, r)
        assertEquals(listOf("g1", "g2"), result.groups.map { it.groupId })
        assertTrue(result.simultaneousGroupIds.isEmpty())
    }

    @Test fun `new entry may not reuse a UUID from the other source`() {
        val b = inventory()
        rejects { KdbxConcurrentAppendOrderReview.review(b, inventory(entry("same")), inventory(entry("same"))) }
    }

    @Test fun `moving or reordering a base entry is not append only`() {
        val b = inventory(entry("old", index = 1))
        rejects { KdbxConcurrentAppendOrderReview.review(b, inventory(entry("old", index = 2)), b) }
    }

    @Test fun `base entry deletion is rejected`() {
        val b = inventory(entry("old", index = 1))
        rejects { KdbxConcurrentAppendOrderReview.review(b, inventory(), b) }
    }

    @Test fun `new groups are excluded from append-only plan`() {
        val b = inventory()
        rejects { KdbxConcurrentAppendOrderReview.review(b, inventory(group("fresh")), b) }
    }

    @Test fun `inserting before existing last index is rejected`() {
        val b = inventory(entry("old", index = 3))
        val l = inventory(entry("old", index = 3), entry("new", index = 2))
        rejects { KdbxConcurrentAppendOrderReview.review(b, l, b) }
    }

    @Test fun `duplicate positions inside one source are rejected`() {
        val b = inventory()
        rejects { KdbxConcurrentAppendOrderReview.review(b, inventory(entry("a", index = 1), entry("b", index = 1)), b) }
    }

    @Test fun `reused deleted UUID is rejected`() {
        val deleted = KdbxModelSnapshotReader.Tombstone("gone", 123L, "DATE")
        val b = inventory().copy(tombstones = mapOf("gone" to deleted))
        val l = inventory(entry("gone")).copy(tombstones = b.tombstones)
        rejects { KdbxConcurrentAppendOrderReview.review(b, l, b) }
    }

    @Test fun `changed tombstones are not ignored`() {
        val b = inventory()
        val l = inventory(entry("added")).copy(tombstones = mapOf("gone" to KdbxModelSnapshotReader.Tombstone("gone", 1, "DATE")))
        rejects { KdbxConcurrentAppendOrderReview.review(b, l, b) }
    }

    @Test fun `sibling index overflow fails closed`() {
        val b = inventory(entry("old", index = Int.MAX_VALUE))
        val l = inventory(entry("old", index = Int.MAX_VALUE), entry("new", index = Int.MAX_VALUE))
        rejects { KdbxConcurrentAppendOrderReview.review(b, l, b) }
    }

    @Test fun `missing index cannot silently pass as append`() {
        val b = inventory()
        val l = inventory(entry("new").copy(indexInParent = null))
        rejects { KdbxConcurrentAppendOrderReview.review(b, l, b) }
    }

    @Test fun `root mismatch is rejected`() {
        val b = inventory()
        val l = inventory(entry("new")).copy(rootGroupId = "other")
        rejects { KdbxConcurrentAppendOrderReview.review(b, l, b) }
    }

    @Test fun `without additions report is empty`() {
        val b = inventory(entry("old", index = 1))
        val result = KdbxConcurrentAppendOrderReview.review(b, b, b)
        assertTrue(result.groups.isEmpty())
        assertTrue(result.simultaneousGroupIds.isEmpty())
    }
}
