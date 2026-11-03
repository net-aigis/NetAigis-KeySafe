/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Read-only ordering preview for independent, append-only KDBX entry additions.
 *
 * Each input is an already validated/decrypted inventory of ONE complete copy.
 * This cannot attest to the completeness of entry history, attachments, group
 * content, credential changes, tombstone semantics or database-wide metadata.
 * The output is an ordering SUGGESTION ONLY, never a merge/write permission.
 */
internal object KdbxConcurrentAppendOrderReview {
    enum class Side { LOCAL, REMOTE }

    data class Append(
        val entryId: String,
        val side: Side,
        val originalIndex: Int,
        val proposedIndex: Int
    )

    data class Group(
        val groupId: String,
        val preservedBaseChildren: List<String>,
        val appended: List<Append>
    )

    data class Report(val groups: List<Group>) {
        val simultaneousGroupIds: List<String>
            get() = groups.filter { group ->
                group.appended.any { it.side == Side.LOCAL } &&
                    group.appended.any { it.side == Side.REMOTE }
            }.map { it.groupId }
    }

    fun review(
        base: KdbxModelSnapshotReader.Inventory,
        local: KdbxModelSnapshotReader.Inventory,
        remote: KdbxModelSnapshotReader.Inventory
    ): Report {
        require(base.rootGroupId == local.rootGroupId &&
            base.rootGroupId == remote.rootGroupId) {
            "KDBX append review requires the same root group"
        }
        require(base.tombstones == local.tombstones && base.tombstones == remote.tombstones) {
            "KDBX DeletedObjects changed during append-only review"
        }
        // Checks attachment to the root, group ancestry, missing parent pointers,
        // negative positions and duplicate sibling positions in EACH source.
        for (copy in listOf(base, local, remote)) {
            require(copy.nodes.keys.intersect(copy.tombstones.keys).isEmpty()) {
                "KDBX live UUID overlaps DeletedObjects"
            }
            KdbxSelectedTopologyPreflight.validate(copy.rootGroupId, copy.nodes)
            require(copy.nodes.values.all { node ->
                node.id == copy.rootGroupId || node.indexInParent != null
            }) { "KDBX append review needs complete real sibling indices" }
        }

        val baseGroups = base.nodes.filterValues { it.kind == KdbxModelSnapshotReader.Kind.GROUP }.keys
        val baseIds = base.nodes.keys
        val baseMaxIndex = HashMap<String, Int>()
        for (node in base.nodes.values) {
            if (node.id == base.rootGroupId) continue
            val parent = requireNotNull(node.parentGroupId)
            val position = requireNotNull(node.indexInParent)
            baseMaxIndex[parent] = maxOf(baseMaxIndex[parent] ?: 0, position)
        }

        fun additions(copy: KdbxModelSnapshotReader.Inventory, side: Side): List<Triple<String, KdbxModelSnapshotReader.Node, Side>> {
            // No base entry, group or position may disappear, move or change kind.
            for ((id, original) in base.nodes) {
                val updated = requireNotNull(copy.nodes[id]) {
                    "KDBX append-only review encountered a removed base UUID: $id"
                }
                require(updated.kind == original.kind &&
                    updated.parentGroupId == original.parentGroupId &&
                    updated.indexInParent == original.indexInParent) {
                    "KDBX base node moved, reordered or changed kind: $id"
                }
            }
            return copy.nodes.values.filter { it.id !in baseIds }.map { node ->
                require(node.kind == KdbxModelSnapshotReader.Kind.ENTRY &&
                    node.parentGroupId in baseGroups) {
                    "KDBX append-only review cannot accept new groups or detached entries"
                }
                require(node.id !in base.tombstones) {
                    "KDBX append-only review detected deleted UUID reuse"
                }
                val index = requireNotNull(node.indexInParent)
                require(index > (baseMaxIndex[node.parentGroupId] ?: 0)) {
                    "KDBX new entry is not appended after the original siblings"
                }
                Triple(node.id, node, side)
            }
        }

        val left = additions(local, Side.LOCAL)
        val right = additions(remote, Side.REMOTE)
        val leftIds = left.map { it.first }.toSet()
        require(right.none { it.first in leftIds }) {
            "KDBX concurrent additions reuse an entry UUID across copies"
        }

        val grouped = (left + right).groupBy { requireNotNull(it.second.parentGroupId) }
        val groups = grouped.toSortedMap().map { (parent, candidates) ->
            val existing = base.nodes.values
                .filter { it.parentGroupId == parent }
                .sortedWith(compareBy({ it.indexInParent }, { it.id }))
                .map { it.id }
            // Comparable across clients: no LOCAL-first precedence. An index
            // collision is ordered by stable UUID without discarding either entry.
            val sorted = candidates.sortedWith(compareBy({ it.second.indexInParent }, { it.first }))
            var proposed = baseMaxIndex[parent] ?: 0
            val appended = sorted.map { (id, node, side) ->
                require(proposed < Int.MAX_VALUE) { "KDBX sibling index overflow" }
                proposed += 1
                Append(id, side, requireNotNull(node.indexInParent), proposed)
            }
            Group(parent, existing, appended)
        }
        return Report(groups)
    }
}
