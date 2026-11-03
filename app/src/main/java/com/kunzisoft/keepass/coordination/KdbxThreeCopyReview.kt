/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import java.security.SecureRandom

/**
 * Read-only assessment of three decrypted KDBX copies. This is NOT a merge plan,
 * cannot grant write access, and intentionally does not return any record HMACs.
 * The caller must hold each model stable for the whole comparison.
 *
 * This reports selected database-wide metadata and custom-icon changes.
 * Callers must load each copy with [KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS]
 * and pass [unknownExtensionsRefused]=true; otherwise merge authorization stays
 * denied. Binary-pool reconstruction, credential handling and revision/lease
 * safety remain mandatory before any later write or upload.
 *
 * When independent offline appends collide only on sibling membership/order,
 * [Report.appendOrder] may carry a deterministic ordering preview. That preview
 * never clears conflict classifications and never authorizes save or publish.
 */
internal object KdbxThreeCopyReview {
    enum class Source { UNCHANGED, LOCAL, REMOTE, IDENTICAL, CONFLICT }

    data class Decision(val id: String, val source: Source)
    data class Report(
        val decisions: List<Decision>,
        val metadata: KdbxDatabaseMetadataReview.Report,
        /**
         * Present only when every record conflict is a parent-group membership
         * change explained by append-only additions with unchanged group shells.
         * Still not merge/write permission.
         */
        val appendOrder: KdbxConcurrentAppendOrderReview.Report? = null,
        /**
         * True only when the caller attests that base/local/remote were each
         * loaded with [KdbxCoordinationLoadPolicy.REFUSE_UNKNOWN_EXTENSIONS].
         * Synthetic in-memory inventories used by unit tests may set this when
         * they never passed through the permissive XML/inner-header parser.
         */
        val unknownExtensionsRefused: Boolean = false,
        /**
         * Always unauthorized while standing integrity blockers remain.
         * Callers must not treat a conflict-free [decisions] list as publishable.
         */
        val mergeAuthorization: KdbxMergeAuthorizationGate.Decision =
            KdbxMergeAuthorizationGate.evaluate(null)
    ) {
        val conflictIds: List<String> get() = decisions.filter { it.source == Source.CONFLICT }.map { it.id }
    }

    /**
     * Generates the ephemeral key internally, uses it for *all three* copies,
     * and zeroes it even if inventory creation or comparison fails.
     *
     * @param unknownExtensionsRefused attest that each copy was loaded with
     *   refuseUnknownExtensions (or is a synthetic model that never used the
     *   permissive parser). Defaults to false and keeps merge unauthorized.
     */
    fun read(
        base: DatabaseKDBX,
        local: DatabaseKDBX,
        remote: DatabaseKDBX,
        unknownExtensionsRefused: Boolean = false
    ): Report {
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        try {
            return compare(
                KdbxRecordContentFingerprints.read(base, key),
                KdbxRecordContentFingerprints.read(local, key),
                KdbxRecordContentFingerprints.read(remote, key),
                KdbxDatabaseMetadataReview.compare(base, local, remote, key),
                unknownExtensionsRefused
            )
        } finally {
            key.fill(0)
        }
    }

    /** Comparison of inventories created under one ephemeral key; never export them. */
    private fun compare(
        base: KdbxRecordContentFingerprints.Inventory,
        local: KdbxRecordContentFingerprints.Inventory,
        remote: KdbxRecordContentFingerprints.Inventory,
        metadata: KdbxDatabaseMetadataReview.Report,
        unknownExtensionsRefused: Boolean
    ): Report {
        val all = listOf(base, local, remote)
        val root = base.model.rootGroupId
        require(root.isNotBlank() && all.all { it.model.rootGroupId == root }) {
            "KDBX root differs between three copies"
        }
        val macPattern = Regex("[0-9a-f]{64}")
        for (inventory in all) {
            val nodes = inventory.model.nodes
            val tombstones = inventory.model.tombstones
            require(nodes.keys == inventory.nodeHmacSha256.keys &&
                tombstones.keys == inventory.tombstoneHmacSha256.keys) {
                "Incomplete KDBX three-copy inventory"
            }
            val groupIds = nodes.filterValues { it.kind == KdbxModelSnapshotReader.Kind.GROUP }.keys
            require(inventory.groupShellHmacSha256.keys == groupIds) {
                "Incomplete KDBX group shell inventory"
            }
            require(nodes[root]?.kind == KdbxModelSnapshotReader.Kind.GROUP &&
                nodes[root]?.parentGroupId == null && root !in tombstones) {
                "KDBX root is missing, modified in type or marked deleted"
            }
            require(nodes.keys.intersect(tombstones.keys).isEmpty()) {
                "KDBX UUID occurs as both live node and DeletedObject"
            }
            require(inventory.nodeHmacSha256.values.all(macPattern::matches) &&
                inventory.groupShellHmacSha256.values.all(macPattern::matches) &&
                inventory.tombstoneHmacSha256.values.all(macPattern::matches)) {
                "Malformed KDBX record fingerprint"
            }
        }

        val ids = all.flatMap { it.model.nodes.keys + it.model.tombstones.keys }.toSortedSet()
        val decisions = ArrayList<Decision>(ids.size)
        val selectedNodes = LinkedHashMap<String, KdbxModelSnapshotReader.Node>()
        var hasConflict = false
        for (id in ids) {
            val kinds = all.mapNotNull { it.model.nodes[id]?.kind }.distinct()
            require(kinds.size <= 1) { "KDBX UUID reused for another record kind: $id" }
            val b = state(base, id)
            val l = state(local, id)
            val r = state(remote, id)
            // A UUID already deleted in the common ancestor cannot silently
            // become a new live record with the same identity.
            require(b !is State.Deleted || (l !is State.Live && r !is State.Live)) {
                "KDBX previously deleted UUID reused as a live record: $id"
            }
            // A disappearing base record without an explicit DeletedObject is
            // not a verified deletion and may indicate truncated/corrupt input.
            if (b is State.Live) {
                require(l != null && r != null) {
                    "KDBX base record disappeared without a DeletedObject: $id"
                }
            }
            val source = when {
                l == r -> if (l == b) Source.UNCHANGED else Source.IDENTICAL
                l == b -> Source.REMOTE
                r == b -> Source.LOCAL
                else -> Source.CONFLICT
            }
            decisions.add(Decision(id, source))
            if (source == Source.CONFLICT) {
                hasConflict = true
            } else {
                // Keep the node metadata from the same inventory that produced
                // the HMAC-based decision, never reread mutable models here.
                val chosen = if (source == Source.REMOTE) remote else local
                chosen.model.nodes[id]?.let { selectedNodes[id] = it }
            }
        }
        // A conflict cannot be resolved by this review; therefore it has no
        // well-defined combined topology to validate. Preserve its decisions.
        if (!hasConflict) {
            KdbxSelectedTopologyPreflight.validate(root, selectedNodes)
        }
        val appendOrder = if (!hasConflict) null else appendOrderPreview(base, local, remote, decisions)
        val draft = Report(
            decisions = decisions,
            metadata = metadata,
            appendOrder = appendOrder,
            unknownExtensionsRefused = unknownExtensionsRefused
        )
        return draft.copy(mergeAuthorization = KdbxMergeAuthorizationGate.requireDenied(draft))
    }

    /**
     * Attach an ordering preview only when every CONFLICT is a parent group
     * whose shell metadata matches base on both sides and whose membership
     * change is explained by append-only new entries. Never mutates decisions.
     */
    private fun appendOrderPreview(
        base: KdbxRecordContentFingerprints.Inventory,
        local: KdbxRecordContentFingerprints.Inventory,
        remote: KdbxRecordContentFingerprints.Inventory,
        decisions: List<Decision>
    ): KdbxConcurrentAppendOrderReview.Report? {
        val conflicts = decisions.filter { it.source == Source.CONFLICT }
        if (conflicts.isEmpty()) return null
        for (decision in conflicts) {
            val kind = base.model.nodes[decision.id]?.kind
                ?: local.model.nodes[decision.id]?.kind
                ?: remote.model.nodes[decision.id]?.kind
            if (kind != KdbxModelSnapshotReader.Kind.GROUP) return null
            val shellBase = base.groupShellHmacSha256[decision.id] ?: return null
            val shellLocal = local.groupShellHmacSha256[decision.id] ?: return null
            val shellRemote = remote.groupShellHmacSha256[decision.id] ?: return null
            // Title/notes/flag edits must not be mistaken for append-only membership.
            if (shellLocal != shellBase || shellRemote != shellBase) return null
        }
        val preview = try {
            KdbxConcurrentAppendOrderReview.review(base.model, local.model, remote.model)
        } catch (_: IllegalArgumentException) {
            return null
        }
        val explained = preview.groups
            .filter { it.appended.isNotEmpty() }
            .map { it.groupId }
            .toSet()
        if (explained.isEmpty()) return null
        if (conflicts.map { it.id }.toSet() != explained) return null
        return preview
    }

    private sealed interface State {
        data class Live(val kind: KdbxModelSnapshotReader.Kind, val parent: String?, val hmac: String) : State
        data class Deleted(val hmac: String) : State
    }

    private fun state(inventory: KdbxRecordContentFingerprints.Inventory, id: String): State? {
        val node = inventory.model.nodes[id]
        if (node != null) return State.Live(node.kind, node.parentGroupId,
            inventory.nodeHmacSha256.getValue(id))
        val deleted = inventory.tombstoneHmacSha256[id]
        return if (deleted == null) null else State.Deleted(deleted)
    }
}
