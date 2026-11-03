/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.DeletedObject
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import java.util.UUID

/**
 * In-memory assembly of a conflict-free selected KDBX model (phase 3B).
 *
 * Applies [KdbxThreeCopyReview] LOCAL/REMOTE/IDENTICAL/UNCHANGED decisions to
 * clone groups, entries and tombstones. Does **not** authorize merge, serialize
 * ciphertext, revalidate a lease or publish. Database-wide metadata must be
 * entirely [KdbxDatabaseMetadataReview.Source.UNCHANGED] in this slice.
 */
internal object KdbxConflictFreeSelectedAssembler {
    fun assemble(
        base: DatabaseKDBX,
        local: DatabaseKDBX,
        remote: DatabaseKDBX,
        report: KdbxThreeCopyReview.Report
    ): DatabaseKDBX {
        require(report.unknownExtensionsRefused) {
            "Selected assembly requires refuseUnknownExtensions attestation"
        }
        require(report.conflictIds.isEmpty()) {
            "Cannot assemble a selected model while record conflicts remain"
        }
        require(report.metadata.conflictKeys.isEmpty()) {
            "Cannot assemble a selected model while metadata conflicts remain"
        }
        require(report.appendOrder == null) {
            "Append-order previews are analysis-only and do not authorize assembly"
        }
        val changedMetadata = report.metadata.decisions
            .filter { it.source != KdbxDatabaseMetadataReview.Source.UNCHANGED }
            .map { "${it.key}:${it.source}" }
        require(changedMetadata.isEmpty()) {
            "This assembler slice requires unchanged database-wide metadata; changed=$changedMetadata"
        }
        require(!report.mergeAuthorization.authorized) {
            "Assembly must not run under an authorized merge decision yet"
        }

        val rootId = requireNotNull(base.rootGroup?.nodeId?.id) { "Base root group missing" }
        require(local.rootGroup?.nodeId?.id == rootId && remote.rootGroup?.nodeId?.id == rootId) {
            "Root group UUID differs between copies"
        }

        fun side(source: KdbxThreeCopyReview.Source): DatabaseKDBX =
            if (source == KdbxThreeCopyReview.Source.REMOTE) remote else local

        val out = DatabaseKDBX()
        copyUnchangedHeader(out, base)

        val rootDecision = report.decisions.firstOrNull { it.id == rootId.toString() }
            ?: throw IllegalArgumentException("Root group missing from three-copy decisions")
        val rootSource = side(rootDecision.source).rootGroup
            ?: throw IllegalArgumentException("Winning side is missing the root group")
        val assembledRoot = GroupKDBX().also { it.updateWith(rootSource, updateParents = false) }
        out.rootGroup = assembledRoot

        val pendingGroups = LinkedHashMap<UUID, GroupKDBX>()
        val pendingEntries = LinkedHashMap<UUID, EntryKDBX>()
        val tombstones = ArrayList<DeletedObject>()

        for (decision in report.decisions) {
            if (decision.id == rootId.toString()) continue
            val id = UUID.fromString(decision.id)
            val winning = side(decision.source)
            val group = winning.getGroupById(id)
            val entry = winning.getEntryById(id)
            val deleted = winning.deletedObjects.firstOrNull { it.uuid == id }
            when {
                group != null && entry == null && deleted == null -> pendingGroups[id] = group
                entry != null && group == null && deleted == null -> pendingEntries[id] = entry
                deleted != null && group == null && entry == null ->
                    tombstones.add(DeletedObject(deleted.uuid, deleted.deletionTime))
                else -> throw IllegalArgumentException(
                    "Winning side has an ambiguous or missing state for UUID $id " +
                        "(group=${group != null}, entry=${entry != null}, deleted=${deleted != null})"
                )
            }
        }

        while (pendingGroups.isNotEmpty()) {
            val ready = pendingGroups.filter { (_, group) ->
                val parentId = group.parent?.nodeId?.id
                parentId != null && (parentId == rootId || out.getGroupById(parentId) != null)
            }
            require(ready.isNotEmpty()) {
                "Selected groups form a cycle or reference a missing parent"
            }
            for ((id, group) in ready) {
                val parentId = group.parent!!.nodeId.id
                val parent = if (parentId == rootId) assembledRoot else out.getGroupById(parentId)!!
                val clone = GroupKDBX().also {
                    it.updateWith(group, updateParents = false)
                    it.indexInParent = group.indexInParent
                }
                out.addGroupTo(clone, parent)
                pendingGroups.remove(id)
            }
        }

        for ((_, entry) in pendingEntries) {
            val parentId = entry.parent?.nodeId?.id
                ?: throw IllegalArgumentException("Selected entry ${entry.nodeId.id} has no parent")
            val parent = if (parentId == rootId) {
                assembledRoot
            } else {
                out.getGroupById(parentId)
                    ?: throw IllegalArgumentException("Selected entry parent $parentId is missing")
            }
            val clone = EntryKDBX().also {
                it.updateWith(entry, copyHistory = true, updateParents = false)
                it.indexInParent = entry.indexInParent
            }
            out.addEntryTo(clone, parent)
        }

        for (tombstone in tombstones) {
            out.addDeletedObject(tombstone)
        }

        // Structural integrity only — never a publish grant.
        KdbxModelSnapshotReader.read(out)
        return out
    }

    /**
     * Metadata must be UNCHANGED across base/local/remote, so copying scalars
     * from [base] preserves the reviewed header without claiming a metadata merge.
     */
    private fun copyUnchangedHeader(dest: DatabaseKDBX, base: DatabaseKDBX) {
        dest.name = base.name
        dest.nameChanged = base.nameChanged
        dest.description = base.description
        dest.descriptionChanged = base.descriptionChanged
        dest.defaultUserName = base.defaultUserName
        dest.defaultUserNameChanged = base.defaultUserNameChanged
        dest.settingsChanged = base.settingsChanged
        dest.keyLastChanged = base.keyLastChanged
        dest.keyChangeRecDays = base.keyChangeRecDays
        dest.keyChangeForceDays = base.keyChangeForceDays
        dest.isKeyChangeForceOnce = base.isKeyChangeForceOnce
        dest.maintenanceHistoryDays = base.maintenanceHistoryDays
        dest.color = base.color
        dest.isRecycleBinEnabled = base.isRecycleBinEnabled
        dest.recycleBinUUID = base.recycleBinUUID
        dest.recycleBinChanged = base.recycleBinChanged
        dest.entryTemplatesGroup = base.entryTemplatesGroup
        dest.entryTemplatesGroupChanged = base.entryTemplatesGroupChanged
        dest.historyMaxItems = base.historyMaxItems
        dest.historyMaxSize = base.historyMaxSize
        dest.lastSelectedGroupUUID = base.lastSelectedGroupUUID
        dest.lastTopVisibleGroupUUID = base.lastTopVisibleGroupUUID
        dest.compressionAlgorithm = base.compressionAlgorithm
        dest.encryptionAlgorithm = base.encryptionAlgorithm
        dest.memoryProtection = base.memoryProtection
    }
}
