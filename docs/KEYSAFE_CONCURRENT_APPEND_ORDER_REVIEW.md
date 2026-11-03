# NetAigis KeySafe – concurrent append-order preview (read-only)

`KdbxConcurrentAppendOrderReview.review(base, local, remote)` compares three
**already decrypted, stable** `KdbxModelSnapshotReader.Inventory` instances.
`KdbxThreeCopyReview` may attach this preview when group conflicts are
membership-only (unchanged group shell HMACs) and the append-only contract
holds. Group UUIDs stay classified as conflicted, because a full group
fingerprint still contains child membership and order as well as other
sensitive group metadata. Attachment is an analysis aid only.

This new helper is an **ordering-only preview**, not a merge algorithm. Its
narrow input contract is append-only entry additions below existing groups:

- The base root, all base UUIDs, node types, parent pointers and sibling
  positions must be unchanged in both branches. Every source is structurally
  validated using `KdbxSelectedTopologyPreflight`.
- DeletedObjects must be identical in all three copies, and no new live entry
  may reuse a deleted UUID. No new groups, entry movements, deletions or
  insertions between existing siblings are eligible.
- Each new entry must be under a base group, and its original sibling index
  must be greater than every base child's index in that group.
- The same new UUID appearing in both branches is **rejected**, even if the
  two records might be identical. Such equality needs actual record-content
  verification before it can be accepted.

The output lists preserved base child UUIDs followed by *both* sets of new
entry UUIDs. New entries are sorted by `(original index, UUID)` and assigned
new sequential sibling indices, starting after the maximum base index. Thus
an offline collision on the same append position never silently drops an
entry, and the result does not depend on whether a client calls one branch
`local` or `remote`. No entry values, passwords, binary data or record MACs
are returned. Integer index overflow fails closed.

**Important limitations:** This preview cannot establish whether affected
parent-group titles, notes, flags, permissions, timestamps, ordering intent,
attachments, history or other record metadata changed. It neither verifies
record-content HMACs nor resolves the conservative group fingerprint conflict.
It does not rebuild any KDBX group or attachment pool, change timestamps,
re-encrypt, serialize, acquire a lease, revalidate a remote revision, write or
upload data. Before any automatic merge, a separate validated model adapter,
metadata-aware merge rules, lossless writer and lease-protected atomic publish
are mandatory. Existing encrypted recovery copies remain untouched.
