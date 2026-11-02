# ADR 0036. Collection-Scoped Cipher Paths + Policy Enforcement (P5 remainder, S3-2)

> Status: Accepted (2026-09-23)

## Context

Collections need a way to place entries in git so that the on-disk path carries membership, the git host learns nothing about collection ids, and the sync policy can enforce who writes where. The work is slice S3-2 and was recorded as D33. The first policy-denied commit wedges every peer's pull permanently, so a commit that no peer would authorize must not exist locally.

## Decision

**Opaque directory.** A collection's cipher directory is a salted hash: `sha256(dir_salt || id)`, truncated to 16 bytes and hex-encoded. The `dir_salt` is minted at collection creation and stored on the collection file. The git host sees neither the collection id nor cross-vault links, and every device derives the same opaque directory.

**Path is membership.** The on-disk path is the collection membership. `cipher.set_collection` is a new token-gated route with a write-guarded state wrapper. It renames the entry's file between the personal flat path and `ciphers/<dir>/<uuid>.enc`, and refuses unknown collections and trash. Reads, updates, archive and unarchive, delete-to-trash, metadata scans, and the index rebuild all resolve through a shared probe (flat first, then collection directories). `list_cipher_ids` recurses one level into collection directories with UUID dedup, because a grantee can plant a same-UUID copy and the index must list it once.

**Enforcement.** The policy walker builds a `CollectionScope` from the verified commit's own tree: the directory to id map, plus the collection ids on which the signer's member holds write grants. A non-admin cannot forge a definition, because `meta/collections/**` is Admin-only, so a referenced directory must be one an admin already defined in that tree. `authorize_scoped` denies any `ciphers/<dir>/**` path whose directory is unknown or ungranted, before the static table. The static table's `ciphers/**` Editor row still gates the role floor, so a Viewer with a grant still cannot write. Legacy vaults carry an empty scope and deny any unexpected 3-segment cipher path.

**Local gate mirrors the policy (review F1, blocker).** `assign_cipher_to_collection` requires the session device's member to hold write scope on both the source and target collection. Owner and Admin bypass, and legacy vaults bypass.

**Other accepted review findings (first rotation; 5 accepted, 2 declined)**

- `CollectionScope` owns its Vecs and no longer leaks `'static` slices per verified commit (F2).
- Grant-less directory duplicates are deduped in `list_cipher_ids` (F4).
- A non-grantee refusal test was added (F6).
- `load_dir_map` applies the same filename-stem pin as `list_collections` (F7).

## Consequences

Scope is per commit tree. Grant revocation converges only when the revocation commit is in the signer's ancestry. Sticky grant revocation (F3) was declined. The walker reads grants from the commit's own tree, so a stale clone can replay a since-revoked grant until its parent ancestry includes the revocation commit. This matches the plan's accepted boundary that revocation is only eventual. Sticky enforcement exists only for member removal, where removal must fail closed. A lib.rs indentation finding was also declined because fmt was already green.

Restore lands at the personal flat path, and membership is re-assigned explicitly. Canary ciphers stay flat. Attachments stay under `entries/`. The `staged path sets` item (the other P5 remainder) is deferred. There is no UI for assignment yet (§4.8 wave). Expiry that rotates will need grant rows re-checked at verification time.

## References

- `docs/adr/0085-sharing.md`, P5 row and the §4.4 `ciphers/<collection_id>/**` row
