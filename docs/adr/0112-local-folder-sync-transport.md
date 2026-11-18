# ADR 0112. Local Folder Sync Transport (Dropbox, Drive, iCloud Drive, Syncthing)

> Status: Proposed (2026-11-18).

## Context

Many users already pay for or run folder-sync services such as Dropbox, Google Drive, iCloud Drive, Nextcloud, or Syncthing, and do not want to create or configure a Git host account (GitHub, GitLab, Codeberg) or manage SSH/HTTPS credentials. ADR 0102 noted folder-based transport (Android SAF, Google Drive, iCloud) as a zero-server candidate for sync. Because a Baluard vault is already a Git repository with signed commits, enrollment proofs, and deterministic merge resolution in `crates/baluard-core/src/sync/`, sync does not require a hosted Git server if the shared folder acts as the bare Git remote.

## Decision

1. **Bare Git repo in the selected folder:** When the user picks a folder ("Select this folder" in desktop, mobile, or `--folder <path>` in CLI), Baluard initializes or opens a bare Git repository inside a dedicated subdirectory (for example `<chosen-folder>/baluard-vault.git` or `<chosen-folder>/<vault-slug>.git`) and configures it as the vault's Git remote.
2. **Same `commit -> pull -> push` invariant:** All sync cycles keep Baluard's existing `commit -> pull -> push` order, signed commits, enrollment proof verification, and force-checkout pull rules in `baluard-core`. No separate file format or CRDT is introduced.
3. **Desktop and CLI transport:** Desktop and CLI access the bare repository directly on the local filesystem via `git2`. File-sync clients (Dropbox, Drive, iCloud Drive, Syncthing) replicate the Git objects and refs between devices.
4. **Mobile platform bridge (Android SAF and iOS Security-Scoped Bookmarks):** On Android, the app cannot pass a raw filesystem path for an arbitrary user-picked folder (Storage Access Framework `content://` URI). The Kotlin layer mirrors or stages the bare repo delta between the SAF document tree and an app-private working bare mirror before calling `baluard-core` over `baluard-uniffi` (and commits/pushes back to SAF). On iOS, the app uses `NSFileCoordinator` and security-scoped URLs for iCloud Drive / Files folders.
5. **Cloud conflict-copy resilience:** Cloud folder syncers occasionally produce duplicate/conflicted files (for example `conflicted copy`) or race on packed refs. Keep loose refs where practical, detect non-object conflict artifacts during `sync` without failing the whole pull, and lock the local mirror during `pull -> push` so two devices writing simultaneously converge via Git merge on the next sync.
6. **Zero extra credentials:** Folder sync requires no Git provider token, SSH key, or `known_hosts` trust step. Enrollment and device revocation remain enforced cryptographically by Baluard's signed commit history inside the encrypted vault.

## Consequences

- Non-technical users can sync across devices using any folder-sync service they already have, with zero server setup.
- Existing `baluard-core` sync, conflict UI, and revocation logic work unchanged.
- Mobile requires a thin platform adapter (SAF on Android, `NSFileCoordinator` on iOS) around `baluard-uniffi` because `git2` expects POSIX paths.
- Folder sync remains optional and can coexist or be migrated to a Git remote via ADR 0047.
