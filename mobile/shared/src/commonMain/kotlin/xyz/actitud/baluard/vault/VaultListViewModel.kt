package xyz.actitud.baluard.vault

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.data.MobileFolderInfo
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.platform.platformLogE

/**
 * Drives the vault list (Phase 3). Holds ciphers as a [StateFlow] so Compose
 * recomposes on changes.
 *
 * Filtering: text search (name/username) + optional type chip + optional tag
 * chip + optional folder chip + favorites-only toggle. Archived entries never render. All filters
 * are client-side for Phase 3; the plan mentions Rust-side full-text search
 * for large vaults (>1000 entries) — that optimization lands when measured
 * perf demands it.
 */
class VaultListViewModel(private val repo: VaultRepository) {
    private val _ciphers = MutableStateFlow<List<MobileCipherMeta>>(emptyList())
    val ciphers: StateFlow<List<MobileCipherMeta>> = _ciphers.asStateFlow()

    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()

    /** Selected type chip (wire tag), or null. */
    val typeFilter = MutableStateFlow<String?>(null)

    /** Selected tag chip, or null. */
    val tagFilter = MutableStateFlow<String?>(null)

    /** Selected folder chip (folder id), or null. */
    val folderFilter = MutableStateFlow<String?>(null)

    private val _folders = MutableStateFlow<List<MobileFolderInfo>>(emptyList())
    private val _archived = MutableStateFlow<List<MobileCipherMeta>>(emptyList())
    private val _trash = MutableStateFlow<List<MobileCipherMeta>>(emptyList())
    private val _totp = MutableStateFlow<List<MobileCipherMeta>>(emptyList())

    /** Archived entries (Archive card). */
    val archived: StateFlow<List<MobileCipherMeta>> = _archived.asStateFlow()

    /** Trashed entries (Trash card). */
    val trash: StateFlow<List<MobileCipherMeta>> = _trash.asStateFlow()

    /** Entries with a TOTP seed (Authenticator card). */
    val totp: StateFlow<List<MobileCipherMeta>> = _totp.asStateFlow()
    val folders: StateFlow<List<MobileFolderInfo>> = _folders.asStateFlow()

    val favoritesOnly = MutableStateFlow(false)

    fun setQuery(q: String) { _query.value = q }

    fun setTypeFilter(tag: String?) { typeFilter.value = tag }
    fun setTagFilter(tag: String?) { tagFilter.value = tag }
    fun setFolderFilter(id: String?) { folderFilter.value = id }
    fun setFavoritesOnly(v: Boolean) { favoritesOnly.value = v }

    /** Reload the cipher index from the runtime. Call after unlock + after mutations. */
    suspend fun refresh(vault: MobileVault) {
        // A throw here used to kill the LaunchedEffect silently, leaving an
        // empty list with no signal (the empty-on-open bug report). Surface it.
        runCatching {
            val ciphers = repo.listCiphers(vault)
            platformLogE("VaultList", "refresh: ${ciphers.size} ciphers")
            _ciphers.value = ciphers
            _folders.value = runCatching { repo.listFolders(vault) }.getOrDefault(emptyList())
        }.onFailure {
            platformLogE("VaultList", "refresh failed", it)
        }
        // Hub card sets. Each is best-effort: a failure leaves the previous
        // (or empty) list instead of killing the caller.
        _totp.value = runCatching { repo.listTotp(vault) }.getOrDefault(emptyList())
        _archived.value = runCatching { repo.listArchived(vault) }.getOrDefault(emptyList())
        _trash.value = runCatching { repo.listTrash(vault) }.getOrDefault(emptyList())
    }

    /** The slice for an [kind] entry list (already reactive via the flows). */
    fun listFor(kind: EntryListKind): List<MobileCipherMeta> = when (kind) {
        EntryListKind.All -> _ciphers.value
        EntryListKind.Totp -> _totp.value
        EntryListKind.Favorites -> _ciphers.value.filter { it.favorite }
        is EntryListKind.Type -> _ciphers.value.filter { it.cipherType == kind.tag }
        is EntryListKind.Folder -> _ciphers.value.filter { it.folderId == kind.id }
        is EntryListKind.Tag -> _ciphers.value.filter { it.tags.contains(kind.tag) }
        EntryListKind.Archive -> _archived.value
        EntryListKind.Trash -> _trash.value
    }

    /** Reload just the TOTP slice. */
    suspend fun loadTotp(vault: MobileVault) {
        _totp.value = runCatching { repo.listTotp(vault) }.getOrDefault(emptyList())
    }

    /** Reload just the archived slice (after unarchive). */
    suspend fun loadArchived(vault: MobileVault) {
        _archived.value = runCatching { repo.listArchived(vault) }.getOrDefault(emptyList())
        _ciphers.value = runCatching { repo.listCiphers(vault) }.getOrDefault(emptyList())
    }

    /** Reload just the trash slice (after restore). */
    suspend fun loadTrash(vault: MobileVault) {
        _trash.value = runCatching { repo.listTrash(vault) }.getOrDefault(emptyList())
    }

    suspend fun unarchive(vault: MobileVault, id: String): Boolean {
        val ok = runCatching { repo.unarchiveCipher(vault, id) }.isSuccess
        loadArchived(vault)
        return ok
    }

    suspend fun restore(vault: MobileVault, id: String): Boolean {
        val ok = runCatching { repo.restoreCipher(vault, id) }.isSuccess
        loadTrash(vault)
        return ok
    }

    /** Distinct tags across visible (non-archived) entries, for the chip row. */
    fun allTags(ciphers: List<MobileCipherMeta>): List<String> =
        ciphers.filter { !it.archived }.flatMap { it.tags }.distinct().sorted()

    /** Distinct wire type tags across visible entries, for the chip row. */
    fun allTypes(ciphers: List<MobileCipherMeta>): List<String> =
        ciphers.filter { !it.archived }.map { it.cipherType }.distinct().sorted()

    /** Folders that hold at least one visible entry, for the chip row. */
    fun allFolders(
        ciphers: List<MobileCipherMeta>,
        folders: List<MobileFolderInfo> = _folders.value,
    ): List<MobileFolderInfo> {
        val used = ciphers.filter { !it.archived }.mapNotNull { it.folderId }.toSet()
        return folders.filter { it.id in used }.sortedBy { it.name }
    }

    /** Folder name lookup for the selected filter (ids are opaque). */
    fun folderName(
        id: String?,
        folders: List<MobileFolderInfo> = _folders.value,
    ): String? =
        folders.firstOrNull { it.id == id }?.name

    /** Apply the current filters to the given (collected) cipher list. */
    fun filtered(ciphers: List<MobileCipherMeta>): List<MobileCipherMeta> {
        val q = _query.value.trim()
        val type = typeFilter.value
        val tag = tagFilter.value
        val folder = folderFilter.value
        val favOnly = favoritesOnly.value
        return ciphers.filter { m ->
            !m.archived &&
                (type == null || m.cipherType == type) &&
                (tag == null || m.tags.contains(tag)) &&
                (folder == null || m.folderId == folder) &&
                (!favOnly || m.favorite) &&
                (q.isEmpty() || m.name.contains(q, ignoreCase = true) ||
                    (m.username?.contains(q, ignoreCase = true) ?: false))
        }
    }
}
