package xyz.actitud.baluard.vault

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.data.MobileFolderInfo
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.platform.platformLogE

/**
 * Drives the vault hub + filtered entry lists. Holds the cipher slices as
 * [StateFlow]s so Compose recomposes on changes.
 *
 * Deep-search: matching inside entry content (notes, URIs, custom fields)
 * needs one decrypted read per entry, so the index is built LAZILY on the
 * first search (see [ensureContentIndex]) and invalidated on every data
 * reload. Never index during [refresh]: that decrypted every cipher on
 * every hub load and sync completion.
 */
class VaultListViewModel(private val repo: VaultRepository) {
    private val _ciphers = MutableStateFlow<List<MobileCipherMeta>>(emptyList())
    val ciphers: StateFlow<List<MobileCipherMeta>> = _ciphers.asStateFlow()

    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()

    private val _folders = MutableStateFlow<List<MobileFolderInfo>>(emptyList())
    private val _archived = MutableStateFlow<List<MobileCipherMeta>>(emptyList())
    private val _trash = MutableStateFlow<List<MobileCipherMeta>>(emptyList())
    private val _totp = MutableStateFlow<List<MobileCipherMeta>>(emptyList())

    /** Entries with a TOTP seed (Authenticator card). */
    val totp: StateFlow<List<MobileCipherMeta>> = _totp.asStateFlow()

    /** Archived entries (Archive card). */
    val archived: StateFlow<List<MobileCipherMeta>> = _archived.asStateFlow()

    /** Trashed entries (Trash card). */
    val trash: StateFlow<List<MobileCipherMeta>> = _trash.asStateFlow()

    val folders: StateFlow<List<MobileFolderInfo>> = _folders.asStateFlow()

    /** id -> lowercase haystack over decryptable content (notes, URIs, custom
     * fields) so search matches inside entries, not just their names. */
    private val contentIndex = mutableMapOf<String, String>()
    private var indexedVault: MobileVault? = null

    private val _indexVersion = MutableStateFlow(0)

    /** Bumps when the deep-search index rebuilds; screens collect it to re-run search. */
    val indexVersion: StateFlow<Int> = _indexVersion.asStateFlow()

    fun setQuery(q: String) { _query.value = q }

    /** Reload all slices from the runtime. Call after unlock + after mutations. */
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
        invalidateContentIndex()
    }

    /** The slice for an [kind] entry list (already reactive via the flows). */
    fun listFor(kind: EntryListKind): List<MobileCipherMeta> = when (kind) {
        EntryListKind.Totp -> _totp.value
        EntryListKind.Favorites -> _ciphers.value.filter { it.favorite }
        is EntryListKind.Type -> _ciphers.value.filter { it.cipherType == kind.tag }
        is EntryListKind.Folder -> _ciphers.value.filter { it.folderId == kind.id }
        is EntryListKind.Tag -> _ciphers.value.filter { it.tags.contains(kind.tag) }
        EntryListKind.Archive -> _archived.value
        EntryListKind.Trash -> _trash.value
    }

    /**
     * Build the deep-search index once per vault state. Screens call this
     * from a LaunchedEffect when the search query turns non-empty; the
     * [indexVersion] bump recomposes the results with content matches.
     */
    suspend fun ensureContentIndex(vault: MobileVault) {
        if (indexedVault === vault) return
        contentIndex.clear()
        indexSlice(vault, _ciphers.value)
        indexSlice(vault, _archived.value)
        indexSlice(vault, _trash.value)
        indexedVault = vault
        _indexVersion.value++
    }

    /** Drop the deep-search index (data changed underneath it). */
    private fun invalidateContentIndex() {
        contentIndex.clear()
        indexedVault = null
    }

    /** Reload just the TOTP slice. */
    suspend fun loadTotp(vault: MobileVault) {
        _totp.value = runCatching { repo.listTotp(vault) }.getOrDefault(emptyList())
        invalidateContentIndex()
    }

    /** Reload the archived slice + active list (after unarchive). */
    suspend fun loadArchived(vault: MobileVault) {
        _archived.value = runCatching { repo.listArchived(vault) }.getOrDefault(emptyList())
        _ciphers.value = runCatching { repo.listCiphers(vault) }.getOrDefault(emptyList())
        invalidateContentIndex()
    }

    /** Reload just the trash slice (after restore / purge). */
    suspend fun loadTrash(vault: MobileVault) {
        _trash.value = runCatching { repo.listTrash(vault) }.getOrDefault(emptyList())
        invalidateContentIndex()
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

    /** Permanently delete every trashed entry. Returns how many entries
     * could not be deleted (partial failure keeps them in the list). */
    suspend fun emptyTrash(vault: MobileVault): Int {
        var failed = 0
        for (meta in _trash.value) {
            if (runCatching { repo.deleteCipher(vault, meta.id) }.isFailure) {
                failed++
            }
        }
        loadTrash(vault)
        return failed
    }

    /** Index the decryptable content of each entry in the slice. */
    private suspend fun indexSlice(vault: MobileVault, metas: List<MobileCipherMeta>) {
        for (meta in metas) {
            runCatching { repo.getCipher(vault, meta.id, decrypt = true) }
                .getOrNull()
                ?.let { indexContent(meta.id, it) }
        }
    }

    private fun indexContent(id: String, raw: String) {
        val obj = runCatching { Json.parseToJsonElement(raw) as? JsonObject }.getOrNull() ?: return
        val data = (obj["kind"] as? JsonObject)?.get("data") as? JsonObject
        fun str(o: JsonObject?, key: String): String =
            (o?.get(key) as? JsonPrimitive)?.content ?: ""
        val parts = mutableListOf(str(obj, "name"), str(obj, "username"), str(obj, "notes"))
        if (data != null) {
            parts += str(data, "username")
            parts += str(data, "notes")
            for (uri in data["uris"] as? JsonArray ?: JsonArray(emptyList())) {
                if (uri is JsonObject) parts += str(uri, "uri")
            }
            for (field in data["custom_fields"] as? JsonArray ?: JsonArray(emptyList())) {
                if (field is JsonObject) {
                    parts += str(field, "name")
                    // Hidden values are secrets; they stay out of the index.
                    if ((field["field_type"] as? JsonPrimitive)?.content?.lowercase() != "hidden") {
                        parts += str(field, "value")
                    }
                }
            }
        }
        contentIndex[id] = parts.filter { it.isNotBlank() }.joinToString(" ").lowercase()
    }

    /** Name/username + deep-content match against the (lazily built) index. */
    fun filtered(ciphers: List<MobileCipherMeta>): List<MobileCipherMeta> {
        val q = _query.value.trim()
        if (q.isEmpty()) return ciphers
        return ciphers.filter { m ->
            m.name.contains(q, ignoreCase = true) ||
                (m.username?.contains(q, ignoreCase = true) ?: false) ||
                contentIndex[m.id]?.contains(q.lowercase()) == true
        }
    }

    /** Deep-search match for the entry-list screens' inline filter. */
    fun contentHit(id: String, query: String): Boolean =
        contentIndex[id]?.contains(query.trim().lowercase()) == true

    /** Drop one entry from the deep-search index (after permanent delete). */
    fun evictContent(id: String) {
        contentIndex.remove(id)
    }
}
