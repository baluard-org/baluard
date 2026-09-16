package xyz.actitud.baluard.vault

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
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

    /** id -> lowercase haystack over decryptable content (every content field
     * of every cipher type) so search matches inside entries, not just their
     * names. Passwords and key material stay out ([SEARCH_SKIP_KEYS]). */
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
        // Rebuild while searching so content matches survive data changes.
        // Owned here (not by screen effects): Compose LaunchedEffects run
        // concurrently, so declaration order cannot guarantee refresh finishes
        // before a keyed effect short-circuits on the stale index.
        if (_query.value.isNotBlank()) ensureContentIndex(vault)
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

    /** Serializes deep-search builds so a refresh-triggered rebuild and a
     * screen-triggered one can never interleave and swap mixed data. */
    private val indexMutex = Mutex()

    /**
     * Build the deep-search index once per vault state. Screens call this
     * from a LaunchedEffect when the search query turns non-empty; refresh()
     * calls it directly after invalidating. Builds into a local map and
     * swaps atomically: readers never see a half-populated index.
     */
    suspend fun ensureContentIndex(vault: MobileVault) {
        indexMutex.withLock {
            if (indexedVault === vault) return
            val fresh = HashMap<String, String>()
            indexSliceInto(fresh, vault, _ciphers.value)
            indexSliceInto(fresh, vault, _archived.value)
            indexSliceInto(fresh, vault, _trash.value)
            contentIndex.clear()
            contentIndex.putAll(fresh)
            indexedVault = vault
            _indexVersion.value++
        }
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
        if (!ok) return false
        loadTrash(vault)
        // The restored entry must re-enter the active list, global search, and
        // the Authenticator card immediately, not at the next revision bump.
        _ciphers.value = runCatching { repo.listCiphers(vault) }.getOrDefault(_ciphers.value)
        _totp.value = runCatching { repo.listTotp(vault) }.getOrDefault(_totp.value)
        return true
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

    /** Index the decryptable content of each entry in the slice into [out]. */
    private suspend fun indexSliceInto(out: MutableMap<String, String>, vault: MobileVault, metas: List<MobileCipherMeta>) {
        for (meta in metas) {
            runCatching { repo.getCipher(vault, meta.id, decrypt = true) }
                .getOrNull()
                ?.let { out[meta.id] = buildSearchHaystack(it) }
        }
    }

    /** Trashed + archived ids: global search never surfaces them, even if a
     * stale active slice still holds one between a mutation and its refresh. */
    private fun hiddenIds(): Set<String> {
        val ids = HashSet<String>(_trash.value.size + _archived.value.size)
        for (m in _trash.value) ids.add(m.id)
        for (m in _archived.value) ids.add(m.id)
        return ids
    }

    /** Name/username + deep-content match against the (lazily built) index.
     * Global search only: excludes trashed + archived entries (id membership
     * AND the archived flag). In-place list search (Trash/Archive screens)
     * uses [contentHit] instead. */
    fun filtered(ciphers: List<MobileCipherMeta>): List<MobileCipherMeta> {
        val q = _query.value.trim()
        if (q.isEmpty()) return ciphers
        val hidden = hiddenIds()
        val lower = q.lowercase()
        return ciphers.filter { m ->
            !m.archived && m.id !in hidden &&
                (m.name.contains(q, ignoreCase = true) ||
                    (m.username?.contains(q, ignoreCase = true) ?: false) ||
                    contentIndex[m.id]?.contains(lower) == true)
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

/** Values under these keys never enter the deep-search haystack.
 * Password-class secrets per user policy: password is the one field excluded
 * from search, so old passwords and key material go with it. `totp_uri`
 * carries the live otpauth seed (password-equivalent). The rest is wire
 * noise (ids, type tags, epochs, timestamps) that would otherwise make every
 * entry match. Field names are never indexed either. */
internal val SEARCH_SKIP_KEYS = setOf(
    "password",
    "password_history",
    "password_revision_date",
    "private_key",
    "prf_key",
    "totp_uri",
    "favicon",
    "tier",
    "update_seq",
    "id",
    "credential_id",
    "aaguid",
    "cipher_type",
    "type",
    "field_type",
    "key_epoch",
    "folder_id",
    "created_at",
    "updated_at",
    "deleted_at",
    "creation_date",
    "linked_login_id",
    "counter",
    "user_handle",
    "key_value",
    "key_type",
    "key_algorithm",
    "key_curve",
)

/**
 * Flattens one decrypted cipher JSON into a lowercase haystack covering EVERY
 * content field: all cipher-type data (card numbers, identity, bank, SSH
 * fingerprints), custom fields (hidden values included, search-everything
 * policy), URIs, tags, passkey metadata. Values only; keys are not indexed.
 * Actual JSON booleans are structural flags (favorite, archived), not user
 * content. Unparseable input yields
 * "" so the entry falls back to name/username matching.
 */
internal fun buildSearchHaystack(raw: String): String {
    val obj = runCatching { Json.parseToJsonElement(raw) as? JsonObject }.getOrNull() ?: return ""
    val sb = StringBuilder()
    fun walk(element: JsonElement, key: String?) {
        // Prune BEFORE descending: a skipped key must exclude its whole
        // subtree (password_history entries, favicon base64), not just its
        // primitive values.
        if (key in SEARCH_SKIP_KEYS) return
        when (element) {
            is JsonObject -> for ((k, v) in element) walk(v, k)
            is JsonArray -> for (v in element) walk(v, key)
            JsonNull -> {}
            is JsonPrimitive -> {
                if (!element.isString && element.content in BOOLEAN_LITERALS) return
                sb.append(element.content).append(' ')
            }
        }
    }
    walk(obj, null)
    return sb.toString().trim().lowercase()
}

private val BOOLEAN_LITERALS = setOf("true", "false")

/** Tripwire: a refactor that drops one of these from [SEARCH_SKIP_KEYS]
 * fails the test instead of leaking a seed or key into the search index. */
internal val NEVER_INDEXABLE = setOf(
    "password", "password_history", "private_key", "prf_key", "totp_uri",
)
