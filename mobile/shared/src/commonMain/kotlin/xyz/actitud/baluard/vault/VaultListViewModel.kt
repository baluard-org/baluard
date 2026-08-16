package xyz.actitud.baluard.vault

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.data.VaultRepository

/**
 * Drives the vault list (Phase 3). Holds ciphers as a [StateFlow] so Compose
 * recomposes on changes.
 *
 * Filtering: text search (name/username) + optional type chip + optional tag
 * chip + favorites-only toggle. Archived entries never render. All filters
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

    val favoritesOnly = MutableStateFlow(false)

    fun setQuery(q: String) { _query.value = q }

    fun setTypeFilter(tag: String?) { typeFilter.value = tag }
    fun setTagFilter(tag: String?) { tagFilter.value = tag }
    fun setFavoritesOnly(v: Boolean) { favoritesOnly.value = v }

    /** Reload the cipher index from the runtime. Call after unlock + after mutations. */
    suspend fun refresh(vault: MobileVault) {
        _ciphers.value = repo.listCiphers(vault)
    }

    /** Distinct tags across visible (non-archived) entries, for the chip row. */
    fun allTags(): List<String> =
        _ciphers.value.filter { !it.archived }.flatMap { it.tags }.distinct().sorted()

    /** Distinct wire type tags across visible entries, for the chip row. */
    fun allTypes(): List<String> =
        _ciphers.value.filter { !it.archived }.map { it.cipherType }.distinct().sorted()

    /** Apply the current filters. */
    fun filtered(): List<MobileCipherMeta> {
        val q = _query.value.trim()
        val type = typeFilter.value
        val tag = tagFilter.value
        val favOnly = favoritesOnly.value
        return _ciphers.value.filter { m ->
            !m.archived &&
                (type == null || m.cipherType == type) &&
                (tag == null || m.tags.contains(tag)) &&
                (!favOnly || m.favorite) &&
                (q.isEmpty() || m.name.contains(q, ignoreCase = true) ||
                    (m.username?.contains(q, ignoreCase = true) ?: false))
        }
    }
}
