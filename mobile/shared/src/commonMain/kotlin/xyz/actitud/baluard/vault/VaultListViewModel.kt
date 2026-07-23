package xyz.actitud.baluard.vault

import xyz.actitud.baluard.MobileCipherMeta
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.data.VaultRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Drives the vault list (Phase 3). Holds ciphers as a [StateFlow] so Compose
 * recomposes on changes.
 *
 * Search is local (client-side filter on name/username) for Phase 3; the plan
 * mentions Rust-side full-text search for large vaults (>1000 entries) —
 * that optimization lands when measured perf demands it.
 */
class VaultListViewModel(private val repo: VaultRepository) {
    private val _ciphers = MutableStateFlow<List<MobileCipherMeta>>(emptyList())
    val ciphers: StateFlow<List<MobileCipherMeta>> = _ciphers.asStateFlow()

    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()

    fun setQuery(q: String) { _query.value = q }

    /** Reload the cipher index from the runtime. Call after unlock + after mutations. */
    suspend fun refresh(vault: MobileVault) {
        _ciphers.value = repo.listCiphers(vault)
    }

    /** Client-side filter for Phase 3. */
    fun filtered(): List<MobileCipherMeta> {
        val q = _query.value.trim()
        if (q.isEmpty()) return _ciphers.value
        return _ciphers.value.filter { meta ->
            meta.name.contains(q, ignoreCase = true) ||
                (meta.username?.contains(q, ignoreCase = true) ?: false)
        }
    }
}
