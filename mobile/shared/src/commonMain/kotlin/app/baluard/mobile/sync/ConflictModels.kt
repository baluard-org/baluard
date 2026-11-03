package app.baluard.mobile.sync

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Wire contract of `MobileVault.getPendingConflictDetails` / `resolveConflict`
 * (runtime `conflict_decrypt_and_merge` / `conflict_resolve_verdict`).
 *
 * SECURITY: the runtime sends masked details only — field names + a coarse
 * `sensitive` flag. Secret values never cross the FFI boundary (mirrors the
 * desktop `sync.conflict` route contract, docs/adr/0093-conflict-resolution-panel.md).
 *
 * Shapes:
 *  - `{pending: false}` — nothing awaiting a decision.
 *  - `{pending, auto_merged: true, push_pending}` — merge_ciphers auto-resolved.
 *  - `{pending: true, cross_epoch: true, unreachable_side, detail, count}` —
 *    one side is at an unreachable key epoch; only keep_local/keep_remote are
 *    safe verdicts (keep_both is refused by the runtime).
 *  - `{pending: true, cross_epoch: false, count, cipher_id, name, cipher_type,
 *     fields: [{key, label, sensitive}]}` — needs a user verdict.
 */
@Serializable
data class PendingConflictDto(
    val pending: Boolean = false,
    @SerialName("auto_merged") val autoMerged: Boolean = false,
    @SerialName("push_pending") val pushPending: Boolean = false,
    @SerialName("cross_epoch") val crossEpoch: Boolean = false,
    @SerialName("unreachable_side") val unreachableSide: String? = null,
    val count: Int = 0,
    @SerialName("cipher_id") val cipherId: String? = null,
    val name: String? = null,
    @SerialName("cipher_type") val cipherType: String? = null,
    val fields: List<ConflictFieldDto> = emptyList(),
)

/** One conflicting field. Label only; `sensitive` marks masked values. */
@Serializable
data class ConflictFieldDto(
    val key: String,
    val label: String = key,
    val sensitive: Boolean = false,
)

/** User verdict, mapped to the runtime's wire strings. */
enum class ConflictVerdict(val wire: String) {
    KEEP_LOCAL("keep_local"),
    KEEP_REMOTE("keep_remote"),
    KEEP_BOTH("keep_both"),
}

/** Lenient decoder: the runtime may add keys; never crash the UI on one. */
private val conflictJson = Json { ignoreUnknownKeys = true }

/** Parse the FFI JSON body; null when nothing is awaiting a decision. */
fun parsePendingConflict(body: String): PendingConflictDto? =
    runCatching { conflictJson.decodeFromString<PendingConflictDto>(body) }.getOrNull()
