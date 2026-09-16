package xyz.actitud.baluard.totp

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.platform.Clock
import kotlin.coroutines.cancellation.CancellationException

/**
 * Live TOTP code display. Refreshes every second to update the countdown ring
 * and re-fetches the code from the runtime near each 30s boundary.
 *
 * The TOTP seed NEVER crosses the FFI boundary (plan §3.6 GOTCHA): only the
 * derived 6-digit code + seconds-until-rollover are returned by the runtime.
 */
class TotpViewModel(private val repo: VaultRepository) {
    private val _state = MutableStateFlow<TotpState>(TotpState.Loading)
    val state: StateFlow<TotpState> = _state.asStateFlow()

    /**
     * Polls the runtime for the current code. The [Clock.currentTimeMillis]
     * fallback computes the countdown from the standard 30s TOTP window when
     * the runtime doesn't return explicit seconds (the daemon wire format
     * returns "code seconds_remaining"; we parse defensively).
     */
    suspend fun start(vault: MobileVault, cipherId: String) {
        _state.value = TotpState.Loading
        try {
            val (code, secs) = fetch(vault, cipherId)
            _state.value = TotpState.Code(code, secs)
            // Tick the countdown once a second; re-fetch near the rollover.
            while (true) {
                delay(1000)
                val cur = (_state.value as? TotpState.Code) ?: break
                val next = cur.secondsRemaining - 1
                if (next <= 0) {
                    val refreshed = runCatching { fetch(vault, cipherId) }
                        .getOrElse { cur.code to 30 }
                    _state.value = TotpState.Code(refreshed.first, refreshed.second)
                } else {
                    _state.value = cur.copy(secondsRemaining = next)
                }
            }
        } catch (e: CancellationException) {
            // Leaving the screen cancels the tick loop; that is not an error state.
            throw e
        } catch (e: Exception) {
            _state.value = TotpState.Error(e.message ?: "TOTP failed")
        }
    }

    private suspend fun fetch(vault: MobileVault, cipherId: String): Pair<String, Int> {
        val raw = repo.totpCode(vault, cipherId)
        return parseTotpResponse(raw, Clock.currentTimeMillis() / 1000)
            ?: throw IllegalStateException("Unparseable TOTP response")
    }
}

/**
 * Parses the runtime TOTP wire response: JSON
 * {"code":"123456","period_seconds":30,"expires_at":<unix_secs>}. Returns
 * (code, secondsRemaining), computed from the expires_at epoch so odd periods
 * stay correct. The legacy "<code> <secs>" space form is accepted defensively
 * for older runtimes. Null when neither parses.
 */
internal fun parseTotpResponse(raw: String, epochSeconds: Long): Pair<String, Int>? {
    val obj = runCatching { Json.parseToJsonElement(raw) as? JsonObject }.getOrNull()
    if (obj != null) {
        val code = (obj["code"] as? JsonPrimitive)?.content ?: return null
        val expiresAt = (obj["expires_at"] as? JsonPrimitive)?.content?.toLongOrNull()
            ?: return code to 30
        return code to (expiresAt - epochSeconds).toInt().coerceIn(0, 3600)
    }
    val parts = raw.trim().split(' ')
    val code = parts.firstOrNull { it.all(Char::isDigit) } ?: return null
    val secs = parts.lastOrNull()?.toIntOrNull() ?: 30
    return code to secs.coerceIn(1, 3600)
}

sealed interface TotpState {
    data object Loading : TotpState
    data class Code(val code: String, val secondsRemaining: Int) : TotpState
    data class Error(val message: String) : TotpState
}
