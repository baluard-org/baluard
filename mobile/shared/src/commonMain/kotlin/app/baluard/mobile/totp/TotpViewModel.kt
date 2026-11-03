package app.baluard.mobile.totp

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import app.baluard.mobile.MobileVault
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.platform.Clock
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
            _state.value = fetch(vault, cipherId).let { (c, s, period) ->
                TotpState.Code(c, s, periodSeconds = period)
            }
            // Tick the countdown once a second; re-fetch near the rollover.
            var rolloverFailures = 0
            while (true) {
                delay(1000)
                val cur = (_state.value as? TotpState.Code) ?: break
                val next = cur.secondsRemaining - 1
                if (next <= 0) {
                    runCatching { fetch(vault, cipherId) }
                        .onSuccess {
                            rolloverFailures = 0
                            _state.value = TotpState.Code(it.first, it.second, periodSeconds = it.third)
                        }
                        .onFailure {
                            // The displayed code just expired: retrying next
                            // tick is honest, re-arming it for 30s is not.
                            rolloverFailures += 1
                            if (rolloverFailures >= 5) throw it
                            _state.value = cur.copy(secondsRemaining = 1)
                        }
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

    private suspend fun fetch(vault: MobileVault, cipherId: String): Triple<String, Int, Int> {
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
internal fun parseTotpResponse(raw: String, epochSeconds: Long): Triple<String, Int, Int>? {
    val obj = runCatching { Json.parseToJsonElement(raw) as? JsonObject }.getOrNull()
    if (obj != null) {
        val code = (obj["code"] as? JsonPrimitive)?.content ?: return null
        val period = (obj["period_seconds"] as? JsonPrimitive)?.content?.toIntOrNull()
            ?.coerceAtLeast(1) ?: 30
        val expiresAt = (obj["expires_at"] as? JsonPrimitive)?.content?.toLongOrNull()
            ?: return Triple(code, period, period)
        return Triple(code, (expiresAt - epochSeconds).toInt().coerceIn(0, period), period)
    }
    val parts = raw.trim().split(' ')
    val code = parts.firstOrNull { it.all(Char::isDigit) } ?: return null
    val secs = parts.lastOrNull()?.toIntOrNull() ?: 30
    return Triple(code, secs.coerceIn(1, 3600), 30)
}

sealed interface TotpState {
    data object Loading : TotpState
    data class Code(
        val code: String,
        val secondsRemaining: Int,
        /** The token's full window; progress bars scale against it. */
        val periodSeconds: Int = 30,
    ) : TotpState
    data class Error(val message: String) : TotpState
}
