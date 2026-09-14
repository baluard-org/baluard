package xyz.actitud.baluard.totp

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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
            val raw = repo.totpCode(vault, cipherId)
            val parts = raw.split(' ')
            val code = parts.firstOrNull { it.all(Char::isDigit) } ?: raw
            val secs = parts.lastOrNull()?.toIntOrNull() ?: secondsIntoWindow()
            _state.value = TotpState.Code(code, secs)
            // Tick the countdown once a second; re-fetch near the rollover.
            while (true) {
                delay(1000)
                val cur = (_state.value as? TotpState.Code) ?: break
                val next = cur.secondsRemaining - 1
                if (next <= 0) {
                    // Re-fetch at the window boundary.
                    val refreshed = runCatching { repo.totpCode(vault, cipherId) }.getOrNull()
                    val rp = refreshed?.split(' ')?.lastOrNull()?.toIntOrNull() ?: 30
                    val rc = refreshed?.split(' ')?.firstOrNull { it.all(Char::isDigit) } ?: cur.code
                    _state.value = TotpState.Code(rc, rp)
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

    private fun secondsIntoWindow(): Int {
        val epochSeconds = Clock.currentTimeMillis() / 1000
        return (30 - (epochSeconds % 30)).toInt().coerceIn(1, 30)
    }
}

sealed interface TotpState {
    data object Loading : TotpState
    data class Code(val code: String, val secondsRemaining: Int) : TotpState
    data class Error(val message: String) : TotpState
}
