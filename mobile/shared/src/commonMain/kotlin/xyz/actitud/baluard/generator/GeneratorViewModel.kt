package xyz.actitud.baluard.generator

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import xyz.actitud.baluard.PassphraseConfig
import xyz.actitud.baluard.PasswordConfig
import xyz.actitud.baluard.data.VaultRepository

enum class GeneratorMode { PASSWORD, PASSPHRASE }

data class GeneratorUiState(
    val mode: GeneratorMode = GeneratorMode.PASSWORD,
    val length: Int = 16,
    val upper: Boolean = true,
    val numbers: Boolean = true,
    val symbols: Boolean = true,
    val wordCount: Int = 5,
    val separator: String = "-",
    val ppUpper: Boolean = false,
    val ppNumber: Boolean = false,
    val ppSymbol: Boolean = false,
    val result: String? = null,
)

/**
 * Drives the generator screen. Calls the Rust generator via [VaultRepository]
 * (suspend; the selection is OsRng-bound, sub-millisecond).
 */
class GeneratorViewModel(private val repo: VaultRepository) {
    private val _state = MutableStateFlow(GeneratorUiState())
    val state: StateFlow<GeneratorUiState> = _state.asStateFlow()

    fun setMode(m: GeneratorMode) { _state.value = _state.value.copy(mode = m) }
    fun setLength(n: Int) { _state.value = _state.value.copy(length = n.coerceIn(1, 256)) }
    fun setUpper(b: Boolean) { _state.value = _state.value.copy(upper = b) }
    fun setNumbers(b: Boolean) { _state.value = _state.value.copy(numbers = b) }
    fun setSymbols(b: Boolean) { _state.value = _state.value.copy(symbols = b) }
    fun setWordCount(n: Int) { _state.value = _state.value.copy(wordCount = n.coerceIn(1, 20)) }
    fun setSeparator(s: String) { _state.value = _state.value.copy(separator = s) }
    fun setPpUpper(b: Boolean) { _state.value = _state.value.copy(ppUpper = b) }
    fun setPpNumber(b: Boolean) { _state.value = _state.value.copy(ppNumber = b) }
    fun setPpSymbol(b: Boolean) { _state.value = _state.value.copy(ppSymbol = b) }

    suspend fun generate() {
        val s = _state.value
        val result = if (s.mode == GeneratorMode.PASSWORD) {
            repo.generatePassword(
                PasswordConfig(
                    length = s.length.toUInt(),
                    upper = s.upper,
                    numbers = s.numbers,
                    symbols = s.symbols,
                ),
            )
        } else {
            repo.generatePassphrase(
                PassphraseConfig(
                    wordCount = s.wordCount.toUInt(),
                    separator = s.separator,
                    upper = s.ppUpper,
                    number = s.ppNumber,
                    symbol = s.ppSymbol,
                ),
            )
        }
        _state.value = s.copy(result = result.getOrNull())
    }
}
