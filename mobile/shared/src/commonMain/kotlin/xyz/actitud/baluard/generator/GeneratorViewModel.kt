package xyz.actitud.baluard.generator

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import xyz.actitud.baluard.MobileVault
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

/** One past generated value, as shown in the history section. */
data class GeneratorHistoryEntry(
    val value: String,
    val kind: String,
    val createdAt: Long,
)

/**
 * Drives the generator screen. Calls the Rust generator via [VaultRepository]
 * (suspend; the selection is OsRng-bound, sub-millisecond). History mirrors
 * the desktop drawer: every generated value is persisted best-effort under
 * the vault and never blocks generation on failure.
 */
class GeneratorViewModel(private val repo: VaultRepository) {
    private val _state = MutableStateFlow(GeneratorUiState())
    val state: StateFlow<GeneratorUiState> = _state.asStateFlow()

    private val _history = MutableStateFlow<List<GeneratorHistoryEntry>>(emptyList())
    val history: StateFlow<List<GeneratorHistoryEntry>> = _history.asStateFlow()

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

    suspend fun loadHistory(vault: MobileVault) {
        _history.value = runCatching { parseHistory(repo.generatorHistoryList(vault)) }
            .getOrDefault(emptyList())
    }

    suspend fun clearHistory(vault: MobileVault) {
        runCatching { repo.generatorHistoryClear(vault) }
        _history.value = emptyList()
    }

    suspend fun generate(vault: MobileVault?) {
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
        val value = result.getOrNull()
        _state.value = s.copy(result = value)

        // Best-effort persistence; generation must never fail because of it.
        if (vault != null && value != null) {
            runCatching {
                val kind = if (s.mode == GeneratorMode.PASSWORD) "password" else "passphrase"
                val params = buildJsonObject {
                    put("length", if (s.mode == GeneratorMode.PASSWORD) s.length else s.wordCount)
                    put("upper", if (s.mode == GeneratorMode.PASSWORD) s.upper else s.ppUpper)
                    put("numbers", if (s.mode == GeneratorMode.PASSWORD) s.numbers else s.ppNumber)
                    put("symbols", if (s.mode == GeneratorMode.PASSWORD) s.symbols else s.ppSymbol)
                    if (s.mode == GeneratorMode.PASSPHRASE) put("separator", s.separator)
                }
                val payload = buildJsonObject {
                    put("value", value)
                    put("kind", kind)
                    put("params", params)
                }.toString()
                repo.generatorHistoryAdd(vault, payload)
                loadHistory(vault)
            }
        }
    }
}

internal fun parseHistory(json: String): List<GeneratorHistoryEntry> =
    Json.parseToJsonElement(json).jsonArray.map { e ->
        val o = e.jsonObject
        GeneratorHistoryEntry(
            value = o["value"]?.jsonPrimitive?.content ?: "",
            kind = o["kind"]?.jsonPrimitive?.content ?: "password",
            createdAt = o["created_at"]?.jsonPrimitive?.longOrNull ?: 0L,
        )
    }
