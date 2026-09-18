package xyz.actitud.baluard.i18n

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import xyz.actitud.baluard.platform.platformLanguage

/**
 * Minimal i18n core (mirrors desktop's en.json/es.json + t()).
 *
 * `t` reads [language] (a Compose state), so any Text(t(...)) recomposes when
 * the language changes. Keys are flat "namespace.key" strings matching the
 * desktop JSON paths. Missing key -> English fallback -> the key itself, so a
 * missing translation is visible, never silent.
 *
 * Interpolation: "{0}", "{1}", ... replaced with [args] in order.
 */
object I18n {
    /** Two-letter ISO code ("en", "es", "pt"). Initialized from the platform locale. */
    var language by mutableStateOf(platformLanguage())
        private set

    fun switchTo(code: String) {
        if (code in DICTS) language = code
    }

    fun t(key: String, vararg args: Any?): String {
        val template = DICTS[language]?.get(key) ?: EN[key] ?: key
        if (args.isEmpty()) return template
        var out = template
        args.forEachIndexed { i, a -> out = out.replace("{$i}", a.toString()) }
        return out
    }
}

/** Translate [key] in the current language. See [I18n]. */
fun t(key: String, vararg args: Any?): String = I18n.t(key, *args)

private val DICTS: Map<String, Map<String, String>> = mapOf(
    "en" to EN,
    "es" to ES,
    "pt" to PT,
)
