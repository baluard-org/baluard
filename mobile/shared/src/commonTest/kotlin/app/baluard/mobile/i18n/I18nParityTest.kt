package app.baluard.mobile.i18n

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

class I18nParityTest {
    private val QUOTED = Regex("\"([^\"]+)\"")
    private val KEY_SHAPE = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)+")

    /**
     * Dotted literals in a t(...) argument window that are not part of a `+`
     * concat. Keys are dotted identifiers by contract, so the shape whitelist
     * ignores comparison literals ("true", "owners") and dynamic suffixes
     * ("Title") that share the window.
     */
    private fun keysIn(window: String): List<String> =
        QUOTED.findAll(window).mapNotNull { m ->
            val frag = m.groupValues[1]
            if (!KEY_SHAPE.matches(frag)) return@mapNotNull null
            val prev = window.substring(0, m.range.first).trimEnd().lastOrNull()
            val next = window.substring(m.range.last + 1).trimStart().firstOrNull()
            if (prev == '+' || next == '+') null else frag
        }.toList()

    @Test
    fun enAndEsHaveExactSameKeys() {
        val missingInEs = EN.keys - ES.keys
        val missingInEn = ES.keys - EN.keys
        assertTrue(missingInEs.isEmpty(), "Keys missing in ES: $missingInEs")
        assertTrue(missingInEn.isEmpty(), "Keys missing in EN: $missingInEn")
    }

    @Test
    fun enAndPtHaveExactSameKeys() {
        val missingInPt = EN.keys - PT.keys
        val missingInEn = PT.keys - EN.keys
        assertTrue(missingInPt.isEmpty(), "Keys missing in PT: $missingInPt")
        assertTrue(missingInEn.isEmpty(), "Keys missing in EN: $missingInEn")
    }

    @Test
    fun enAndFrHaveExactSameKeys() {
        val missingInFr = EN.keys - FR.keys
        val missingInEn = FR.keys - EN.keys
        assertTrue(missingInFr.isEmpty(), "Keys missing in FR: $missingInFr")
        assertTrue(missingInEn.isEmpty(), "Keys missing in EN: $missingInEn")
    }

    /**
     * Every t("...") literal in the Kotlin sources must exist in EN: key
     * parity alone misses rendered keys that no locale ships (the raw
     * common.confirm defect shipped as a visible key string). Scans the
     * shared and androidApp source trees relative to the repo root the
     * Gradle test runs from.
     */
    @Test
    fun everyRenderedKeyExistsInEn() {
        val roots = listOf(
            File("../shared/src/commonMain/kotlin"),
            File("../androidApp/src/androidMain/kotlin"),
            File("src/commonMain/kotlin"),
            File("src/androidMain/kotlin"),
        )
        val sources = roots.flatMap { root ->
            root.takeIf { it.isDirectory }
                ?.walkTopDown()
                ?.filter { it.isFile && it.extension == "kt" }
                ?.toList()
                .orEmpty()
        }
        assertTrue(sources.isNotEmpty(), "no Kotlin sources found; run from the repo root or mobile/")
        val missing = mutableMapOf<String, MutableList<String>>()
        for (file in sources) {
            val text = file.readText()
            // Scan every quoted string inside each t(...) argument list.
            // Matching only the plain t("key") shape misses the conditional
            // t(if (..) "a" else "b") form, which is exactly how the raw-key
            // delete-dialog defect shipped.
            for (call in Regex("""\bt\(""").findAll(text)) {
                var depth = 0
                var i = call.range.first + call.value.length
                val window = StringBuilder()
                while (i < text.length) {
                    when (val c = text[i]) {
                        '(' -> depth++
                        ')' -> if (depth == 0) break else depth--
                        else -> window.append(c)
                    }
                    i++
                }
                for (key in keysIn(window.toString())) {
                    if (key !in EN.keys) missing.getOrPut(key) { mutableListOf() }.add(file.name)
                }
            }
        }
        assertTrue(missing.isEmpty(), "Rendered keys missing from EN: $missing")
    }

    /**
     * The rendered-key scanner's whitelist assumes every key is a dotted
     * identifier; enforce the assumption instead of letting it rot silently.
     */
    @Test
    fun enKeysAreKeyShaped() {
        val odd = EN.keys.filter { !KEY_SHAPE.matches(it) }
        assertTrue(odd.isEmpty(), "EN keys not matching key shape: $odd")
    }
}
