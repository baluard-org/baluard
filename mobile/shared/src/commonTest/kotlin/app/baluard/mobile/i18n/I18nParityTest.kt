package app.baluard.mobile.i18n

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

class I18nParityTest {
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
            for (match in Regex("""\bt\(\s*"([^"]+)"""").findAll(text)) {
                val key = match.groupValues[1]
                // Dynamic prefixes (t("people." + kind + "Title")) scan as a
                // trailing-dot literal; their completions are runtime data.
                if (key.endsWith(".")) continue
                if (key !in EN.keys) missing.getOrPut(key) { mutableListOf() }.add(file.name)
            }
        }
        assertTrue(missing.isEmpty(), "Rendered keys missing from EN: $missing")
    }
}
