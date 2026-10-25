package xyz.actitud.baluard.platform

import java.io.File

/**
 * Tiny cross-process key-value store for settings that both the main app
 * process and `:autofill` read (vault pointer, screenshot/clipboard prefs,
 * the biometric KEK blobs). SharedPreferences are cached per process and a
 * background process never reloads what the foreground wrote, so these are
 * plain sandbox files read on every call — the same shape as
 * [AutofillFlagFile], generalized to string values. Not for large or
 * high-frequency data.
 */
internal object CrossProcessPrefs {

    private fun dir(): File? =
        AppContextHolder.get()?.filesDir?.let { File(it, "local_prefs") }

    private fun file(key: String): File? = dir()?.let { File(it, key) }

    fun read(key: String): String? {
        val f = file(key) ?: return null
        return runCatching { f.takeIf { it.isFile }?.readText() }.getOrNull()
    }

    fun write(key: String, value: String) {
        val f = file(key) ?: return
        runCatching {
            f.parentFile?.mkdirs()
            val tmp = File(f.parentFile, f.name + ".tmp")
            tmp.writeText(value)
            if (!tmp.renameTo(f)) f.writeText(value)
        }
    }

    fun remove(key: String) {
        runCatching { file(key)?.delete() }
    }
}
