package xyz.actitud.baluard.platform

import java.io.File

/**
 * Tiny cross-process flag store for the autofill feature gates (Agy finding
 * #7): SharedPreferences are cached per process and background processes do
 * not reload files written by another process, so a flag flipped in the main
 * app could stay stale in `:autofill` until restart. These flags are read
 * directly from app-sandbox files on every call instead; they change rarely
 * and reads are tiny.
 */
internal object AutofillFlagFile {

    private fun file(name: String): File? {
        val dir = AppContextHolder.get()?.filesDir ?: return null
        return File(dir, "autofill_flags/$name")
    }

    fun read(name: String, default: Boolean): Boolean {
        val f = file(name) ?: return default
        return runCatching { f.readText().trim() == "1" }.getOrDefault(default)
    }

    fun write(name: String, value: Boolean) {
        val f = file(name) ?: return
        runCatching {
            f.parentFile?.mkdirs()
            f.writeText(if (value) "1" else "0")
        }
    }
}
