package app.baluard.mobile.platform

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Extracts the stored site icon from a decrypted cipher JSON. Display-only:
 * nothing here fetches. The mime is attacker-influenced when the favicon
 * arrived via git sync or import (desktop D6), so only the desktop
 * allowlist reaches a decoder; anything else yields null and the UI falls
 * back to initials.
 */
@OptIn(ExperimentalEncodingApi::class)
object SiteIcon {

    private val MIME_ALLOWLIST = setOf(
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/x-icon",
        "image/vnd.microsoft.icon",
    )

    fun fromCipherJson(raw: String): ByteArray? {
        val obj = runCatching { Json.parseToJsonElement(raw) }.getOrNull()
            as? JsonObject ?: return null
        val favicon = obj["favicon"] as? JsonObject ?: return null
        val mime = (favicon["mime"] as? JsonPrimitive)?.content ?: return null
        val data = (favicon["data"] as? JsonPrimitive)?.content ?: return null
        if (mime !in MIME_ALLOWLIST) return null
        val bytes = runCatching { Base64.decode(data) }.getOrNull() ?: return null
        if (bytes.size < 8) return null
        // Android's BitmapFactory has no ICO decoder; hand it the PNG image
        // embedded in the container instead. Non-PNG ICO entries stay raw
        // (decoder-dependent) and fall back to initials when undecodable.
        return if (isIco(bytes)) embeddedPng(bytes) ?: bytes else bytes
    }

    private fun isIco(b: ByteArray): Boolean =
        b.size >= 4 && b[0] == 0.toByte() && b[1] == 0.toByte() &&
            b[2] == 1.toByte() && b[3] == 0.toByte()

    private fun embeddedPng(b: ByteArray): ByteArray? {
        val count = u16Le(b, 4)
        for (i in 0 until count) {
            val entry = 6 + i * 16
            if (entry + 16 > b.size) return null
            val size = u32Le(b, entry + 8).toInt()
            val offset = u32Le(b, entry + 12).toInt()
            if (offset < 0 || size <= 0 || offset + size > b.size) continue
            val img = b.copyOfRange(offset, offset + size)
            if (img.size >= 4 && img[0] == 0x89.toByte() && img[1] == 0x50.toByte() &&
                img[2] == 0x4E.toByte() && img[3] == 0x47.toByte()
            ) {
                return img
            }
        }
        return null
    }

    private fun u16Le(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

    private fun u32Le(b: ByteArray, off: Int): Long =
        (b[off].toLong() and 0xFF) or ((b[off + 1].toLong() and 0xFF) shl 8) or
            ((b[off + 2].toLong() and 0xFF) shl 16) or ((b[off + 3].toLong() and 0xFF) shl 24)
}
