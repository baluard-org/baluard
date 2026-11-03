package app.baluard.mobile.platform

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import java.io.ByteArrayOutputStream

actual fun decodeImageBitmap(bytes: ByteArray): ImageBitmap? =
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap()

actual fun prepareAvatarImage(bytes: ByteArray): Pair<ByteArray, String>? {
    val src = BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: return null
    // Longest edge 512px keeps avatars crisp at every display size while
    // pulling multi-megabyte camera photos under the storage cap.
    val longest = maxOf(src.width, src.height)
    val scale = if (longest > 512) 512f / longest else 1f
    val bmp = if (scale < 1f) {
        Bitmap.createScaledBitmap(
            src,
            (src.width * scale).toInt().coerceAtLeast(1),
            (src.height * scale).toInt().coerceAtLeast(1),
            true,
        )
    } else {
        src
    }
    // Recompress until the decoded size clears the core's cap (~256KB
    // decoded <-> 350K base64 chars); quality 90 is visually lossless
    // for avatar display sizes.
    for (quality in intArrayOf(90, 80, 70, 60)) {
        val out = ByteArrayOutputStream()
        bmp.compress(Bitmap.CompressFormat.JPEG, quality, out)
        val data = out.toByteArray()
        if (data.size <= 262_144) return data to "jpg"
    }
    val out = ByteArrayOutputStream()
    bmp.compress(Bitmap.CompressFormat.JPEG, 50, out)
    return out.toByteArray() to "jpg"
}
