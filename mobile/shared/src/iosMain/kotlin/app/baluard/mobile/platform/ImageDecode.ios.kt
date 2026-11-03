package app.baluard.mobile.platform

import androidx.compose.ui.graphics.ImageBitmap

/** iOS avatars render nothing until a CoreGraphics decoder lands. */
actual fun decodeImageBitmap(bytes: ByteArray): ImageBitmap? = null

actual fun prepareAvatarImage(bytes: ByteArray): Pair<ByteArray, String>? = null
