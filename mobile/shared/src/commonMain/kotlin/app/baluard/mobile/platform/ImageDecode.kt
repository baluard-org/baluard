package app.baluard.mobile.platform

import androidx.compose.ui.graphics.ImageBitmap

/** Decode image bytes for display (G21 avatar). Null when the platform
 *  cannot decode or the bytes are malformed. */
expect fun decodeImageBitmap(bytes: ByteArray): ImageBitmap?

/** Prepare picked image bytes for storage as the vault avatar: decode,
 *  downscale, and recompress so typical phone photos fit the core's
 *  ~256KB cap. Returns (bytes, ext) or null when undecodable. */
expect fun prepareAvatarImage(bytes: ByteArray): Pair<ByteArray, String>?
