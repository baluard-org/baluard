package app.baluard.mobile.platform

import androidx.compose.runtime.Composable

/**
 * Platform bridge for Direct sharing -> Outboxes.
 * Mirrors a platform-picked shared folder (Android SAF tree or iOS bookmark)
 * into a per-folder app-private POSIX directory so Rust outbox git ops can
 * read and write standard filesystem paths.
 */
interface OutboxFolderBridge {
    fun pickFolder(onReady: (mirrorPath: String?) -> Unit)
    fun pushMirror(mirrorPath: String)
    fun pullMirror(mirrorPath: String)
}

expect object OutboxFolderSupport {
    fun isSupported(): Boolean
}

@Composable
expect fun rememberOutboxFolderBridge(): OutboxFolderBridge

data class OutboxTreeMatch(
    val uriString: String,
    val relativeSegments: List<String>,
)

fun deriveOutboxTargetPath(
    basePath: String,
    recipientDisplayName: String,
    recipientSigningPubkey: String,
    multiRecipient: Boolean,
): String {
    val base = basePath.trim().trimEnd('/')
    if (!multiRecipient) return base
    val slug = recipientDisplayName.lowercase()
        .replace(Regex("[^a-z0-9]+"), "-")
        .trim('-')
        .ifEmpty { "recipient" }
    return "$base/$slug-${recipientSigningPubkey.take(6)}"
}

fun resolveOutboxTreeMatch(
    mirrorPath: String,
    mappings: Map<String, String>,
): OutboxTreeMatch? {
    val normTarget = mirrorPath.trimEnd('/')
    if (normTarget.isEmpty()) return null
    var bestKey = ""
    var bestUri: String? = null
    for ((rawKey, uri) in mappings) {
        val normKey = rawKey.trimEnd('/')
        if (normKey.isEmpty()) continue
        val matches = normTarget == normKey || normTarget.startsWith("$normKey/")
        if (matches && normKey.length > bestKey.length) {
            bestKey = normKey
            bestUri = uri
        }
    }
    val uri = bestUri ?: return null
    val remainder = normTarget.removePrefix(bestKey).trim('/')
    val segments = if (remainder.isEmpty()) emptyList() else remainder.split('/').filter { it.isNotEmpty() }
    return OutboxTreeMatch(uriString = uri, relativeSegments = segments)
}
