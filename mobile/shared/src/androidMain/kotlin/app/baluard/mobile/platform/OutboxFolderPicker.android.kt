package app.baluard.mobile.platform

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

private const val OUTBOX_PREFS = "baluard_outbox_mirrors"

actual object OutboxFolderSupport {
    actual fun isSupported(): Boolean = true
}

@Composable
actual fun rememberOutboxFolderBridge(): OutboxFolderBridge {
    val context = AppContextHolder.require()
    val scope = rememberCoroutineScope()
    var pending by remember { mutableStateOf<((Uri?) -> Unit)?>(null) }
    val openTree = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri -> pending?.invoke(uri) }

    return remember(context) {
        object : OutboxFolderBridge {
            override fun pickFolder(onReady: (String?) -> Unit) {
                pending = { uri ->
                    if (uri == null) {
                        onReady(null)
                    } else {
                        scope.launch {
                            val path = withContext(Dispatchers.IO) {
                                val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
                                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                                runCatching {
                                    context.contentResolver.takePersistableUriPermission(uri, flags)
                                }
                                val mirror = outboxMirrorDir(context, uri)
                                saveOutboxTreeMapping(context, mirror.absolutePath, uri)
                                DocumentFile.fromTreeUri(context, uri)?.let { doc ->
                                    copyDocTreeToDir(context, doc, mirror, inRefs = false)
                                }
                                mirror.absolutePath
                            }
                            onReady(path)
                        }
                    }
                }
                openTree.launch(null)
            }

            override fun pushMirror(mirrorPath: String) {
                val match = loadOutboxTreeMatch(context, mirrorPath) ?: return
                val root = DocumentFile.fromTreeUri(context, Uri.parse(match.uriString)) ?: return
                val targetDoc = resolveDocSubtree(root, match.relativeSegments, createMissing = true) ?: return
                val dir = File(mirrorPath)
                val children = dir.listFiles().orEmpty()
                    .sortedBy { if (it.name == "refs" || it.name == "HEAD") 1 else 0 }
                copyDirEntriesToDocTree(context, children, targetDoc, inRefs = false)
            }

            override fun pullMirror(mirrorPath: String) {
                val match = loadOutboxTreeMatch(context, mirrorPath) ?: return
                val root = DocumentFile.fromTreeUri(context, Uri.parse(match.uriString)) ?: return
                val targetDoc = resolveDocSubtree(root, match.relativeSegments, createMissing = false) ?: return
                val dir = File(mirrorPath).apply { mkdirs() }
                copyDocTreeToDir(context, targetDoc, dir, inRefs = false)
            }
        }
    }
}

private fun outboxMirrorDir(context: Context, uri: Uri): File {
    val digest = MessageDigest.getInstance("SHA-256")
        .digest(uri.toString().toByteArray())
        .take(12)
        .joinToString("") { "%02x".format(it) }
    return File(File(context.filesDir, "outbox_mirrors"), digest).apply { mkdirs() }
}

private fun saveOutboxTreeMapping(context: Context, mirrorPath: String, uri: Uri) {
    val key = runCatching { File(mirrorPath).canonicalPath }.getOrDefault(mirrorPath)
    context.getSharedPreferences(OUTBOX_PREFS, Context.MODE_PRIVATE)
        .edit()
        .putString(key, uri.toString())
        .putString(mirrorPath, uri.toString())
        .apply()
}

private fun loadOutboxTreeMatch(context: Context, mirrorPath: String): OutboxTreeMatch? {
    val prefs = context.getSharedPreferences(OUTBOX_PREFS, Context.MODE_PRIVATE)
    val mappings = prefs.all.mapNotNull { (k, v) ->
        (v as? String)?.let { k to it }
    }.toMap()
    resolveOutboxTreeMatch(mirrorPath, mappings)?.let { return it }
    val canonical = runCatching { File(mirrorPath).canonicalPath }.getOrNull() ?: return null
    return resolveOutboxTreeMatch(canonical, mappings)
}

private fun resolveDocSubtree(
    root: DocumentFile,
    relativeSegments: List<String>,
    createMissing: Boolean,
): DocumentFile? {
    var current = root
    for (segment in relativeSegments) {
        val existing = current.findFile(segment)?.takeIf { it.isDirectory }
        current = when {
            existing != null -> existing
            createMissing -> current.createDirectory(segment) ?: return null
            else -> return null
        }
    }
    return current
}
