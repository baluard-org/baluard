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

private const val FOLDER_PREFS = "baluard_folder_sync"
private const val KEY_TREE_URI = "saf_tree_uri"

@Composable
actual fun rememberFolderSyncBridge(): FolderSyncBridge {
    val context = AppContextHolder.require()
    val scope = rememberCoroutineScope()
    var pending by remember { mutableStateOf<((Uri?) -> Unit)?>(null) }
    val openTree = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri -> pending?.invoke(uri) }

    return remember(context) {
        object : FolderSyncBridge {
            override fun pickAndMirrorFolder(onMirrorReady: (String?) -> Unit) {
                pending = { uri ->
                    if (uri == null) {
                        onMirrorReady(null)
                    } else {
                        scope.launch {
                            val path = withContext(Dispatchers.IO) {
                                persistTreePermission(context, uri)
                                val mirror = mirrorRoot(context)
                                pullSafToMirror(context, uri, mirror)
                                mirror.absolutePath
                            }
                            onMirrorReady(path)
                        }
                    }
                }
                openTree.launch(null)
            }

            override fun pushMirrorToRemote(mirrorPath: String) {
                val uri = persistedTreeUri(context) ?: return
                pushMirrorToSaf(context, File(mirrorPath), uri)
            }

            override fun pullRemoteToMirror(mirrorPath: String) {
                val uri = persistedTreeUri(context) ?: return
                pullSafToMirror(context, uri, File(mirrorPath))
            }
        }
    }
}

private fun persistTreePermission(context: Context, treeUri: Uri) {
    val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
    context.contentResolver.takePersistableUriPermission(treeUri, flags)
    context.getSharedPreferences(FOLDER_PREFS, Context.MODE_PRIVATE)
        .edit()
        .putString(KEY_TREE_URI, treeUri.toString())
        .apply()
}

private fun persistedTreeUri(context: Context): Uri? {
    val raw = context.getSharedPreferences(FOLDER_PREFS, Context.MODE_PRIVATE)
        .getString(KEY_TREE_URI, null)
        ?: return null
    return Uri.parse(raw)
}

private fun mirrorRoot(context: Context): File =
    File(context.filesDir, "folder_sync_mirror").apply { mkdirs() }

private fun pullSafToMirror(context: Context, treeUri: Uri, mirrorDir: File) {
    val root = DocumentFile.fromTreeUri(context, treeUri) ?: return
    mirrorDir.mkdirs()
    copyDocTreeToDir(context, root, mirrorDir, inRefs = false)
}

private fun pushMirrorToSaf(context: Context, mirrorDir: File, treeUri: Uri) {
    val root = DocumentFile.fromTreeUri(context, treeUri) ?: return
    // Copy objects before refs/HEAD so readers never see a dangling ref.
    val children = mirrorDir.listFiles().orEmpty()
        .sortedBy { if (it.name == "refs" || it.name == "HEAD") 1 else 0 }
    copyDirEntriesToDocTree(context, children, root, inRefs = false)
}

internal fun copyDocTreeToDir(
    context: Context,
    doc: DocumentFile,
    dstDir: File,
    inRefs: Boolean,
) {
    val children = doc.listFiles()
        .sortedBy { if (it.name == "refs" || it.name == "HEAD") 1 else 0 }
    for (child in children) {
        val name = child.name ?: continue
        val nextInRefs = inRefs || name == "refs" || name == "HEAD"
        if (child.isDirectory) {
            val sub = File(dstDir, name).apply { mkdirs() }
            copyDocTreeToDir(context, child, sub, nextInRefs)
        } else if (child.isFile) {
            val target = File(dstDir, name)
            val skipByMtime = !nextInRefs
                && target.exists()
                && child.lastModified() > 0L
                && target.lastModified() >= child.lastModified()
            if (skipByMtime) continue
            context.contentResolver.openInputStream(child.uri)?.use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
        }
    }
}

internal fun copyDirEntriesToDocTree(
    context: Context,
    entries: List<File>,
    dstDoc: DocumentFile,
    inRefs: Boolean,
) {
    val existing = dstDoc.listFiles().associateBy { it.name }
    for (child in entries) {
        val nextInRefs = inRefs || child.name == "refs" || child.name == "HEAD"
        if (child.isDirectory) {
            val subDoc = existing[child.name]?.takeIf { it.isDirectory }
                ?: dstDoc.createDirectory(child.name)
                ?: continue
            val subChildren = child.listFiles().orEmpty()
                .sortedBy { if (it.name == "refs" || it.name == "HEAD") 1 else 0 }
            copyDirEntriesToDocTree(context, subChildren, subDoc, nextInRefs)
        } else if (child.isFile) {
            val docFile = existing[child.name]?.takeIf { it.isFile }
                ?: dstDoc.createFile("application/octet-stream", child.name)
                ?: continue
            // Always overwrite refs/HEAD regardless of SAF mtime skew.
            val skipByMtime = !nextInRefs
                && docFile.lastModified() > 0L
                && docFile.lastModified() >= child.lastModified()
            if (skipByMtime) continue
            context.contentResolver.openOutputStream(docFile.uri, "wt")?.use { output ->
                child.inputStream().use { input -> input.copyTo(output) }
            }
        }
    }
}
