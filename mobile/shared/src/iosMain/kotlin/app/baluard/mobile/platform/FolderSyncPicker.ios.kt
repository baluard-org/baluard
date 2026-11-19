package app.baluard.mobile.platform

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSData
import platform.Foundation.NSFileCoordinator
import platform.Foundation.NSFileManager
import platform.Foundation.NSURL
import platform.Foundation.NSUserDefaults
import platform.Foundation.dataWithContentsOfURL
import platform.Foundation.writeToURL

private const val BOOKMARK_KEY = "baluard_folder_sync_bookmark"

@OptIn(ExperimentalForeignApi::class)
@Composable
actual fun rememberFolderSyncBridge(): FolderSyncBridge = remember {
    object : FolderSyncBridge {
        override fun pickAndMirrorFolder(onMirrorReady: (String?) -> Unit) {
            val url = restoreBookmark()
            if (url == null) {
                onMirrorReady(null)
                return
            }
            val mirror = iosMirrorRoot()
            coordinateFolder(url, writing = false) { scoped ->
                copyUrlTreeToLocal(scoped, mirror)
            }
            onMirrorReady(mirror)
        }

        override fun pushMirrorToRemote(mirrorPath: String) {
            val url = restoreBookmark() ?: return
            coordinateFolder(url, writing = true) { scoped ->
                copyLocalToUrlTree(mirrorPath, scoped)
            }
        }

        override fun pullRemoteToMirror(mirrorPath: String) {
            val url = restoreBookmark() ?: return
            coordinateFolder(url, writing = false) { scoped ->
                copyUrlTreeToLocal(scoped, mirrorPath)
            }
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun restoreBookmark(): NSURL? {
    val data = NSUserDefaults.standardUserDefaults.dataForKey(BOOKMARK_KEY) ?: return null
    return NSURL.URLByResolvingBookmarkData(
        data,
        options = 0uL,
        relativeToURL = null,
        bookmarkDataIsStale = null,
        error = null,
    )
}

private fun iosMirrorRoot(): String {
    val fm = NSFileManager.defaultManager
    val base = fm.temporaryDirectory.path ?: "/tmp"
    val dir = "$base/baluard_folder_sync_mirror"
    fm.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = null, error = null)
    return dir
}

@OptIn(ExperimentalForeignApi::class)
private fun coordinateFolder(url: NSURL, writing: Boolean, block: (NSURL) -> Unit) {
    if (!url.startAccessingSecurityScopedResource()) return
    try {
        val coordinator = NSFileCoordinator(filePresenter = null)
        if (writing) {
            coordinator.coordinateWritingItemAtURL(url, options = 0uL, error = null) { target ->
                if (target != null) block(target)
            }
        } else {
            coordinator.coordinateReadingItemAtURL(url, options = 0uL, error = null) { target ->
                if (target != null) block(target)
            }
        }
    } finally {
        url.stopAccessingSecurityScopedResource()
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun copyUrlTreeToLocal(srcUrl: NSURL, dstDir: String) {
    val fm = NSFileManager.defaultManager
    val srcPath = srcUrl.path ?: return
    val items = fm.subpathsOfDirectoryAtPath(srcPath, error = null) ?: return
    for (relAny in items) {
        val rel = relAny as? String ?: continue
        val srcFile = "$srcPath/$rel"
        val dstFile = "$dstDir/$rel"
        val parent = (dstFile as platform.Foundation.NSString).stringByDeletingLastPathComponent
        fm.createDirectoryAtPath(parent, withIntermediateDirectories = true, attributes = null, error = null)
        val data = NSData.dataWithContentsOfURL(NSURL.fileURLWithPath(srcFile)) ?: continue
        data.writeToURL(NSURL.fileURLWithPath(dstFile), atomically = true)
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun copyLocalToUrlTree(srcDir: String, dstUrl: NSURL) {
    val fm = NSFileManager.defaultManager
    val dstPath = dstUrl.path ?: return
    val items = fm.subpathsOfDirectoryAtPath(srcDir, error = null) ?: return
    for (relAny in items) {
        val rel = relAny as? String ?: continue
        val srcFile = "$srcDir/$rel"
        val dstFile = "$dstPath/$rel"
        val parent = (dstFile as platform.Foundation.NSString).stringByDeletingLastPathComponent
        fm.createDirectoryAtPath(parent, withIntermediateDirectories = true, attributes = null, error = null)
        val data = NSData.dataWithContentsOfURL(NSURL.fileURLWithPath(srcFile)) ?: continue
        data.writeToURL(NSURL.fileURLWithPath(dstFile), atomically = true)
    }
}
