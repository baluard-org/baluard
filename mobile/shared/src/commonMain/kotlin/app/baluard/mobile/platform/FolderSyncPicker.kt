package app.baluard.mobile.platform

import androidx.compose.runtime.Composable

/**
 * Platform bridge for ADR 0112 local-folder sync.
 * Mirrors a platform-owned folder (Android SAF `content://` tree or iOS
 * security-scoped iCloud/Files folder) into an app-private POSIX directory
 * so `baluard-uniffi` / `git2` can run `commit -> pull -> push`.
 */
interface FolderSyncBridge {
    fun pickAndMirrorFolder(onMirrorReady: (mirrorPath: String?) -> Unit)
    fun pushMirrorToRemote(mirrorPath: String)
    fun pullRemoteToMirror(mirrorPath: String)
}

@Composable
expect fun rememberFolderSyncBridge(): FolderSyncBridge
