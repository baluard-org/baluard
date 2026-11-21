package app.baluard.mobile.vault

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import app.baluard.mobile.MobileVault

/**
 * Lazily loads one list row's stored site icon through the VM cache: rows
 * request their bytes only while composed, so a large vault decrypts only
 * what is on screen. [vault] null (foreign merged-search hits) and
 * stored-absent cases return null and render the initials fallback. The
 * VM's faviconGen flow re-keys the load after every refresh()/clear(),
 * so post-backfill and post-edit rows pick up new bytes.
 */
@Composable
fun rememberCipherFavicon(
    viewModel: VaultListViewModel,
    vault: MobileVault?,
    id: String,
): ByteArray? {
    val gen by viewModel.faviconGen.collectAsState()
    var bytes by remember(id, gen) { mutableStateOf<ByteArray?>(null) }
    if (vault != null) {
        LaunchedEffect(id, gen) { bytes = viewModel.faviconFor(vault, id) }
    }
    return bytes
}
