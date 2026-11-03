package app.baluard.mobile.platform

import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource

/** Android `actual`: the official brand lock vector drawable. */
@Composable
actual fun BaluardBrandLock(modifier: Modifier) {
    Image(
        painter = painterResource(app.baluard.mobile.shared.R.drawable.baluard_lock),
        contentDescription = null,
        modifier = modifier,
    )
}
