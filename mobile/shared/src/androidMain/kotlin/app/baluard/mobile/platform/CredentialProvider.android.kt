package app.baluard.mobile.platform

import android.os.Build

actual val credentialProviderSupported: Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
