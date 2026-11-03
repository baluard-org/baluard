package app.baluard.mobile.platform

import platform.UIKit.UIDevice

/**
 * iOS `actual`: the user-named device ("Esteban's iPhone"). Unverified
 * until the iOS host build (plan §1.1) — kept alongside the other
 * iOS stubs.
 */
actual fun deviceDisplayName(): String {
    val name = UIDevice.currentDevice.name
    return name?.trim().orEmpty()
}
