// Baluard mobile — Compose Multiplatform (Android + iOS)
// Phase 1 hello-world scaffold. UNTESTED-IN-THIS-ENV: this Linux container has
// no Android NDK configured end-to-end and no Xcode, so the Gradle build must
// be run on a macOS host. See docs/dev/dev-setup-mobile.md and the
// Phase 1 spike log in docs/adr/0089-mobile-apps.md.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "baluard-mobile"

include(":shared")
include(":androidApp")
