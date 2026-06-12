plugins {
    kotlin("multiplatform") version "1.9.20"
    id("com.android.library") version "8.1.0"
}

kotlin {
    androidTarget()
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                // Compose Multiplatform / KMP dependencies go here
            }
        }
    }
}

android {
    namespace = "xyz.actitud.baluard"
    compileSdk = 34
}
