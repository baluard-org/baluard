plugins {
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.composeMultiplatform)
    alias(libs.plugins.composeCompiler)
    alias(libs.plugins.kotlinMultiplatform)
}

kotlin {
    androidTarget {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    sourceSets {
        androidMain.dependencies {
            implementation(project(":shared"))
            implementation(libs.androidx.activity.compose)
        }
    }
}

android {
    namespace = "xyz.actitud.baluard"
    compileSdk = 35

    defaultConfig {
        applicationId = "xyz.actitud.baluard"
        minSdk = 32
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        // Project debug keystore (mobile/keystore/debug.keystore, alias/store/key
        // password "baluard"). CI restores it from the BALUARD_DEBUG_KEYSTORE_B64
        // secret; locally it is git-ignored. Stable signature across builds so
        // `adb install -r` never fails on a changed key.
        create("baluardDebug") {
            storeFile = rootProject.file("keystore/debug.keystore")
            storePassword = "baluard"
            keyAlias = "baluard"
            keyPassword = "baluard"
        }
    }

    buildTypes {
        debug {
            signingConfig = signingConfigs.getByName("baluardDebug")
        }
    }
}
