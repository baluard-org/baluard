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
            // MainActivity is a FragmentActivity host for BiometricPrompt (B5).
            implementation("androidx.fragment:fragment-ktx:1.6.2")
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

        // Package only ABIs we ship a cdylib for. Alpha default: arm64-v8a
        // (every test phone since ~2016). Also strips the JNA aar's other-ABI
        // .so, which would otherwise let a 32-bit device load libjnidispatch
        // and then fail on the missing libbaluard_uniffi.
        // Multi-ABI build: ./gradlew -Pbaluard.abis=arm64-v8a,x86_64 :androidApp:assembleDebug
        ndk {
            abiFilters += (findProperty("baluard.abis") as String? ?: "arm64-v8a")
                .split(",").map(String::trim)
        }
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
        release {
            // Alpha: debug-keystore-signed release so local A/B testing
            // (debug vs release ART/Compose perf) can adb install -r over
            // the same applicationId. Store signing lands at store time.
            signingConfig = signingConfigs.getByName("baluardDebug")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}
