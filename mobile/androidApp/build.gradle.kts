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
            // The E2E root Box (testTagsAsResourceId) needs foundation
            // layout directly; :shared's compose deps are not exported.
            implementation(compose.foundation)
            implementation(libs.androidx.activity.compose)
            // MainActivity is a FragmentActivity host for BiometricPrompt (B5).
            implementation("androidx.fragment:fragment-ktx:1.6.2")
            // Autofill service/activity (:autofill process) call uniffi suspend
            // fns and BiometricPrompt directly; same versions as :shared.
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
            implementation("net.java.dev.jna:jna:5.14.0@aar")
            // Inline autofill chips (InlineSuggestionUi) for the
            // "Display autofill suggestions: Inline" option (plan 2b/S2).
            implementation("androidx.autofill:autofill:1.1.0")
            // Credential provider surface (G10): the line Bitwarden pins;
            // BiometricPromptData and the provider APIs need 1.5+, not 1.3.x.
            implementation("androidx.credentials:credentials:1.6.0")
        }
    }
}

android {
    namespace = "xyz.actitud.baluard"
    compileSdk = 35
    // BuildConfig carries the E2E gate: `-Pbaluard.e2e=true` produces a
    // build that skips FLAG_SECURE so Maestro can screenshot (E12,
    // docs/e2e-testing.md). Normal debug/release builds never see it.
    buildFeatures {
        buildConfig = true
    }
    // Pinned: AGP 8.7's default (26.0.2.1) is absent on this machine; 27.2 is installed.
    ndkVersion = "27.2.12479018"


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
            // E2E gate lives on debug ONLY: no release variant can ever
            // ship with FLAG_SECURE skipped, whatever flags the build
            // was invoked with (fail secure).
            buildConfigField(
                "boolean",
                "BALUARD_E2E",
                ((project.findProperty("baluard.e2e") as? String) == "true").toString(),
            )
        }
        release {
            // Alpha: debug-keystore-signed release so local A/B testing
            // (debug vs release ART/Compose perf) can adb install -r over
            // the same applicationId. Store signing lands at store time.
            signingConfig = signingConfigs.getByName("baluardDebug")
            // The E2E gate exists in both build types (the shared flag
            // readers compile against both), but release is pinned false
            // so no release build can ever ship the FLAG_SECURE skip.
            buildConfigField("boolean", "BALUARD_E2E", "false")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}
