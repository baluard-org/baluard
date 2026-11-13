import java.net.URI

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

val entitlementServiceUrl = (findProperty("baluard.entitlementServiceUrl") as String?)
    ?: System.getenv("BALUARD_ENTITLEMENT_SERVICE_URL").orEmpty()
val fellowshipUploadCertificateSha256 = "392514C7E4B6C83FBA25D01E301693A4471CF3C3EB05ED97EA3267CFFC5A2CB3"
val fellowshipPlayCertificatesSha256 = (findProperty("baluard.fellowshipPlayCertificatesSha256") as String?)
    ?: System.getenv("BALUARD_FELLOWSHIP_PLAY_CERTIFICATES_SHA256").orEmpty().ifBlank {
        "1856707D5517FF046FC76E780C63585FA62ECA8FE4BE53B0FE705E6E2BFC4D31"
    }
val fellowshipCertificatesSha256 = listOf(fellowshipUploadCertificateSha256, fellowshipPlayCertificatesSha256)
    .filter(String::isNotBlank)
    .joinToString(",")

android {
    val releaseStorePath = System.getenv("BALUARD_ANDROID_KEYSTORE")
        ?: "${System.getProperty("user.home")}/.baluard/baluard-android-upload.keystore"
    val releaseStorePassword = System.getenv("BALUARD_ANDROID_STORE_PASSWORD")
    val releaseKeyPassword = System.getenv("BALUARD_ANDROID_KEY_PASSWORD") ?: releaseStorePassword
    val releaseStoreFile = file(releaseStorePath)

    namespace = "app.baluard.mobile"
    compileSdk = 36
    // BuildConfig carries the E2E gate: `-Pbaluard.e2e=true` produces a
    // build that skips FLAG_SECURE so Maestro can screenshot (E12).
    // Normal debug/release builds never see it.
    buildFeatures {
        buildConfig = true
    }
    // Pinned: AGP 8.7's default (26.0.2.1) is absent on this machine; 27.2 is installed.
    ndkVersion = "27.2.12479018"


    defaultConfig {
        applicationId = "app.baluard.mobile"
        minSdk = 32
        targetSdk = 36
        versionCode = 5002
        versionName = "0.5.2"
        // Package only ABIs we ship a cdylib for. Alpha default: arm64-v8a
        // (every test phone since ~2016). Also strips the JNA aar's other-ABI
        // .so, which would otherwise let a 32-bit device load libjnidispatch
        // and then fail on the missing libbaluard_uniffi.
        // Multi-ABI build: ./gradlew -Pbaluard.abis=arm64-v8a,x86_64 :androidApp:assembleDebug
        ndk {
            // clear() first: abiFilters restores stale entries from the gradle
            // configuration cache, and += then merges old ABIs back in.
            abiFilters.clear()
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
        create("baluardRelease") {
            storeFile = releaseStoreFile
            storePassword = releaseStorePassword
            keyAlias = System.getenv("BALUARD_ANDROID_KEY_ALIAS") ?: "baluard-upload"
            keyPassword = releaseKeyPassword
        }
    }

    // Fail on the signing validation task, which runs only in release
    // builds and BEFORE any signing: a doFirst on assemble/bundle fires
    // after validate+sign have already executed. With flavors the tasks are
    // validateSigningFdroidRelease / validateSigningPlayRelease (empirical
    // names; the signing-config segment disappears once flavors exist).
    tasks.matching {
        it.name.startsWith("validateSigning") && it.name.endsWith("Release")
    }.configureEach {
        doFirst {
            require(releaseStoreFile.isFile) {
                "Android release keystore not found. Run just android-release-key, then rerun."
            }
            require(!releaseStorePassword.isNullOrEmpty() && !releaseKeyPassword.isNullOrEmpty()) {
                "Set BALUARD_ANDROID_STORE_PASSWORD and BALUARD_ANDROID_KEY_PASSWORD for release signing."
            }
        }
    }

    // Store vs free split (ADR 0102): play carries Google Play Billing and gates
    // sync/sharing/TOTP generation; fdroid ships ungated with no billing code in the
    // package (F-Droid policy forbids the proprietary library). Same applicationId,
    // signing key, and versionCode on both.
    flavorDimensions += "monetization"
    productFlavors {
        create("fdroid") { dimension = "monetization" }
        create("play") {
            dimension = "monetization"
            val escapedUrl = entitlementServiceUrl.replace("\\", "\\\\").replace("\"", "\\\"")
            buildConfigField("String", "ENTITLEMENT_SERVICE_URL", "\"$escapedUrl\"")
            // Comma-separated upload + Play signing pins; every hybrid signer must be pinned.
            val escapedFellowshipPins = fellowshipCertificatesSha256.replace("\\", "\\\\").replace("\"", "\\\"")
            buildConfigField(
                "String",
                "FELLOWSHIP_CERTIFICATES_SHA256",
                "\"$escapedFellowshipPins\"",
            )
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
            signingConfig = signingConfigs.getByName("baluardRelease")
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

tasks.matching { it.name == "prePlayReleaseBuild" }.configureEach {
    val serviceUrl = entitlementServiceUrl
    val playPins = fellowshipPlayCertificatesSha256
    val allPins = fellowshipCertificatesSha256
    doLast {
        if (serviceUrl.isBlank()) {
            throw GradleException("Play release requires baluard.entitlementServiceUrl")
        }
        val uri = runCatching { URI(serviceUrl) }.getOrElse { error ->
            throw GradleException("Play release entitlement URL is invalid", error)
        }
        if (uri.scheme != "https" || uri.host.isNullOrBlank() ||
            uri.userInfo != null || uri.query != null || uri.fragment != null
        ) {
            throw GradleException("Play release entitlement URL must be an HTTPS origin without user info, query, or fragment")
        }
        val sha256 = Regex("[0-9a-fA-F]{64}")
        if (playPins.isBlank() || playPins.split(",").map(String::trim).any { !sha256.matches(it) }) {
            throw GradleException(
                "Play release requires baluard.fellowshipPlayCertificatesSha256 with valid Play app-signing pins",
            )
        }
        if (allPins.split(",").map(String::trim).any { !sha256.matches(it) }) {
            throw GradleException("Play release Fellowship pin list is malformed")
        }
    }
}

dependencies {
    // Google Play Billing, play flavor only: the fdroid APK must not carry the
    // proprietary library (F-Droid policy, ADR 0102).
    "playImplementation"("com.android.billingclient:billing-ktx:9.1.0")
    "playImplementation"("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    "testImplementation"("junit:junit:4.13.2")
    "testImplementation"("org.json:json:20240303")
    "testImplementation"("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}
