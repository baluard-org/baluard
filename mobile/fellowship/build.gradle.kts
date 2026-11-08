import java.util.Properties

plugins {
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.kotlinAndroid)
}

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.isFile) file.inputStream().use(::load)
}

fun fellowshipSetting(property: String, environment: String): String? =
    System.getenv(environment) ?: localProperties.getProperty(property)

val fellowshipStorePath = fellowshipSetting("fellowship.storeFile", "BALUARD_FELLOWSHIP_KEYSTORE")
val fellowshipStorePassword = fellowshipSetting("fellowship.storePassword", "BALUARD_FELLOWSHIP_STORE_PASSWORD")
val fellowshipKeyPassword = fellowshipSetting("fellowship.keyPassword", "BALUARD_FELLOWSHIP_KEY_PASSWORD")
    ?: fellowshipStorePassword
val fellowshipKeyAlias = fellowshipSetting("fellowship.keyAlias", "BALUARD_FELLOWSHIP_KEY_ALIAS") ?: "fellowship"
val fellowshipSigningConfigured = !fellowshipStorePath.isNullOrBlank() &&
    !fellowshipStorePassword.isNullOrBlank() && !fellowshipKeyPassword.isNullOrBlank()
val fellowshipStoreFile = fellowshipStorePath?.let(::file)

android {
    namespace = "app.baluard.mobile.fellowship"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.baluard.mobile.fellowship"
        minSdk = 32
        targetSdk = 36
        versionCode = 2
        versionName = "1.0.1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        create("fellowship") {
            if (fellowshipSigningConfigured) {
                storeFile = fellowshipStoreFile
                `storePassword` = fellowshipStorePassword
                keyAlias = fellowshipKeyAlias
                `keyPassword` = fellowshipKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            if (fellowshipSigningConfigured) {
                signingConfig = signingConfigs.getByName("fellowship")
            }
        }
        release {
            signingConfig = signingConfigs.getByName("fellowship")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
