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
}
