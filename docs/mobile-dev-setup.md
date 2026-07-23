# Mobile dev setup (host build)

This Linux container proved the Rust side of the Phase 1 toolchain (see the spike log in `docs/plan-mobile-apps.md`). The Gradle/Kotlin scaffold under `mobile/` is **untested blind code** — it must be compiled on a macOS host with the tooling below.

## Prerequisites (macOS host)

| Tool | Version | Notes |
|------|---------|-------|
| Xcode | 16+ | For the iOS target + the credential-extension link path (the least-traveled piece the spike de-risks). |
| Android Studio | latest | Installs Android SDK + NDK. Set `ANDROID_HOME` + `ANDROID_NDK_HOME`. |
| Rust | 1.85+ (MSRV) | `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android aarch64-apple-ios aarch64-apple-ios-sim` |
| JDK | 17+ | Kotlin 2.4 compiles to JVM 17 target. |
| `cargo-ndk` | latest | `cargo install cargo-ndk` — builds the Rust cdylib for Android ABIs and ships the `.so` into `jniLibs/`. |

## Build steps

### 1. Build the Rust cdylib for Android

```sh
# From repo root. Produces target/<abi>/release/libbaluard_uniffi.so per ABI.
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 -o mobile/androidApp/src/main/jniLibs build -p baluard-uniffi --release
```

Copy the `.so` files into `mobile/androidApp/src/main/jniLibs/<abi>/` (cargo-ndk's `-o` does this).

### 2. Generate the UniFFI Kotlin bindings

UniFFI 0.28 has no standalone `uniffi-bindgen` binary. Build a one-off runner:

```sh
# One-time: create a throwaway cargo project that depends on uniffi_bindgen 0.28
# and calls library_mode::generate_bindings (7-arg signature — see spike log).
# Output: mobile/shared/src/commonMain/kotlin/generated/baluard.kt
```

The generated file defines `package xyz.actitud.baluard` with `generateRecoveryPhrase()`, `deriveKek(...)`, `mobileVersion()`, and `data class MobileRecoveryPhrase`. Commit it.

### 3. Build the Android APK

```sh
cd mobile
./gradlew :androidApp:assembleDebug
# Output: androidApp/build/outputs/apk/debug/androidApp-debug.apk
```

Install on a device/emulator and launch "Baluard". Tapping "Generate recovery phrase" should render a 24-word BIP-39 string from Rust.

### 4. Build the iOS app + link the extension (the real de-risk)

```sh
cd mobile
./gradlew :shared:linkDebugFrameworkIosSimulatorArm64
# Produces BaluardShared.framework under shared/build/bin/...
```

Open `mobile/iosApp/Baluard.xcodeproj` (create it in Xcode if absent — the scaffold ships only sources, not the `.xcodeproj`), link the framework, and run on the iOS simulator.

The credential-extension target (`BaluardAutoFill`) links the SAME framework. Getting it to build is the spike's true goal — it's the Kotlin/Native → Obj-C → iOS-ext path Mozilla uses but few others exercise.

## What the scaffold contains

```
mobile/
├── settings.gradle.kts          # KMP project root (shared + androidApp)
├── build.gradle.kts             # plugin aliases
├── gradle.properties
├── gradle/libs.versions.toml    # version catalog
├── shared/                      # KMP module
│   ├── build.gradle.kts         # androidTarget + iosX64/Arm64/SimArm64
│   └── src/
│       ├── commonMain/kotlin/xyz/actitud/baluard/
│       │   ├── ui/App.kt        # Compose hello-world screen
│       │   ├── data/VaultRepository.kt  # wraps UniFFI bindings
│       │   └── generated/       # UniFFI-generated baluard.kt (run bindgen, then commit)
│       ├── androidMain/         # (Phase 2+: platform actuals)
│       └── iosMain/kotlin/.../MainViewController.kt  # ComposeUIViewController host
└── androidApp/                  # Android shell
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        └── kotlin/.../MainActivity.kt  # single-Activity Compose host
```

## Known gaps (intentionally deferred)

- **`iosApp/Baluard.xcodeproj`** not scaffolded — Xcode projects are painful to hand-write; create in Xcode and add the framework link manually.
- **UniFFI bindgen runner** not committed — 0.28's API needs a `BindgenCrateConfigSupplier` impl. Build the runner locally per the spike log.
- **No password generator** in Rust (plan §3.3 assumed reuse; it lives in desktop JS). Phase 4 ports it.
- **Autofill / credential extension** deferred to Phase 6/7.
