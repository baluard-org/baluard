# Mobile dev setup (macOS host build)

Proven end-to-end on macOS 15 (Apple Silicon) through Rust cdylib compilation and Android APK generation.
`just android-apk` produces a functional debug APK for all 4 Android ABIs.

> The earlier "Linux container proved the Rust side" note still holds; this doc
> replaces the speculative macOS steps with the ones actually run on-host.

---

## Prerequisites (macOS host)

| Tool | Version | How | Notes |
|------|---------|-----|-------|
| JDK | **17** (Temurin) | `brew install --cask temurin@17` | **Gradle 8.10 rejects JDK 26** (the default Homebrew `openjdk`). Kotlin 2.4 / AGP 8.7 run the build on JDK 17. Set `JAVA_HOME` per [Step 6](#step-6--bootstrap-gradlew-and-build-the-apk). |
| Android cmdline-tools | 14742923 | `brew install --cask android-commandlinetools` | Ships `sdkmanager`. SDK root: `/opt/homebrew/share/android-commandlinetools`. |
| Android platform-tools | 37.0.1 | `brew install --cask android-platform-tools` | Ships `adb`, `fastboot`. |
| Android SDK platform | android-35 | via `sdkmanager` (matches `compileSdk = 35`) | |
| Android build-tools | 35.0.0 | via `sdkmanager` | |
| Android NDK | r27c (`27.2.12479018`) | via `sdkmanager` | No `ndkVersion` pinned in `mobile/androidApp/build.gradle.kts`, so AGP picks a default, pin via `ANDROID_NDK_HOME`. |
| Rust | 1.85+ (MSRV) via **rustup** | see [The Rust toolchain gotcha](#gotcha-1--use-rustup-not-homebrew-rust) | **Do not rely on the Homebrew `rust` formula.** |
| Android Rust targets | `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android` | `rustup target add …` | |
| `cargo-ndk` | 4.x | `cargo install cargo-ndk` | Builds the cdylib per ABI and ships it into `jniLibs/`. |

No Android Studio install is required, the command-line tools + platform-tools
are enough for building and debugging on a physical device (via `adb`). Install
Android Studio only if you want the GUI debugger / emulator manager.

---

## Step 1: Install the Android toolchain (Homebrew)

```sh
brew install --cask android-commandlinetools android-platform-tools
```

This puts `sdkmanager`, `adb`, etc. on `PATH` and sets the SDK root to
`/opt/homebrew/share/android-commandlinetools`.

Accept licenses and install the SDK + NDK components (versions pinned to the
Gradle config: `compileSdk = 35`, AGP 8.7.0):

```sh
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export ANDROID_SDK_ROOT=$ANDROID_HOME
yes | sdkmanager --licenses >/dev/null
sdkmanager --install \
  "platform-tools" \
  "platforms;android-35" \
  "build-tools;35.0.0" \
  "ndk;27.2.12479018"
```

Verify:

```sh
sdkmanager --list_installed        # shows the four packages above
ls "$ANDROID_HOME/ndk"             # -> 27.2.12479018
```

## Step 2: Persist env vars in `~/.zshrc`

```sh
cat >> ~/.zshrc <<'EOF'

# Android SDK (Baluard mobile)
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export ANDROID_SDK_ROOT=$ANDROID_HOME
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.2.12479018
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
EOF
```

Open a new shell (or `source ~/.zshrc`) before continuing. `adb` and `sdkmanager`
must resolve, and `echo $ANDROID_NDK_HOME` must be non-empty.

## Step 3: Add the Rust Android targets and `cargo-ndk`

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cargo install cargo-ndk
```

### <a id="gotcha-1--use-rustup-not-homebrew-rust"></a>⚠️ Gotcha 1: Use rustup, not Homebrew `rust`

This machine had **two Rust installs shadowing each other**, and it silently broke
cross-compilation:

- `which cargo` → `/opt/homebrew/bin/cargo` (Homebrew `rust` formula). **No rustup,
  no `rust-std` for foreign targets.**
- `rustup` manages `~/.rustup/toolchains/stable-…` **with** the android targets, but
  the `cargo`/`rustc` shims were missing from `~/.cargo/bin`, so `cargo` on `PATH`
  fell through to the Homebrew binary.

Symptom: `rustup target add` "succeeds", but `cargo build --target aarch64-linux-android`
fails with `error[E0463]: can't find crate for core`. (Adding `~/.cargo/bin` to `PATH`
isn't enough if the proxy shims aren't there.)

**Fix (durable):** let rustup own Rust. Remove the Homebrew formula and install via
rustup so the `~/.cargo/bin` proxies exist:

```sh
brew uninstall rust            # run manually; this is a privilege-ish change
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # creates the shims
source ~/.cargo/env
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

**Fix (workaround, if you can't uninstall Homebrew rust):** force every cross-build
through the rustup toolchain explicitly:

```sh
export RUSTC="$(rustup which rustc)"   # points cargo at the toolchain rustc
rustup run stable cargo ndk …          # use the toolchain cargo, not the Homebrew one
```

`rustup run stable rustc --target aarch64-linux-android` finding `core` while plain
`cargo build --target …` failed with E0463 is the signature of this shadowing.

---

## Step 4: Build the Rust cdylib into `jniLibs`

```sh
# From repo root
export ANDROID_NDK_HOME=/opt/homebrew/share/android-commandlinetools/ndk/27.2.12479018
export RUSTC="$(rustup which rustc)"     # only needed if Gotcha 1's workaround applies

rustup run stable cargo ndk \
  -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
  -o mobile/androidApp/src/main/jniLibs \
  build -p baluard-uniffi --release
```

Output (one `.so` per ABI, ~8–13 MB):

```
mobile/androidApp/src/main/jniLibs/
├── arm64-v8a/libbaluard_uniffi.so      # 64-bit ARM, real devices
├── armeabi-v7a/libbaluard_uniffi.so    # 32-bit ARM (legacy)
├── x86_64/libbaluard_uniffi.so         # 64-bit emulators
└── x86/libbaluard_uniffi.so            # 32-bit emulators
```

For a quick single-architecture build during development (most physical devices
are `arm64-v8a`):

```sh
rustup run stable cargo ndk -t arm64-v8a -o mobile/androidApp/src/main/jniLibs build -p baluard-uniffi --release
```

### <a id="gotcha-2--openssl-must-be-vendored-for-android"></a>⚠️ Gotcha 2: OpenSSL must be vendored for Android

`baluard-uniffi` enables `git-sync` on `baluard-core` (the mobile surface uses the
autosync coordinator: `sync_on_unlock`, `sync_status`, …). That pulls `git2` →
`libgit2` → `openssl-sys`, which cannot find a system OpenSSL when cross-compiling
to Android and fails its build script with *"Could not find directory of OpenSSL
installation"*.

The fix is already in `crates/baluard-uniffi/Cargo.toml`, an **Android-only**
vendored dependency so desktop builds are untouched:

```toml
[target.'cfg(target_os = "android")'.dependencies]
# Vendored OpenSSL: lets git2/libgit2 cross-compile for Android ABIs.
openssl-sys = { version = "0.9", features = ["vendored"] }
```

`openssl-src` then builds OpenSSL from source using the NDK (needs `ANDROID_NDK_HOME`).
The first build is slow (~40 s/ABI); subsequent builds are cached.

### <a id="gotcha-3--32-bit-rlim-cast"></a>⚠️ Gotcha 3: 32-bit `rlim_t` cast

`baluard-runtime/src/host.rs` compared `(baseline as u64) * 2 >= rlim`, but `rlim`
(`libc::rlimit.rlim_cur`) is `u64` on 64-bit and `u32` on 32-bit, so the build
failed with `E0308` on `armeabi-v7a` / `x86`. Fixed by casting:

```rust
if (baseline as u64) * 2 >= rlim as u64 {
```

### ⚠️ Gotcha 4: `cdylib_name` must match the artifact

`crates/baluard-uniffi/src/uniffi.toml` originally had `cdylib_name = "baluard"`,
but the `[lib] name` is `baluard_uniffi`, so the artifact is `libbaluard_uniffi.so`.
The generated Kotlin would call `System.loadLibrary("baluard")` and hit an
`UnsatisfiedLinkError` at runtime. Fixed to:

```toml
[bindings.kotlin]
package_name = "xyz.actitud.baluard"
cdylib_name  = "baluard_uniffi"
```

### ⚠️ Gotcha 5: also build a host cdylib for bindgen

UniFFI's `library_mode` bindgen dlopens the cdylib to read `uniffi_metadata`
symbols, so it needs a **host-loadable** library (`.dylib` on macOS):

```sh
rustup run stable cargo build -p baluard-uniffi --release
# -> target/release/libbaluard_uniffi.dylib
```

---

## Step 5: Generate the UniFFI Kotlin bindings

UniFFI 0.28 **ships no standalone `uniffi-bindgen` binary** (`uniffi_bindgen` is a
library only; `uniffi-bindgen-cli` exists only in later versions). Generate via a
one-off runner that calls `library_mode::generate_bindings` (7-arg signature).

Create a throwaway project (kept out of the repo):

```sh
mkdir -p /tmp/uniffi-bindgen-runner/src
```

`/tmp/uniffi-bindgen-runner/Cargo.toml`:

```toml
[package]
name = "uniffi-bindgen-runner"
version = "0.0.0"
edition = "2021"
publish = false

[[bin]]
name = "uniffi-bindgen-runner"
path = "src/main.rs"

[dependencies]
uniffi_bindgen = "=0.28.3"
anyhow = "1"
camino = "1"
```

`/tmp/uniffi-bindgen-runner/src/main.rs`:

```rust
// Usage: uniffi-bindgen-runner <cdylib> <out_dir> <uniffi.toml>
use anyhow::{anyhow, Result};
use camino::Utf8Path;
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let library = PathBuf::from(args.next().ok_or_else(|| anyhow!("usage: <cdylib> <out_dir> <uniffi.toml>"))?);
    let out_dir  = PathBuf::from(args.next().ok_or_else(|| anyhow!("missing <out_dir>"))?);
    let config   = PathBuf::from(args.next().ok_or_else(|| anyhow!("missing <uniffi.toml>"))?);

    let library = Utf8Path::from_path(&library).ok_or_else(|| anyhow!("non-utf8 cdylib path"))?;
    let out_dir = Utf8Path::from_path(&out_dir).ok_or_else(|| anyhow!("non-utf8 out_dir"))?;
    let config  = Utf8Path::from_path(&config).ok_or_else(|| anyhow!("non-utf8 uniffi.toml path"))?;

    uniffi_bindgen::library_mode::generate_bindings(
        library,
        None,
        &uniffi_bindgen::bindings::KotlinBindingGenerator,
        &uniffi_bindgen::EmptyCrateConfigSupplier,
        Some(config),
        out_dir,
        true, // try_format_code
    )?;
    println!("bindings generated to {out_dir}");
    Ok(())
}
```

Build and run against the **host** `.dylib` (Step 5 of Gotcha 5). Output goes under
the package path so imports like `import xyz.actitud.baluard.MobileVault` resolve:

```sh
cd /tmp/uniffi-bindgen-runner && cargo build --release

./target/release/uniffi-bindgen-runner \
  <repo>/target/release/libbaluard_uniffi.dylib \
  <repo>/mobile/shared/src/commonMain/kotlin \
  <repo>/crates/baluard-uniffi/src/uniffi.toml
```

Bindgen outputs `baluard.kt`, which `regen-bindings.sh` renames to `baluard_uniffi.kt` (the committed binding at `mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/baluard_uniffi.kt`) to keep package imports stable. Commit it.

> The runner uses `uniffi_bindgen::bindings::KotlinBindingGenerator`, note the
> re-export at `bindings::`, **not** `bindings::kotlin::` (the `kotlin` submodule is
> private even though the struct is public).

---

## Step 6: Bootstrap `gradlew` and build the APK

The repo ships no Gradle wrapper. Two prerequisites first:

### <a id="gotcha-6--jdk-17-not-26"></a>⚠️ Gotcha 6: JDK 17, not 26

Gradle 8.10 (the version AGP 8.7 requires) **does not run on JDK 26** (Homebrew's
default `openjdk`), it dies with a bare `26.0.1` error. Install Temurin 17 and
point `JAVA_HOME` at it for every Gradle invocation:

```sh
brew install --cask temurin@17
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
export PATH="$JAVA_HOME/bin:$PATH"
```

(Put these in `~/.zshrc` or a project `direnv` so every shell has them.)

### ⚠️ Gotcha 7: Homebrew Gradle is 9.x; AGP 8.7 needs 8.x

`brew install gradle` gives Gradle 9.6.1, which is too new for AGP 8.7 (it fails
configuring the project). Use a one-shot Gradle 8.10 to bootstrap the pinned
wrapper, then `./gradlew` downloads 8.10 itself:

```sh
# One-time: fetch Gradle 8.10 to /tmp (Homebrew only ships latest)
curl -sSL -o /tmp/gradle-8.10-bin.zip https://services.gradle.org/distributions/gradle-8.10-bin.zip
unzip -q -o /tmp/gradle-8.10-bin.zip -d /tmp
```

### ⚠️ Gotcha 8: `kotlinOptions` is removed in Kotlin 2.4

The scaffold used the deprecated `kotlinOptions { jvmTarget = "17" }` DSL in
both `androidApp/build.gradle.kts` and `shared/build.gradle.kts`. Kotlin 2.4.10
treats it as a hard `Unresolved reference: jvmTarget`. Migrate both to:

```kotlin
kotlin {
    androidTarget {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }
}
```

### ⚠️ Gotcha 9: `local.properties` must pin `sdk.dir`

The Gradle daemon doesn't inherit `ANDROID_HOME` reliably. Create
`mobile/local.properties` (gitignored):

```sh
printf 'sdk.dir=/opt/homebrew/share/android-commandlinetools\n' > mobile/local.properties
```

### Bootstrap the wrapper and build

```sh
cd mobile
/tmp/gradle-8.10/bin/gradle wrapper --gradle-version 8.10   # generates ./gradlew
./gradlew :androidApp:assembleDebug
# -> androidApp/build/outputs/apk/debug/androidApp-debug.apk
```

Every `./gradlew` invocation needs `JAVA_HOME` set to JDK 17 (Gotcha 6).

---

## Step 7: Install and debug on a physical device

1. On the device: **Settings → About phone → tap Build number 7×** to enable
   Developer options, then **Settings → System → Developer options → enable USB
   debugging**.
2. Plug in over USB. Approve the **"Allow USB debugging?"** RSA prompt on the device.
3. Verify the host sees it:

   ```sh
   adb devices                 # must list the device, not "unauthorized"
   ```

4. Install + launch:

   ```sh
   adb install mobile/androidApp/build/outputs/apk/debug/androidApp-debug.apk
   adb shell am start -n xyz.actitud.baluard/.MainActivity
   ```

   Or via Gradle (installs + launches in one step):

   ```sh
   cd mobile && ./gradlew :androidApp:installDebug
   ```

5. Watch logs (filter to the app + Rust via `env_logger`/`android_logger`):

   ```sh
   adb logcat -v time | grep -iE "baluard|uniffi|FATAL|AndroidRuntime"
   ```

   Add `*:S` after the grep pattern to silence everything else if it's noisy.

### Rebuild-and-redeploy loop

```sh
# Rust change → rebuild the affected ABI(s) → rebuild APK → reinstall
export RUSTC="$(rustup which rustc)"
rustup run stable cargo ndk -t arm64-v8a -o mobile/androidApp/src/main/jniLibs build -p baluard-uniffi --release
cd mobile && ./gradlew :androidApp:installDebug
```

(Rust changes require re-running `cargo ndk`; Gradle alone won't rebuild the `.so`.)

---

## <a id="known-blockers"></a>Build status (first mac build 2026-07-30)

The first real `just android-apk` on macOS surfaced four failures. All four are
fixed in the same change set (verified: `cargo test -p baluard-uniffi` 7/7 green;
host cdylib + UniFFI binding regenerated and committed):

1. **`processDebugMainManifest`, manifest path.** Kotlin 2.4 KMP enforces the
   V2 source-set layout: Kotlin sources + manifest must live under `src/androidMain/`,
   not the deprecated `src/main/`. **Fixed:** moved `androidApp/src/main/{AndroidManifest.xml,kotlin}`
   to `src/androidMain/`. (Note: AGP-native assets such as `jniLibs`/`res` are NOT
   relocated by V2, they stay at the AGP default `src/main/`. A first attempt wrongly
   moved `jniLibs` too and added an explicit `jniLibs.srcDirs`, which made the same
   `.so` register twice and fail `mergeDebugJniLibFolders`; reverted, the `.so` stays
   at `src/main/jniLibs`, AGP's default, with no extra config.)
2. **`Unresolved reference 'jna' / 'Structure' / 'Pointer' / 'Library'`** in the
   generated `baluard_uniffi.kt`. UniFFI 0.28's Kotlin generator emits JNA-backed
   bindings (`com.sun.jna.*`) by design; the JNA dependency was missing.
   **Fixed:** added `implementation("net.java.dev.jna:jna:5.14.0@aar")` to
   `shared/build.gradle.kts` `androidMain.dependencies` (JNA is Android/JVM-only
   by nature, so it belongs there, not in `commonMain`; the iOS Kotlin/Native
   targets are deferred per plan §1.1 and are not compiled by `assembleDebug`).
3. **`EditCipherViewModel.kt`, `putJsonNull` unresolved + `Any` vs `JsonElement`.**
   `putJsonNull` is **not** a `kotlinx-serialization-json` API (an earlier note
   misjudged this as a non-issue; the build proved otherwise). **Fixed:** replaced
   `putJsonNull("x")` with `put("x", JsonNull)`, and made the `notes` value a
   `JsonPrimitive` to satisfy the `put(String, JsonElement)` overload.
4. **`BaluardError` `val message` hides `Throwable.message`.** UniFFI 0.28
   generates the error class extending `Exception`; a variant field literally
   named `message` collides with `Throwable.message`. **Fixed:** renamed the
   field `message` -> `detail` across `BaluardError` (4 variants, format strings,
   all `From` impls + call sites) and regenerated the binding, which now emits
   `override val message get() = ...` (correct override, no clash).
5. **`mergeDebugJniLibFolders`, duplicate `.so`.** A first attempt moved
   `jniLibs` into `src/androidMain/` and added an explicit `jniLibs.srcDirs`.
   Wrong: KMP's V2 layout relocates only Kotlin sources + manifest, NOT
   AGP-native assets (`jniLibs`/`res` stay at the AGP default `src/main/`).
   **Fixed:** `.so` stays at `src/main/jniLibs` (AGP default, where `cargo-ndk -o`
   already writes), explicit config removed, misplaced copy deleted.
6. **`BaluardAutofillService.onFillRequest`, wrong callback API.** The scaffold
   declared the callback as `OutcomeReceiver<FillResponse, Exception>` and called
   `onError`/`onResult`; the real `AutofillService.onFillRequest` takes a
   `FillCallback` with `onSuccess(FillResponse?)` / `onFailure(CharSequence)`.
   **Fixed:** corrected the override signature + the three callback call sites to
   the real `FillCallback` API. The body is still a Phase-6 TODO stub (returns an
   empty `FillResponse`); real AssistStructure parsing + KEK-gated unlock land in Phase 6.

**BUILD SUCCESSFUL (2026-07-30).** `just android-apk` produces
`mobile/androidApp/build/outputs/apk/debug/androidApp-debug.apk` (~69 MB debug;
4 ABIs x ~13 MB Rust `.so` + JNA + Compose runtime, release + ABI splits shrink
this in Phase 8).

**Binding freshness is now enforced:** `build-android-apk.sh` regenerates the
committed `baluard_uniffi.kt` automatically when `lib.rs`/`uniffi.toml` are newer
than the binding, so an API change can no longer produce a silently stale binding.

The scaffold had never been compiled end-to-end before, so further Kotlin compile
errors may still surface as the compiler advances past these four, clear them as
they appear. The Gradle 8.10 / Kotlin 2.5.0 deprecation warning is non-blocking.

## One-command build

`mobile/scripts/build-android-apk.sh` automates Steps 1–6 (SDK/NDK/JDK 17
detection, `local.properties`, the `cargo ndk` cdylib build, and `assembleDebug`).
From the repo root:

```sh
just android-apk          # build the debug APK
just android-install       # build + adb install + launch on a connected device
```

The bindings are committed and current; regenerate only after a
`baluard-uniffi` API change (`just android-bindings` or `--regen-bindings`).

---

## iOS (not yet attempted on this host)

The spike de-risked the Kotlin/Native → Obj-C → credential-extension link path on
Linux. On macOS, after installing Xcode 16+:

```sh
cd mobile
./gradlew :shared:linkDebugFrameworkIosSimulatorArm64
# -> BaluardShared.framework under shared/build/bin/...
```

Open (or create) `mobile/iosApp/Baluard.xcodeproj` in Xcode, link the framework, and
run on the iOS simulator. The `BaluardAutoFill` credential-extension target links the
same framework. The `.xcodeproj` is intentionally not scaffolded (hand-writing it is
painful); create it in Xcode and add the framework link manually.

---

## Commands cheat-sheet

```sh
# --- one-time setup ---
brew install --cask android-commandlinetools android-platform-tools
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
yes | sdkmanager --licenses >/dev/null
sdkmanager --install "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;27.2.12479018"
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cargo install cargo-ndk

# --- build cdylib (run from repo root) ---
export ANDROID_NDK_HOME=/opt/homebrew/share/android-commandlinetools/ndk/27.2.12479018
export RUSTC="$(rustup which rustc)"   # only if Homebrew rust is still installed
rustup run stable cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
  -o mobile/androidApp/src/main/jniLibs build -p baluard-uniffi --release

# --- generate Kotlin bindings (needs host .dylib) ---
rustup run stable cargo build -p baluard-uniffi --release
/tmp/uniffi-bindgen-runner/target/release/uniffi-bindgen-runner \
  target/release/libbaluard_uniffi.dylib \
  mobile/shared/src/commonMain/kotlin \
  crates/baluard-uniffi/src/uniffi.toml

# --- APK ---
cd mobile && gradle wrapper --gradle-version 8.10   # first time only
./gradlew :androidApp:assembleDebug

# --- device ---
adb install androidApp/build/outputs/apk/debug/androidApp-debug.apk
adb shell am start -n xyz.actitud.baluard/.MainActivity
adb logcat -v time | grep -iE "baluard|uniffi|FATAL|AndroidRuntime"

# --- tests ---
cargo test -p baluard-uniffi                       # Rust side
cd mobile && ./gradlew :shared:test               # KMP common tests
cd mobile && ./gradlew :androidApp:testDebugUnitTest
cd mobile && ./gradlew :androidApp:connectedAndroidTest   # instrumented, needs device
```
