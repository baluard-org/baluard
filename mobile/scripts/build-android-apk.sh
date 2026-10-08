#!/usr/bin/env bash
#
# build-android-apk.sh — produce the Baluard Android debug APK on a macOS or Linux host.
#
# One command: builds the Rust cdylib for all 4 ABIs, writes local.properties,
# runs `./gradlew :androidApp:assembleDebug`, and prints the APK path.
#
# Usage:
#   ./scripts/build-android-apk.sh            # build APK
#   ./scripts/build-android-apk.sh --install  # build + adb install on connected device
#   ./scripts/build-android-apk.sh --install --device 192.168.1.50:38507  # pick one of several
#   ./scripts/build-android-apk.sh --regen-bindings  # also regenerate UniFFI Kotlin bindings
#   ./scripts/build-android-apk.sh --skip-native     # skip cargo-ndk (use committed .so)
#
# Prereqs (the script checks and tells you the exact install command):
#   JDK 17            macOS: brew install --cask temurin@17 | Debian/Ubuntu: apt install openjdk-17-jdk
#   Android SDK       macOS: brew install --cask android-commandlinetools android-platform-tools
#                     Linux: Android Studio (installs to ~/Android/Sdk) or cmdline-tools in /opt/android-sdk
#   NDK r27c          sdkmanager "ndk;27.2.12479018"
#   Rust + targets    rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
#   cargo-ndk         cargo install cargo-ndk
#
# Prebuilt .so for all ABIs are committed; the native build is skipped with --skip-native.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MOBILE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$MOBILE_DIR/.." && pwd)"

DO_INSTALL=0
DO_REGEN_BINDINGS=0
SKIP_NATIVE=0
DO_E2E=0
DEVICE="${ANDROID_DEVICE:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)         DO_INSTALL=1; shift ;;
    --regen-bindings)  DO_REGEN_BINDINGS=1; shift ;;
    --skip-native)     SKIP_NATIVE=1; shift ;;
    --e2e)             DO_E2E=1; shift ;;   # -Pbaluard.e2e=true (skips FLAG_SECURE for Maestro)
    --device)          DEVICE="${2:?--device needs a serial}"; shift 2 ;;
    --device=*)        DEVICE="${1#--device=}"; shift ;;
    -h|--help)
      sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# ── Platform guard ──────────────────────────────────────────────────────────
case "$(uname)" in
  Darwin|Linux) ;;
  *) echo "ERROR: this script builds the Android APK on macOS or Linux. You are on $(uname)." >&2; exit 1 ;;
esac

echo "==> Baluard Android build"
echo "    repo:     $REPO_ROOT"
echo "    flags:    ${*:-none}"
echo

# ── Preflight: locate / verify every tool, fail fast with the fix ────────────
fail() { echo "ERROR: $*" >&2; exit 1; }

# JDK 17 (Gradle 8.10 / AGP 8.7 reject JDK 21+; Temurin 17 is the proven pair).
# macOS: java_home. Linux: Android Studio's ~/.jdks, distro JVMs, Homebrew openjdk@17,
# or sdkman. A JAVA_HOME already pointing at 17 wins everywhere.
JDK17_HOME=""
if [[ -n "${JAVA_HOME:-}" ]] && "$JAVA_HOME/bin/java" -version 2>&1 | grep -q '"17'; then
  JDK17_HOME="$JAVA_HOME"
elif [[ "$(uname)" == "Darwin" ]] && /usr/libexec/java_home -v 17 &>/dev/null; then
  JDK17_HOME="$(/usr/libexec/java_home -v 17)"
else
  for cand in \
    "$HOME"/.jdks/temurin-17* \
    "$HOME"/.jdks/corretto-17* \
    "$HOME"/.jdks/zulu-17* \
    /usr/lib/jvm/java-17-openjdk-* \
    /home/linuxbrew/.linuxbrew/opt/openjdk@17 \
    "$HOME"/.sdkman/candidates/java/17* ; do
    [[ -x "$cand/bin/java" ]] && JDK17_HOME="$cand" && break
  done
fi
[[ -n "$JDK17_HOME" ]] || fail "JDK 17 not found. Install: brew install --cask temurin@17 | Debian/Ubuntu: apt install openjdk-17-jdk"
echo "    JDK 17:   $JDK17_HOME"

# Android SDK root: env, then Homebrew cmdline-tools, then per-OS defaults:
#   macOS: Android Studio ~/Library/Android/sdk
#   Linux: Android Studio ~/Android/Sdk, /opt/android-sdk, distro /usr/lib/android-sdk
SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$SDK_ROOT" ]]; then
  for cand in \
    "/opt/homebrew/share/android-commandlinetools" \
    "$HOME/Library/Android/sdk" \
    "/usr/local/share/android-commandlinetools" \
    "$HOME/Android/Sdk" \
    "/opt/android-sdk" \
    "/usr/lib/android-sdk" \
    "/home/linuxbrew/.linuxbrew/share/android-commandlinetools" ; do
    [[ -d "$cand/cmdline-tools" || -d "$cand/platform-tools" ]] && SDK_ROOT="$cand" && break
  done
fi
[[ -n "$SDK_ROOT" && -d "$SDK_ROOT" ]] || fail "Android SDK not found. Install Android Studio or cmdline-tools into ~/Android/Sdk,\n       then set ANDROID_HOME or rerun."
echo "    SDK:      $SDK_ROOT"
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"

# Ensure required SDK components (platform-tools, platform-35, build-tools-35, NDK).
SDKMANAGER=""
for p in "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" "$SDK_ROOT/cmdline-tools/bin/sdkmanager"; do
  [[ -x "$p" ]] && SDKMANAGER="$p" && break
done
if [[ -n "$SDKMANAGER" ]]; then
  echo "==> Ensuring SDK components (platform-tools, android-35, build-tools;35.0.0, ndk)..."
  "$SDKMANAGER" --install "platform-tools" "platforms;android-35" "build-tools;35.0.0" >/dev/null 2>&1 || true
else
  echo "WARN: sdkmanager not found under $SDK_ROOT; skipping component check." >&2
  echo "      If the build fails on a missing platform, run:" >&2
  echo "        $SDK_ROOT/cmdline-tools/latest/bin/sdkmanager \"platforms;android-35\" \"build-tools;35.0.0\"" >&2
fi

# NDK (cargo-ndk needs ANDROID_NDK_HOME). Pick newest installed, else install r27c.
NDK_HOME="${ANDROID_NDK_HOME:-}"
if [[ -z "$NDK_HOME" && -d "$SDK_ROOT/ndk" ]]; then
  NDK_HOME="$(ls -1d "$SDK_ROOT/ndk"/*/ 2>/dev/null | tail -1)"
  NDK_HOME="${NDK_HOME%/}"
fi
if [[ -z "$NDK_HOME" || ! -d "$NDK_HOME" ]]; then
  if [[ -n "$SDKMANAGER" ]]; then
    echo "==> Installing NDK 27.2.12479018 (one-time, ~1 GB)..."
    "$SDKMANAGER" --install "ndk;27.2.12479018" >/dev/null
    NDK_HOME="$SDK_ROOT/ndk/27.2.12479018"
  else
    fail "NDK not found and sdkmanager unavailable. Set ANDROID_NDK_HOME or install NDK."
  fi
fi
export ANDROID_NDK_HOME="$NDK_HOME"
echo "    NDK:      $NDK_HOME"

# Rust + cargo-ndk (only needed when building the native cdylib).
CARGO_NDK="cargo-ndk"
if [[ $SKIP_NATIVE -eq 0 ]]; then
  # Rustup first: a Homebrew/distro rust in PATH shadows rustup and lacks the
  # Android targets (Gotcha 1; on Linux ~/.cargo/bin is often off-PATH entirely).
  [[ -d "$HOME/.cargo/bin" ]] && export PATH="$HOME/.cargo/bin:$PATH"
  command -v cargo >/dev/null  || fail "Rust not found. Install via rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  command -v "$CARGO_NDK" >/dev/null || fail "cargo-ndk not found. Install: cargo install cargo-ndk"
  echo "    cargo-ndk: $(command -v $CARGO_NDK)"
  for t in aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android; do
    if ! rustup target list --installed 2>/dev/null | grep -q "$t"; then
      echo "==> Adding Rust target $t..."
      rustup target add "$t"
    fi
  done
fi
echo

# ── Step 1: build the Rust cdylib into jniLibs (all 4 ABIs) ─────────────────
if [[ $SKIP_NATIVE -eq 1 ]]; then
  echo "==> [skip-native] using committed .so under androidApp/src/main/jniLibs/"
else
  echo "==> Building Rust cdylib for arm64-v8a armeabi-v7a x86_64 x86..."
  (
    cd "$REPO_ROOT"
    # If Homebrew's `rust` shadows rustup, force the toolchain rustc (Gotcha 1).
    if [[ -e "$HOME/.cargo/env" ]] && ! rustc --print sysroot &>/dev/null; then
      # shellcheck disable=SC1091
      source "$HOME/.cargo/env"
    fi
    export RUSTC="${RUSTC:-$(rustup which rustc 2>/dev/null || command -v rustc)}"
    cargo ndk \
      -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
      -o "$MOBILE_DIR/androidApp/src/main/jniLibs" \
      build -p baluard-uniffi --release
  )
  echo "    -> $(ls "$MOBILE_DIR"/androidApp/src/main/jniLibs/*/libbaluard_uniffi.so | wc -l | tr -d ' ') .so files present"
fi
echo

# ── Step 1b (optional): regenerate UniFFI Kotlin bindings ───────────────────
if [[ $DO_REGEN_BINDINGS -eq 1 ]]; then
  echo "==> Regenerating UniFFI Kotlin bindings..."
  "$SCRIPT_DIR/regen-bindings.sh"
  echo
fi

# ── Step 1c: auto-regenerate bindings if the Rust API drifted past the commit ─
BINDING="$MOBILE_DIR/shared/src/commonMain/kotlin/xyz/actitud/baluard/baluard_uniffi.kt"
LIB_RS="$REPO_ROOT/crates/baluard-uniffi/src/lib.rs"
UNIFFI_TOML="$REPO_ROOT/crates/baluard-uniffi/src/uniffi.toml"
if [[ ! -f "$BINDING" ]] || [[ "$LIB_RS" -nt "$BINDING" ]] || [[ "$UNIFFI_TOML" -nt "$BINDING" ]]; then
  echo "==> Rust API newer than (or missing) committed binding -> regenerating..."
  "$SCRIPT_DIR/regen-bindings.sh"
  echo
fi

# ── Step 2: write local.properties (gitignored, machine-local) ──────────────
echo "==> Writing mobile/local.properties (sdk.dir=$SDK_ROOT)"
printf 'sdk.dir=%s\n' "$SDK_ROOT" > "$MOBILE_DIR/local.properties"

# ── Step 3: Gradle assembleDebug on JDK 17 ──────────────────────────────────
export JAVA_HOME="$JDK17_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
echo "==> ./gradlew :androidApp:assembleDebug  (JAVA_HOME=$JAVA_HOME)"
GRADLE_ARGS=()
[[ $DO_E2E -eq 1 ]] && GRADLE_ARGS+=("-Pbaluard.e2e=true")
(
  cd "$MOBILE_DIR"
  ./gradlew :androidApp:assembleDebug "${GRADLE_ARGS[@]}"
)
echo

# ── Step 4: locate + report the APK ─────────────────────────────────────────
APK="$(find "$MOBILE_DIR/androidApp/build/outputs/apk/debug" -name '*.apk' 2>/dev/null | head -1 || true)"
if [[ -z "$APK" ]]; then
  fail "Gradle reported success but no debug APK found under androidApp/build/outputs/apk/debug/"
fi
echo "==> APK ready:"
echo "    $APK"
echo "    size: $(du -h "$APK" | cut -f1)"

# ── Step 5 (optional): install on a connected device ────────────────────────
if [[ $DO_INSTALL -eq 1 ]]; then
  ADB="$SDK_ROOT/platform-tools/adb"
  [[ -x "$ADB" ]] || ADB="$(command -v adb || true)"
  [[ -n "$ADB" && -x "$ADB" ]] || fail "adb not found under $SDK_ROOT/platform-tools; install android-platform-tools"

  # Resolve the target device. adb needs -s <serial> when more than one is
  # attached (common with Android 11+ wireless debugging: one manual IP:port +
  # one mDNS auto-discovered entry for the SAME phone). Never guess.
  DEVS=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && DEVS+=("$line")
  done < <("$ADB" devices | awk '$2=="device"{print $1}')

  if [[ -n "$DEVICE" ]]; then
    SERIAL="$DEVICE"
  elif [[ ${#DEVS[@]} -eq 1 ]]; then
    SERIAL="${DEVS[0]}"
  elif [[ ${#DEVS[@]} -eq 0 ]]; then
    fail "No device attached. Connect one: adb connect <ip:port>  (or pair via Wireless debugging)."
  else
    echo "Multiple devices attached — pick one with --device <serial> or ANDROID_DEVICE=<serial>:" >&2
    printf '  %s\n' "${DEVS[@]}" >&2
    fail "ambiguous device target"
  fi
  ADBS=( "$ADB" -s "$SERIAL" )

  # Phase 2 (docs/e2e-testing.md): a freshly connected wireless device can
  # still be mid-boot; installing before sys.boot_completed fails.
  BOOTED="$("${ADBS[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
  WAITED=0
  while [[ "$BOOTED" != "1" ]]; do
    WAITED=$((WAITED + 5))
    [[ $WAITED -ge 120 ]] && fail "device $SERIAL not booted after 120s (sys.boot_completed != 1)"
    sleep 5
    BOOTED="$("${ADBS[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
  done

  echo
  echo "==> ${ADBS[*]} install -r $APK"
  "${ADBS[@]}" install -r "$APK"
  echo "==> Launch: ${ADBS[*]} shell am start -n xyz.actitud.baluard/.MainActivity"
  "${ADBS[@]}" shell am start -n xyz.actitud.baluard/.MainActivity
fi
