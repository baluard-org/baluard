#!/usr/bin/env bash
#
# build-android-apk.sh — produce Baluard Android debug or release packages on macOS or Linux.
#
# One command: builds the Rust cdylib for all 4 ABIs, writes local.properties,
# runs the gradle assemble for the chosen flavor, and prints the APK path.
#
# Usage:
#   ./scripts/build-android-apk.sh --release # signed release APK + Play AAB
#   ./scripts/build-android-apk.sh --install  # build + adb install on connected device
#   ./scripts/build-android-apk.sh --install --device 192.168.1.50:38507  # pick one of several
#   ./scripts/build-android-apk.sh --regen-bindings  # also regenerate UniFFI Kotlin bindings
#   ./scripts/build-android-apk.sh --skip-native     # skip cargo-ndk (use committed .so)
#   ./scripts/build-android-apk.sh --abis arm64-v8a  # build+pack only these ABIs
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
DO_RELEASE=0
ABIS="${ABIS:-arm64-v8a,armeabi-v7a,x86_64,x86}"
DEVICE="${ANDROID_DEVICE:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)         DO_INSTALL=1; shift ;;
    --regen-bindings)  DO_REGEN_BINDINGS=1; shift ;;
    --skip-native)     SKIP_NATIVE=1; shift ;;
    --e2e)             DO_E2E=1; shift ;;   # -Pbaluard.e2e=true (skips FLAG_SECURE for Maestro)
    --release)         DO_RELEASE=1; shift ;;
    --abis)            ABIS="${2:?--abis needs a comma-separated list}"; shift 2 ;;
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
  # cargo-ndk accepts the ABI names directly; the gradle abiFilters below
  # pack only the ABIs listed here, so gating both on one list keeps the
  # jniLibs tree and the APK in sync.
  echo "==> Building Rust cdylib for $ABIS..."
  (
    cd "$REPO_ROOT"
    # If Homebrew's `rust` shadows rustup, force the toolchain rustc (Gotcha 1).
    if [[ -e "$HOME/.cargo/env" ]] && ! rustc --print sysroot &>/dev/null; then
      # shellcheck disable=SC1091
      source "$HOME/.cargo/env"
    fi
    export RUSTC="${RUSTC:-$(rustup which rustc 2>/dev/null || command -v rustc)}"
    ndk_targets=()
    IFS=',' read -r -a abi_list <<< "$ABIS"
    for abi in "${abi_list[@]}"; do
      ndk_targets+=(-t "$(echo "$abi" | tr -d '[:space:]')")
    done
    cargo ndk "${ndk_targets[@]}" \
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

# ── Step 3: Gradle assemble on JDK 17 ─────────────────────────────────────
export JAVA_HOME="$JDK17_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
if [[ $DO_RELEASE -eq 1 ]]; then
  [[ $DO_E2E -eq 0 ]] || fail "--e2e is debug-only and cannot be combined with --release"
  # The fdroid APK ships to F-Droid; the play AAB is the Play upload vehicle
  # (bundlePlayRelease covers the play side; the play APK is not built).
  GRADLE_TASKS=(":androidApp:assembleFdroidRelease" ":androidApp:bundlePlayRelease")
else
  # Dev installs default to the fdroid flavor; BALUARD_ANDROID_FLAVOR=play for store-flavor dev testing.
  FLAVOR="${BALUARD_ANDROID_FLAVOR:-fdroid}"
  case "$FLAVOR" in
    fdroid) FLAVOR_CAP=Fdroid ;;
    play) FLAVOR_CAP=Play ;;
    *) fail "BALUARD_ANDROID_FLAVOR must be fdroid or play (got: $FLAVOR)" ;;
  esac
  GRADLE_TASKS=(":androidApp:assemble${FLAVOR_CAP}Debug")
fi
echo "==> ./gradlew ${GRADLE_TASKS[*]}  (JAVA_HOME=$JAVA_HOME)"
GRADLE_ARGS=()
[[ $DO_E2E -eq 1 ]] && GRADLE_ARGS+=("-Pbaluard.e2e=true")
[[ -n "${ABIS:-}" ]] && GRADLE_ARGS+=("-Pbaluard.abis=$ABIS")
(
  cd "$MOBILE_DIR"
  ./gradlew "${GRADLE_TASKS[@]}" "${GRADLE_ARGS[@]}"
)
echo

# ── Step 4: locate + report the packages ────────────────────────────────────
if [[ $DO_RELEASE -eq 1 ]]; then
  APK="$(find "$MOBILE_DIR/androidApp/build/outputs/apk/fdroid/release" -name '*.apk' 2>/dev/null | head -1 || true)"
  AAB="$(find "$MOBILE_DIR/androidApp/build/outputs/bundle/play/release" -name '*.aab' 2>/dev/null | head -1 || true)"
  [[ -n "$APK" && -n "$AAB" ]] || fail "Gradle reported success but the release APK or AAB is missing"
  # A release APK with a broken signature must not reach fdroid-stage or
  # Play. build-tools ships apksigner; verify before reporting success.
APKSIGNER="$(find "$SDK_ROOT/build-tools" -name apksigner -type f 2>/dev/null | sort -V | tail -1 || true)"
  [[ -n "$APKSIGNER" ]] || fail "apksigner not found under $SDK_ROOT/build-tools; cannot verify the release signature"
  # The billing dex gate below needs unzip; failing open there would ship
  # billing classes in the fdroid APK (ADR 0102).
  command -v unzip >/dev/null 2>&1 || fail "unzip not found on PATH; cannot run the fdroid billing gate"
  echo "==> apksigner verify (release APK)"
  "$APKSIGNER" verify --print-certs "$APK" | sed -n '1,2p'
  # ADR 0102 hard gate: the fdroid APK must never carry Google billing
  # classes. Grep the dex string pool for the package descriptor. Count form:
  # grep -q stops reading at the first match, unzip dies on SIGPIPE, and
  # pipefail flips the matched pipeline into failure - the gate would pass in
  # exactly the case it exists to catch.
  BILLING_HITS="$(unzip -p "$APK" 'classes*.dex' 2>/dev/null | grep -ac 'com/android/billingclient' || true)"
  if [[ "${BILLING_HITS:-0}" -gt 0 ]]; then
    fail "billing classes found in the fdroid APK; the play/fdroid split is broken (ADR 0102)"
  fi
  echo "==> F-Droid release APK ready: $APK"
  echo "==> Play AAB ready:            $AAB"
else
  FLAVOR="${BALUARD_ANDROID_FLAVOR:-fdroid}"
  APK="$(find "$MOBILE_DIR/androidApp/build/outputs/apk/$FLAVOR/debug" -name '*.apk' 2>/dev/null | head -1 || true)"
  if [[ -z "$APK" ]]; then
    fail "Gradle reported success but no debug APK found under androidApp/build/outputs/apk/$FLAVOR/debug/"
  fi
  echo "==> APK ready:"
  echo "    $APK"
fi
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

  # Phase 2: a freshly connected wireless device can
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
  echo "==> Launch: ${ADBS[*]} shell am start -n app.baluard.mobile/.MainActivity"
  "${ADBS[@]}" shell am start -n app.baluard.mobile/.MainActivity
fi
