#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Run the Windows packaging script against a sandbox copy of the repo so the
# real worktree, its tauri.conf.json, and its cargo/npm are never touched.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$SANDBOX/desktop/src-tauri" "$TMP/bin"
cp "$ROOT/scripts/build-windows-installer.sh" "$SANDBOX/scripts/"
cp "$ROOT/desktop/src-tauri/tauri.conf.json" "$SANDBOX/desktop/src-tauri/"

# The recipe runs from the repo root; give the sandbox the shape it expects.
mkdir -p "$SANDBOX/desktop"

# Fake tools: record argv, honor failure knobs. `cargo xwin` is how the
# script drives the cross-compile, and cargo-xwin is a cargo subcommand, so
# the fake `cargo` must dispatch `xwin` to the fake `cargo-xwin`.
make_shim() {
  local tool="$1" var="$2"
  cat > "$TMP/bin/$tool" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "$tool" == "cargo" && "\${1:-}" == "xwin" ]]; then
  printf '%s\n' "\$*" >> "\${$var:?}"
  shift
  exec "$TMP/bin/cargo-xwin" "\$@"
fi
printf '%s\n' "\$*" >> "\${$var:?}"
[[ "$tool" == "cargo-xwin" && -f "\$SANDBOX/.xwin-fail" ]] && exit 1
if [[ "$tool" == "cargo-xwin" ]]; then
  mkdir -p "\$SANDBOX/target/x86_64-pc-windows-msvc/release"
  : > "\$SANDBOX/target/x86_64-pc-windows-msvc/release/baluard-daemon.exe"
  : > "\$SANDBOX/target/x86_64-pc-windows-msvc/release/baluard.exe"
fi
exit 0
EOF
  chmod +x "$TMP/bin/$tool"
}
make_shim cargo CARGO_LOG
make_shim cargo-xwin CARGOXWIN_LOG
make_shim npm NPM_LOG
make_shim makensis MAKENSIS_LOG
make_shim clang CLANG_LOG
make_shim lld LLD_LOG
make_shim llvm-rc LLVMRC_LOG
# rustc only needs to answer the target-sysroot probe.
cat > "$TMP/bin/rustc" <<EOF
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TMP/bin/rustc"
export PATH="$TMP/bin:$PATH"
export SANDBOX
export CARGO_LOG="$TMP/cargo.log" \
  CARGOXWIN_LOG="$TMP/cargo-xwin.log" NPM_LOG="$TMP/npm.log" MAKENSIS_LOG="$TMP/makensis.log"

run_build() {
  (cd "$SANDBOX" && ./scripts/build-windows-installer.sh)
}

# ── Happy path: sidecars cross-compiled, tauri builds nsis ──────────────────
run_build > "$TMP/happy.out"
grep -q 'windows installer:' "$TMP/happy.out"

# sidecars land at the target-triple names Tauri looks for.
for bin in baluard-daemon baluard; do
  test -f "$SANDBOX/desktop/src-tauri/binaries/$bin-x86_64-pc-windows-msvc.exe"
done

# cargo received and forwarded the xwin subcommand.
grep -q '^xwin build' "$TMP/cargo.log"

# cargo-xwin built the two crates for the windows target.
grep -q -- '--target x86_64-pc-windows-msvc' "$TMP/cargo-xwin.log"
grep -q -- '-p baluard-daemon' "$TMP/cargo-xwin.log"
grep -q -- '-p baluard-cli' "$TMP/cargo-xwin.log"

# tauri build ran with the nsis bundle, the windows target, and the xwin runner.
grep -q 'tauri build' "$TMP/npm.log"
grep -q -- '--bundles nsis' "$TMP/npm.log"
grep -q -- '--target x86_64-pc-windows-msvc' "$TMP/npm.log"
grep -q -- '--runner cargo-xwin' "$TMP/npm.log"

# ── Scoped targets: no msi in the config ─────────────────────────────────────
if grep -q '"msi"' "$SANDBOX/desktop/src-tauri/tauri.conf.json"; then
  echo 'tauri.conf.json still references msi' >&2
  exit 1
fi

# ── Cross-compile failure fails the run before tauri build ──────────────────
rm -f "$SANDBOX/desktop/src-tauri/binaries/"*.exe
: > "$TMP/npm.log"
touch "$SANDBOX/.xwin-fail"
if run_build > /dev/null 2> "$TMP/xfail.err"; then
  echo 'expected cargo-xwin failure to fail the run' >&2
  exit 1
fi
rm -f "$SANDBOX/.xwin-fail"
grep -qi 'cargo-xwin' "$TMP/xfail.err"
# tauri build never ran.
if [[ -s "$TMP/npm.log" ]]; then
  echo 'tauri build ran despite cargo-xwin failure' >&2
  exit 1
fi

# ── Re-run cross-compiles again (the build is intentionally unconditional) ──
rm -f "$TMP/cargo-xwin.log"
run_build > /dev/null
grep -q -- '--target x86_64-pc-windows-msvc' "$TMP/cargo-xwin.log"
test -f "$SANDBOX/desktop/src-tauri/binaries/baluard-x86_64-pc-windows-msvc.exe"

printf 'PASS: build-windows-installer.sh\n'
