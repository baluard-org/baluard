#!/usr/bin/env bash
#
# regen-bindings.sh — regenerate the committed UniFFI Kotlin bindings.
#
# Run ONLY when the baluard-uniffi Rust API changes. The bindings are committed
# (mobile/shared/src/commonMain/kotlin/xyz/actitud/baluard/baluard_uniffi.kt) and
# in sync by default; regenerating unnecessarily churns the file.
#
# UniFFI 0.28 ships no standalone bindgen binary, so this builds a one-off runner
# in a temp dir (kept out of the repo) that calls library_mode::generate_bindings.
# See docs/mobile-dev-setup.md Step 5.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MOBILE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$MOBILE_DIR/.." && pwd)"

CRATE="$REPO_ROOT/crates/baluard-uniffi"
UNIFFI_TOML="$CRATE/src/uniffi.toml"
OUT_DIR="$MOBILE_DIR/shared/src/commonMain/kotlin"

[[ -f "$UNIFFI_TOML" ]] || { echo "ERROR: $UNIFFI_TOML missing" >&2; exit 1; }

# Self-heal stale sys-crate link paths before the host build. Homebrew
# upgrades (e.g. libgit2 1.9.6 -> 1.9.7) delete the Cellar dir that a
# *-sys build script cached as an -L search path; the next host link then
# dies with `ld: library 'git2' not found` pointing at the dead path.
# Scan build outputs for nonexistent link-search paths and clean the
# offending crate so its build script re-runs against the live prefix.
clean_stale_sys_crates() {
  local builds="$REPO_ROOT/target/release/build"
  [[ -d "$builds" ]] || return 0
  local out crate name cleaned=0
  for out in "$builds"/*/output; do
    [[ -f "$out" ]] || continue
    crate="$(basename "$(dirname "$out")")"   # e.g. libgit2-sys-8d5f5675
    [[ "$crate" == *-sys-* ]] || continue
    name="${crate%-*}"                           # e.g. libgit2-sys
    while IFS= read -r p; do
      [[ -n "$p" ]] || continue
      if [[ ! -e "$p" ]]; then
        echo "==> Stale link path '$p' in $name build output (brew upgrade?)"
        echo "    -> cargo clean -p $name"
        ( cd "$REPO_ROOT" && cargo clean -p "$name" )
        cleaned=1
        break
      fi
    done < <(grep -oE 'cargo:rustc-link-search=native=[^ ]+' "$out" 2>/dev/null \
             | sed 's/^cargo:rustc-link-search=native=//' || true)
  done
  (( cleaned )) && echo "    (build scripts will re-run on the next build)"
  return 0
}
clean_stale_sys_crates

echo "==> Building host cdylib..."
( cd "$REPO_ROOT" && cargo build -p baluard-uniffi --release )
# Pick the extension matching the host OS. A Linux target dir can carry a
# stale foreign .dylib (copied from a macOS host); picking by glob order would
# silently generate bindings from that stale artifact.
DYLIB_EXT="so"
[[ "$(uname -s)" == "Darwin" ]] && DYLIB_EXT="dylib"
DYLIB="$REPO_ROOT/target/release/libbaluard_uniffi.$DYLIB_EXT"
[[ -f "$DYLIB" ]] || { echo "ERROR: $DYLIB not built" >&2; exit 1; }

RUNNER_DIR="$(mktemp -d)/uniffi-bindgen-runner"
mkdir -p "$RUNNER_DIR/src"

cat > "$RUNNER_DIR/Cargo.toml" <<'EOF'
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
EOF

cat > "$RUNNER_DIR/src/main.rs" <<'EOF'
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
EOF

echo "==> Building bindgen runner in $RUNNER_DIR..."
( cd "$RUNNER_DIR" && cargo build --release )

echo "==> Generating Kotlin bindings -> $OUT_DIR"
"$RUNNER_DIR/target/release/uniffi-bindgen-runner" "$DYLIB" "$OUT_DIR" "$UNIFFI_TOML"

GEN="$OUT_DIR/xyz/actitud/baluard/baluard.kt"
if [[ -f "$GEN" ]]; then
  # bindgen emits baluard.kt; the committed file is baluard_uniffi.kt (matches
  # the package, not the crate). Rename to keep imports stable.
  mv "$GEN" "$OUT_DIR/xyz/actitud/baluard/baluard_uniffi.kt"
fi

echo "==> Done. Review and commit:"
echo "    $OUT_DIR/xyz/actitud/baluard/baluard_uniffi.kt"
