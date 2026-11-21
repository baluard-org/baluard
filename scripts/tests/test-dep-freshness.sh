#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hermetic freshness check: a fixture lockfile and a stubbed crates.io.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$TMP/bin"
cp "$ROOT/scripts/dep-freshness.sh" "$SANDBOX/scripts/"

cat > "$SANDBOX/Cargo.lock" <<'EOF'
[[package]]
name = "libgit2-sys"
version = "0.18.1+1.9.0"
[[package]]
name = "git2"
version = "0.20.2"
[[package]]
name = "zip"
version = "2.6.1"
EOF

cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  case "$arg" in
    *crates.io/api/v1/crates/*)
      crate="${arg##*/crates/}"
      case "$crate" in
        libgit2-sys)  printf '{"crate":{"max_stable_version":"0.18.8+1.9.7"}}' ;;
        git2)         printf '{"crate":{"max_stable_version":"0.21.0"}}' ;;
        zip)          printf '{"crate":{"max_stable_version":"9.8.1"}}' ;;
      esac
      exit 0 ;;
  esac
done
exit 0
EOF
chmod +x "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH"

out="$(cd "$SANDBOX" && "$SANDBOX/scripts/dep-freshness.sh")"
grep -q 'libgit2-sys *0.18.1+1.9.0 *0.18.8+1.9.7 *STALE (libgit2 behind)' <<<"$out" \
  || { echo "expected libgit2-sys stale: $out" >&2; exit 1; }
grep -q 'git2 *0.20.2 *0.21.0 *STALE (0.x minor behind)' <<<"$out" \
  || { echo "expected git2 0.x-minor stale: $out" >&2; exit 1; }
grep -q 'zip *2.6.1 *9.8.1 *STALE (major behind)' <<<"$out" \
  || { echo "expected zip major stale: $out" >&2; exit 1; }

# Current crate reads ok.
out="$(cd "$SANDBOX" && "$SANDBOX/scripts/dep-freshness.sh" --)"
grep -q 'lookup failed' <<<"$out"

echo "test-dep-freshness: ok"
