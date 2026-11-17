#!/usr/bin/env bash
# Hermetic tests for scripts/sign-release-artifacts.sh (release signing).
# Pattern: temp sandbox, the script under test copied into the sandbox's
# scripts/ dir, fake npx shim first on PATH, hermetic updater key,
# assertions on the signed set, then a PASS line.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

BIN="$TMP/bin"
mkdir -p "$BIN" "$TMP/scripts" "$TMP/dist"
cp "$SCRIPT_DIR/../sign-release-artifacts.sh" "$TMP/scripts/"
cat > "$BIN/npx" <<'EOF'
#!/usr/bin/env bash
# `npx --yes @tauri-apps/cli@X signer sign FILE` -> write FILE.sig
if [[ "${4:-}" == "sign" && -n "${5:-}" ]]; then
  printf -- "--- FAKE SIG: %s\n" "$5" > "$5.sig"
fi
exit 0
EOF
chmod +x "$BIN/npx"

# Hermetic key: the script cats this file into TAURI_SIGNING_PRIVATE_KEY.
printf 'fake-updater-key\n' > "$TMP/fake-updater-key"
export BALUARD_UPDATER_KEY="$TMP/fake-updater-key"
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD

cat > "$TMP/Cargo.toml" <<'EOF'
[workspace.package]
version = "0.7.3"
edition = "2024"
EOF

seed_good_dist() {
  : > "$TMP/dist/Baluard_0.7.3_amd64.deb"
  : > "$TMP/dist/Baluard-0.7.3-1.x86_64.rpm"
  : > "$TMP/dist/Baluard_0.7.3_amd64.AppImage"
  : > "$TMP/dist/Baluard_0.7.3_x64-setup.exe"
  : > "$TMP/dist/baluard-0.7.3-linux-amd64.tar.gz"
  : > "$TMP/dist/checksums.txt"
}

# 1. A version-clean dist signs everything, tolerates versionless files.
seed_good_dist
out="$(PATH="$BIN:$PATH" "$TMP/scripts/sign-release-artifacts.sh" "$TMP/dist" 2>&1)"
grep -q "Baluard_0.7.3_amd64.deb" "$TMP/dist/SHA256SUMS" || fail "SHA256SUMS misses the deb"
[[ $(grep -c . "$TMP/dist/SHA256SUMS") -eq 5 ]] || fail "SHA256SUMS should list the 5 artifacts, got $(grep -c . "$TMP/dist/SHA256SUMS")"
[[ -f "$TMP/dist/SHA256SUMS.sig" ]] || fail "SHA256SUMS left unsigned"
[[ -f "$TMP/dist/Baluard_0.7.3_amd64.deb.sig" ]] || fail "deb left unsigned"
[[ -f "$TMP/dist/checksums.txt" ]] || fail "versionless file must survive signing"
echo "ok 1: clean dist signs fully and keeps versionless files"

# 2. A stale artifact refuses before any signature is written.
rm -rf "$TMP/dist"; mkdir -p "$TMP/dist"
seed_good_dist
: > "$TMP/dist/Baluard_0.7.2_amd64.deb"
rc=0
out="$(PATH="$BIN:$PATH" "$TMP/scripts/sign-release-artifacts.sh" "$TMP/dist" 2>&1)" || rc=$?
[[ $rc -ne 0 ]] || fail "stale artifact must fail the run"
grep -q "0.7.3" <<<"$out" || fail "refusal must name the workspace version"
[[ -f "$TMP/dist/Baluard_0.7.3_amd64.deb.sig" ]] && fail "gate must fire before signing starts"
[[ -f "$TMP/dist/SHA256SUMS" ]] && fail "SHA256SUMS must not be written on refusal"
echo "ok 2: stale artifact refuses pre-signing"

# 3. A stale .sig sidecar alone refuses: the scan covers the whole top level.
rm -rf "$TMP/dist"; mkdir -p "$TMP/dist"
seed_good_dist
: > "$TMP/dist/Baluard_9.9.9_amd64.deb.sig"
rc=0
out="$(PATH="$BIN:$PATH" "$TMP/scripts/sign-release-artifacts.sh" "$TMP/dist" 2>&1)" || rc=$?
[[ $rc -ne 0 ]] || fail "stale sidecar must fail the run"
grep -q "Baluard_9.9.9_amd64.deb.sig" <<<"$out" || fail "refusal must name the stale file"
echo "ok 3: stale sidecar refuses"

# 4. archive-* subtrees are recovery storage, never scanned.
rm -rf "$TMP/dist"; mkdir -p "$TMP/dist/archive-0.7.2"
seed_good_dist
: > "$TMP/dist/archive-0.7.2/Baluard_0.7.2_amd64.deb"
PATH="$BIN:$PATH" "$TMP/scripts/sign-release-artifacts.sh" "$TMP/dist" > /dev/null 2>&1 \
  || fail "archive-* stale files must not block signing"
echo "ok 4: archive-* ignored"

# 5. A dist holding only stale files refuses with the names, not 'no artifacts'.
rm -rf "$TMP/dist"; mkdir -p "$TMP/dist"
: > "$TMP/dist/Baluard_0.7.2_amd64.deb"
rc=0
out="$(PATH="$BIN:$PATH" "$TMP/scripts/sign-release-artifacts.sh" "$TMP/dist" 2>&1)" || rc=$?
[[ $rc -ne 0 ]] || fail "stale-only dist must fail"
grep -q "Baluard_0.7.2_amd64.deb" <<<"$out" || fail "refusal must name the stale file"
echo "ok 5: stale-only dist refuses by name"

# 6. A truly empty dist still reports no artifacts.
rm -rf "$TMP/dist"; mkdir -p "$TMP/dist"
rc=0
out="$(PATH="$BIN:$PATH" "$TMP/scripts/sign-release-artifacts.sh" "$TMP/dist" 2>&1)" || rc=$?
[[ $rc -ne 0 ]] || fail "empty dist must fail"
grep -q "no artifacts" <<<"$out" || fail "empty dist message lost"
echo "ok 6: empty dist still fires"

echo "PASS test-sign-release-artifacts"
