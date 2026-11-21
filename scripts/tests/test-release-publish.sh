#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Generated against release-publish.sh's own constants (the closer, the
# staged-sums filename, the skip seam, the refusal fragments) so a rename
# cannot rot the suite silently.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$SANDBOX/release-upload" "$TMP/bin"
cp "$ROOT/scripts/release-publish.sh" "$ROOT/scripts/release-common.sh" "$SANDBOX/scripts/"

printf '[workspace.package]\nversion = "0.9.9"\n' > "$SANDBOX/Cargo.toml"
touch "$SANDBOX/release-upload/SHA256SUMS"
git -C "$SANDBOX" init -q
git -C "$SANDBOX" -c user.email=t@t -c user.name=t commit -q --allow-empty -m init

CLOSER="As always, thanks for trying Baluard :)"
NOTES="$TMP/notes.md"
printf 'Release notes body.\n\n%s\n' "$CLOSER" > "$NOTES"

GH_LOG="$TMP/gh.log"
cat > "$TMP/bin/gh" <<'GHEOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${PUB_TEST_GH_LOG:?}"
if [[ "${PUB_TEST_GH_FAIL:-0}" == 1 ]]; then exit 1; fi
case "$*" in
  "release view "*) [[ "${PUB_TEST_GH_HAD_RELEASE:-0}" == 1 ]] && exit 0; exit 1 ;;
  "repo "*|" gh repo "*) printf 'baluard-org/baluard\n'; exit 0 ;;
  "release create "*) echo "https://example.invalid/created"; exit 0 ;;
  "release upload "*) exit 0 ;;
esac
exit 0
GHEOF
chmod +x "$TMP/bin/gh"
export PATH="$TMP/bin:$PATH" PUB_TEST_GH_LOG="$GH_LOG"

run_pub() { (cd "$SANDBOX" && "$SANDBOX/scripts/release-publish.sh" "$@" 2>&1) || true; }
die() { echo "test-release-publish: $*" >&2; exit 1; }

out="$(run_pub 0.9.8 "$NOTES")"
grep -q 'does not match the workspace' <<<"$out" || die "mismatch case: $out"
[[ ! -s "$GH_LOG" ]] || die "gh ran despite the version mismatch"

out="$(run_pub 0.9.9 "$NOTES")"
grep -q 'does not exist locally' <<<"$out" || die "missing tag: $out"

git -C "$SANDBOX" tag 0.9.9

printf 'Body without closer.\n' > "$TMP/bad.md"
out="$(run_pub 0.9.9 "$TMP/bad.md")"
grep -q 'standing closer' <<<"$out" || die "closer case: $out"

printf 'Body.\n%s\n' "$CLOSER" > "$TMP/tight.md"
out="$(run_pub 0.9.9 "$TMP/tight.md")"
grep -q 'empty line before it' <<<"$out" || die "blank-line case: $out"

out="$(export PUB_TEST_GH_HAD_RELEASE=1; run_pub 0.9.9 "$NOTES")"
grep -q 'already exists' <<<"$out" || die "existing case: $out"

rm -f "$GH_LOG"
out="$(BALUARD_RELEASE_PUBLISH_SKIP_VERIFY=1 run_pub 0.9.9 "$NOTES")"
grep -q 'creating release 0.9.9' <<<"$out" || die "happy case: $out"
grep -q -- '--latest' "$GH_LOG" || die "no --latest: $(cat "$GH_LOG")"
grep -q 'release upload ' "$GH_LOG" || die "no upload: $(cat "$GH_LOG")"
grep -q 'skipping live verify' <<<"$out" || die "verify seam: $out"

echo "test-release-publish: ok"
