#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Generated against release-publish.sh's own constants (the closer, the
# staged-sums filename, the stable-require set, the skip seam, the refusal
# fragments) so a rename cannot rot the suite silently.
SANDBOX="$TMP/repo"
mkdir -p "$SANDBOX/scripts" "$SANDBOX/release-upload" "$TMP/bin"
cp "$ROOT/scripts/release-publish.sh" "$ROOT/scripts/release-common.sh" "$SANDBOX/scripts/"

CLOSER="$(grep '^RELEASE_NOTES_CLOSER=' "$ROOT/scripts/release-common.sh" | cut -d= -f2- | tr -d '"')"
SKIP_VAR="BALUARD_RELEASE_PUBLISH_SKIP_VERIFY"
MISSING_PAT="run just release-stage first"

printf '[workspace.package]\nversion = "0.9.9"\n' > "$SANDBOX/Cargo.toml"
git -C "$SANDBOX" init -q
git -C "$SANDBOX" -c user.email=t@t -c user.name=t commit -q --allow-empty -m init
git -C "$SANDBOX" init -q --bare "$TMP/origin.git"
git -C "$SANDBOX" remote add origin "$TMP/origin.git"

CLOSER="As always, thanks for trying Baluard :)"
NOTES="$TMP/notes.md"
printf 'Release notes body.\n\n%s\n' "$CLOSER" > "$NOTES"

STABLE_LIST="$(cd "$ROOT" && bash -c 'source scripts/release-common.sh; printf "%s\n" "${STABLE_REQUIRE[@]}"')"
stage_set() {
  : > "$SANDBOX/release-upload/SHA256SUMS"
  : > "$SANDBOX/release-upload/SHA256SUMS.sig"
  printf '%s\n' "${PUB_TEST_STAGED_VERSION:-0.9.9}" > "$SANDBOX/release-upload/.staged-version"
  local n
  while IFS= read -r n; do
    [[ "$n" == SHA256SUMS ]] && continue
    : > "$SANDBOX/release-upload/$n"
  done <<<"$STABLE_LIST"
  return 0
}
stage_set

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
gh_uncalled() {
  if [[ -s "$GH_LOG" ]]; then echo "gh ran during a refusal: $(cat "$GH_LOG")" >&2; exit 1; fi
}

out="$(run_pub 0.9.8 "$NOTES")"
grep -q 'does not match the workspace' <<<"$out" || die "mismatch case: $out"
gh_uncalled

out="$(run_pub 0.9.9 "$NOTES")"
grep -q 'does not exist locally' <<<"$out" || die "missing tag: $out"
gh_uncalled

git -C "$SANDBOX" tag 0.9.9

# The tag exists locally but is not pushed: the remote would otherwise tag
# the default-branch HEAD.
out="$(run_pub 0.9.9 "$NOTES")"
grep -q 'is not pushed' <<<"$out" || die "unpushed tag: $out"
gh_uncalled

git -C "$SANDBOX" push -q origin refs/tags/0.9.9

printf 'Body without closer.\n' > "$TMP/bad.md"
out="$(run_pub 0.9.9 "$TMP/bad.md")"
grep -q 'standing closer' <<<"$out" || die "closer case: $out"
gh_uncalled

printf 'Body.\n%s\n' "$CLOSER" > "$TMP/tight.md"
out="$(run_pub 0.9.9 "$TMP/tight.md")"
grep -q 'blank line before it' <<<"$out" || die "blank-line case: $out"
gh_uncalled

# A trailing blank line after the closer is fine.
printf 'Body.\n\n%s\n\n' "$CLOSER" > "$TMP/trailing.md"
rm -f "$GH_LOG"
out="$(export $SKIP_VAR=1; run_pub 0.9.9 "$TMP/trailing.md")"
grep -q 'creating release 0.9.9' <<<"$out" || die "trailing-blank case: $out"

# A single-line file (closer, no body) refuses.
printf '%s\n' "$CLOSER" > "$TMP/only.md"
rm -f "$GH_LOG"
out="$(run_pub 0.9.9 "$TMP/only.md")"
grep -q 'blank line before it' <<<"$out" || die "single-line case: $out"
gh_uncalled

# Missing staged asset refuses before gh.
rm -f "$SANDBOX/release-upload/Baluard-amd64.deb"
out="$(run_pub 0.9.9 "$NOTES")"
grep -q "$MISSING_PAT" <<<"$out" || die "missing asset: $out"
gh_uncalled
stage_set

# Presence is not freshness: the upload set must carry a stage marker
# matching the tag, else a leftover set from another cycle publishes.
rm -f "$SANDBOX/release-upload/.staged-version"
out="$(run_pub 0.9.9 "$NOTES")"
grep -q 'stale or unstaged' <<<"$out" || die "unmarked upload set: $out"
gh_uncalled

printf '0.9.8\n' > "$SANDBOX/release-upload/.staged-version"
out="$(run_pub 0.9.9 "$NOTES")"
grep -q 'stale or unstaged' <<<"$out" || die "stale upload set: $out"
gh_uncalled

stage_set

out="$(export PUB_TEST_GH_HAD_RELEASE=1; run_pub 0.9.9 "$NOTES")"
grep -q 'already exists' <<<"$out" || die "existing case: $out"

rm -f "$GH_LOG"
out="$(export $SKIP_VAR=1; run_pub 0.9.9 "$NOTES")"
grep -q 'creating release 0.9.9' <<<"$out" || die "happy case: $out"
grep -q -- '--latest' "$GH_LOG" || die "no --latest: $(cat "$GH_LOG")"
grep -q -- '--verify-tag' "$GH_LOG" || die "no --verify-tag: $(cat "$GH_LOG")"
grep -q -- '--title' "$GH_LOG" || die "no --title: $(cat "$GH_LOG")"
grep -q -- '--notes-file' "$GH_LOG" || die "no --notes-file: $(cat "$GH_LOG")"
grep -q -- '--repo' "$GH_LOG" || die "no --repo: $(cat "$GH_LOG")"
grep -q 'release upload ' "$GH_LOG" || die "no upload: $(cat "$GH_LOG")"
grep -q -- '--clobber' "$GH_LOG" || die "no --clobber: $(cat "$GH_LOG")"
grep -q 'skipping live verify' <<<"$out" || die "verify seam: $out"

echo "test-release-publish: ok"
