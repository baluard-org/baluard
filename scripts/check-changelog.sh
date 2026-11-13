#!/usr/bin/env bash
# Read-only changelog invariants, asserted after any scripted cut or bullet
# edit: exactly one [UNRELEASED] heading, positioned above the given version
# section (the section itself must exist), and no stale placeholder sitting
# beside real bullets. usage: check-changelog.sh <tag> [changelog-path]
set -euo pipefail

TAG="${1:?usage: check-changelog.sh <tag> [changelog-path]}"
FILE="${2:-CHANGELOG.md}"
fail() { echo "changelog: $*" >&2; exit 1; }

[[ -f "$FILE" ]] || fail "no changelog at $FILE"
count="$(grep -c '^## \[UNRELEASED\]' "$FILE" || true)"
[[ "$count" -eq 1 ]] || fail "expected exactly one [UNRELEASED] heading, found $count"

tag_re="${TAG//./\\.}"
idx_un="$(grep -n '^## \[UNRELEASED\]' "$FILE" | cut -d: -f1)"
if ! grep -q "^## $tag_re - " "$FILE"; then
  fail "no section for $TAG (expected a '^## $TAG - <date>' heading)"
fi
idx_ver="$(grep -n "^## $tag_re - " "$FILE" | head -1 | cut -d: -f1)"
[[ "$idx_un" -lt "$idx_ver" ]] || fail "[UNRELEASED] sits below the $TAG section (stranded-heading shape)"

body="$(sed -n "$((idx_un + 1)),$((idx_ver - 1))p" "$FILE")"
if grep -q "No user-facing changes yet." <<<"$body" \
   && grep -v "No user-facing changes yet." <<<"$body" | grep -qE "^- |^\* "; then
  fail "the UNRELEASED placeholder coexists with real bullets; sweep the placeholder"
fi

echo "changelog: invariants hold for $TAG"
