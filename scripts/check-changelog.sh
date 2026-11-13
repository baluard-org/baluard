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

# Junction invariant: every heading that opens a bulleted section must sit
# exactly one blank line above its first bullet. A cut that relocates a
# bullets block can double the separator (the moved block carries its own
# leading blank line) or glue the bullet to the heading, and no other
# invariant reads separator whitespace.
mapfile -t lines < "$FILE"
for i in "${!lines[@]}"; do
  [[ "${lines[$i]}" == "## "* ]] || continue
  has_bullet=0
  for (( j = i + 1; j < ${#lines[@]}; j++ )); do
    if [[ "${lines[$j]}" == "## "* ]]; then break; fi
    if [[ "${lines[$j]}" == "- "* || "${lines[$j]}" == "* " ]]; then has_bullet=1; break; fi
  done
  [[ "$has_bullet" -eq 1 ]] || continue
  next1="${lines[$((i + 1))]:-}"
  next2="${lines[$((i + 2))]:-}"
  if [[ -n "$next1" ]]; then
    fail "the section '${lines[$i]}' must be followed by one blank line before its first bullet"
  fi
  if [[ -z "$next2" ]]; then
    fail "the section '${lines[$i]}' is separated from its bullets by more than one blank line"
  fi
done

echo "changelog: invariants hold for $TAG"
