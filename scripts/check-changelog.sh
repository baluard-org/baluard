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

# Junction invariants, both directions of the cut splice damage: a heading
# that opens a bulleted section must sit exactly one blank line above its
# first content line (a relocated bullets block carries its own leading
# blank line and doubles the separator), and every heading must open on a
# blank line after the previous section's bullets. No other invariant
# reads separator whitespace.
mapfile -t lines < "$FILE"
is_bullet() { [[ "$1" == "- "* || "$1" == "* "* ]]; }
# Intro prose may sit above the first heading; the reverse invariant is
# section separation, so it applies from the second heading on.
first_heading=-1
for i in "${!lines[@]}"; do
  if [[ "${lines[$i]}" == "## "* ]]; then first_heading="$i"; break; fi
done
for i in "${!lines[@]}"; do
  [[ "${lines[$i]}" == "## "* ]] || continue
  has_bullet=0
  for (( j = i + 1; j < ${#lines[@]}; j++ )); do
    if [[ "${lines[$j]}" == "## "* ]]; then break; fi
    if is_bullet "${lines[$j]}"; then has_bullet=1; break; fi
  done
  if [[ "$has_bullet" -eq 1 ]]; then
    next1="${lines[$((i + 1))]:-}"
    next2="${lines[$((i + 2))]:-}"
    if [[ -n "$next1" ]]; then
      fail "the section '${lines[$i]}' must be followed by one blank line before its first bullet"
    fi
    if [[ -z "$next2" ]]; then
      fail "the section '${lines[$i]}' is separated from its bullets by more than one blank line"
    fi
  fi
  if [[ "$i" -gt 0 && -n "${lines[$((i - 1))]}" && "$i" -ne "$first_heading" ]]; then
    fail "the heading '${lines[$i]}' must open on a blank line after the previous section"
  fi
done

echo "changelog: invariants hold for $TAG"
