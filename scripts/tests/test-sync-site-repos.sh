#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SRC="$TMP/repo-out"
SITE="$TMP/baluard-org"
mkdir -p "$SRC/dists/stable" "$SRC/rpms/repodata" "$SRC/fdroid/repo" "$SITE/repo/dists" "$SITE/fdroid/repo"
printf 'release\n' > "$SRC/dists/stable/InRelease"
printf 'rpm\n' > "$SRC/rpms/repodata/repomd.xml.asc"
printf 'fdroid\n' > "$SRC/fdroid/repo/index-v2.json"
printf 'entry\n' > "$SRC/fdroid/repo/entry.jar"
printf 'apk\n' > "$SRC/fdroid/repo/app.baluard.mobile_1.apk"
printf 'sums\n' > "$SRC/SHA256SUMS"
printf 'sig\n' > "$SRC/SHA256SUMS.sig"
printf 'key\n' > "$SRC/baluard-release.asc"
touch "$SRC/.nojekyll"
printf 'stale\n' > "$SITE/repo/dists/stale"
printf 'stale\n' > "$SITE/fdroid/repo/stale.apk"
printf 'guard\n' > "$SITE/repo/dists/index.html"
printf '[baluard]\n' > "$SITE/repo/baluard.repo"
printf 'Types: deb\n' > "$SITE/repo/baluard.sources"
printf 'landing\n' > "$SITE/fdroid/index.html"
printf 'keep\n' > "$SITE/index.html"
printf 'baluard.app\n' > "$SITE/CNAME"
git -C "$SITE" init -q

"$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE"

test ! -e "$SITE/repo/dists/stale"
test ! -e "$SITE/fdroid/repo/stale.apk"
test "$(cat "$SITE/repo/dists/index.html")" = guard
test "$(cat "$SITE/repo/baluard.repo")" = "[baluard]"
test "$(cat "$SITE/repo/baluard.sources")" = "Types: deb"
test "$(cat "$SITE/fdroid/index.html")" = landing
test "$(cat "$SITE/index.html")" = keep
test -f "$SITE/.nojekyll"
cmp "$SRC/dists/stable/InRelease" "$SITE/repo/dists/stable/InRelease"
cmp "$SRC/fdroid/repo/index-v2.json" "$SITE/fdroid/repo/index-v2.json"
test ! -e "$SITE/repo/fdroid"

mv "$SRC/fdroid/repo/index-v2.json" "$TMP/index-v2.json"
if "$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE" 2>/dev/null; then
  echo 'expected an incomplete staging tree to fail' >&2
  exit 1
fi
mv "$TMP/index-v2.json" "$SRC/fdroid/repo/index-v2.json"

mkdir -p "$SITE/repo/fdroid"
if "$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE" 2>/dev/null; then
  echo 'expected a misplaced nested F-Droid tree to fail' >&2
  exit 1
fi
rmdir "$SITE/repo/fdroid"

printf 'wrong.example\n' > "$SITE/CNAME"
if "$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE" 2>/dev/null; then
  echo 'expected a non-site worktree to fail' >&2
  exit 1
fi

printf 'PASS: sync-site-repos.sh\n'
