#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SRC="$TMP/repo-out"
SITE="$TMP/baluard-org"
PKG_SITE="$TMP/baluard-packages"

mkdir -p "$SRC/dists/stable" "$SRC/rpms/repodata" "$SRC/fdroid/repo" "$SRC/arch/x86_64" "$PKG_SITE/arch/x86_64" "$PKG_SITE/dists" "$PKG_SITE/fdroid/repo" "$PKG_SITE/.github/workflows" "$SITE"
printf 'keep-dotfile
' > "$PKG_SITE/.gitignore"
printf 'deploy-marker
' > "$PKG_SITE/.github/workflows/deploy-pages.yml"
printf 'release
' > "$SRC/dists/stable/InRelease"
printf 'rpm
' > "$SRC/rpms/repodata/repomd.xml.asc"
printf 'fdroid
' > "$SRC/fdroid/repo/index-v2.json"
printf 'entry
' > "$SRC/fdroid/repo/entry.jar"
printf 'apk
' > "$SRC/fdroid/repo/app.baluard.mobile_1.apk"
printf 'sums
' > "$SRC/SHA256SUMS"
printf 'sig
' > "$SRC/SHA256SUMS.sig"
printf 'key
' > "$SRC/baluard-release.asc"
printf 'archdb
' > "$SRC/arch/x86_64/baluard.db"
printf 'archdbsig
' > "$SRC/arch/x86_64/baluard.db.sig"
touch "$SRC/.nojekyll"
# Author-owned clone content: install definitions, dotfiles, and stale trees
# the sync must replace or preserve.
printf '[baluard]
' > "$PKG_SITE/baluard.repo"
printf 'Types: deb
' > "$PKG_SITE/baluard.sources"
printf 'landing
' > "$PKG_SITE/index.html"
printf 'keep-dotfile
' > "$PKG_SITE/.gitignore"
printf 'stale
' > "$PKG_SITE/dists/stale"
printf 'oldarch
' > "$PKG_SITE/arch/x86_64/baluard.db"
printf 'stale
' > "$PKG_SITE/fdroid/repo/stale.apk"
printf 'keep
' > "$SITE/index.html"
printf 'baluard.app
' > "$SITE/CNAME"
git -C "$SITE" init -q

"$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE" "$PKG_SITE"

# The site itself must stay free of package trees.
test ! -e "$SITE/repo"
test ! -e "$SITE/fdroid"
test "$(cat "$SITE/index.html")" = keep
# Repo project site: staged content lands, stale bytes die, author-owned
# files survive.
test "$(cat "$PKG_SITE/arch/x86_64/baluard.db")" = archdb
test "$(cat "$PKG_SITE/arch/x86_64/baluard.db.sig")" = archdbsig
test "$(cat "$PKG_SITE/dists/stable/InRelease")" = release
test "$(cat "$PKG_SITE/SHA256SUMS")" = sums
test ! -e "$PKG_SITE/dists/stale"
test "$(cat "$PKG_SITE/baluard.repo")" = "[baluard]"
test "$(cat "$PKG_SITE/baluard.sources")" = "Types: deb"
test "$(cat "$PKG_SITE/index.html")" = landing
test "$(cat "$PKG_SITE/.gitignore")" = keep-dotfile
test -f "$PKG_SITE/.nojekyll"
test "$(cat "$PKG_SITE/.github/workflows/deploy-pages.yml")" = deploy-marker
# F-Droid project site: same contract.
test "$(cat "$PKG_SITE/fdroid/repo/index-v2.json")" = fdroid
test "$(cat "$PKG_SITE/fdroid/repo/entry.jar")" = entry
test "$(cat "$PKG_SITE/fdroid/repo/app.baluard.mobile_1.apk")" = apk
test ! -e "$PKG_SITE/fdroid/repo/stale.apk"
test "$(cat "$PKG_SITE/.gitignore")" = keep-dotfile
test -f "$PKG_SITE/.nojekyll"

rm -rf "$PKG_SITE"
if "$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE" 2>/dev/null; then
  echo 'expected a missing package site clone to fail' >&2
  exit 1
fi
mkdir -p "$PKG_SITE/arch/x86_64" "$PKG_SITE/dists" "$PKG_SITE/fdroid/repo"

mv "$SRC/fdroid/repo/index-v2.json" "$TMP/index-v2.json"
if "$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE" 2>/dev/null; then
  echo 'expected an incomplete staging tree to fail' >&2
  exit 1
fi
mv "$TMP/index-v2.json" "$SRC/fdroid/repo/index-v2.json"

# A site repo that still carries package trees must refuse the sync; the
# trees would bloat every deploy of the main site.
mkdir -p "$SITE/repo"
if "$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE" 2>/dev/null; then
  echo 'expected package trees in the site repo to fail' >&2
  exit 1
fi
rmdir "$SITE/repo"

printf 'wrong.example
' > "$SITE/CNAME"
if "$ROOT/scripts/sync-site-repos.sh" "$SRC" "$SITE" 2>/dev/null; then
  echo 'expected a non-site worktree to fail' >&2
  exit 1
fi

printf 'PASS: sync-site-repos.sh
'
