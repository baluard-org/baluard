#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: sync-site-repos.sh <repo-out-dir> <baluard-org-dir>}"
SITE="${2:?usage: sync-site-repos.sh <repo-out-dir> <baluard-org-dir>}"
fail() { echo "ERROR: $*" >&2; exit 1; }
command -v rsync >/dev/null 2>&1 || fail "rsync is required"
required=(
  fdroid/repo/index-v2.json
  fdroid/repo/entry.jar
  dists/stable/InRelease
  rpms/repodata/repomd.xml.asc
  SHA256SUMS
  SHA256SUMS.sig
  baluard-release.asc
)
for relative in "${required[@]}"; do
  [[ -s "$SRC/$relative" ]] || fail "incomplete staging tree; missing $relative"
done
compgen -G "$SRC/fdroid/repo/*.apk" >/dev/null || fail "incomplete staging tree; no APK found"
[[ "$(<"$SITE/CNAME")" == "baluard.app" ]] || fail "site marker is missing or invalid: $SITE/CNAME"
git -C "$SITE" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "site is not a git worktree: $SITE"
[[ ! -e "$SITE/repo/fdroid" ]] || fail "unexpected nested F-Droid tree: $SITE/repo/fdroid"

mkdir -p "$SITE/repo" "$SITE/fdroid/repo"
# baluard.repo and baluard.sources are site-authored repo definitions the
# install instructions fetch; staging never produces them.
rsync -a --delete --exclude=/fdroid/ --exclude=index.html \
  --exclude=/baluard.repo --exclude=/baluard.sources "$SRC/" "$SITE/repo/"
rsync -a --delete "$SRC/fdroid/repo/" "$SITE/fdroid/repo/"
touch "$SITE/.nojekyll"

echo "Repositories synchronized into $SITE"
echo "Review the site diff, then commit and push to publish."
