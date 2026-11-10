#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: sync-site-repos.sh <repo-out-dir> <baluard-org-dir> [pkg-repo-site] [pkg-fdroid-site]}"
SITE="${2:?usage: sync-site-repos.sh <repo-out-dir> <baluard-org-dir> [pkg-repo-site] [pkg-fdroid-site]}"
PKG_REPO_SITE="${3:-$(dirname "$SITE")/baluard-org-repo}"
PKG_FDROID_SITE="${4:-$(dirname "$SITE")/baluard-org-fdroid}"
fail() { echo "ERROR: $*" >&2; exit 1; }
command -v rsync >/dev/null 2>&1 || fail "rsync is required"
required=(
  fdroid/repo/index-v2.json
  fdroid/repo/entry.jar
  dists/stable/InRelease
  rpms/repodata/repomd.xml.asc
  arch/x86_64/baluard.db
  arch/x86_64/baluard.db.sig
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
[[ -d "$PKG_REPO_SITE" ]] || fail "package repo site clone missing: $PKG_REPO_SITE (git clone baluard-org/repo)"
[[ -d "$PKG_FDROID_SITE" ]] || fail "package F-Droid site clone missing: $PKG_FDROID_SITE (git clone baluard-org/fdroid)"

mkdir -p "$SITE/repo" "$SITE/fdroid/repo"
# baluard.repo and baluard.sources are site-authored repo definitions the
# install instructions fetch; staging never produces them.
rsync -a --delete --exclude=/fdroid/ --exclude=index.html \
  --exclude=/baluard.repo --exclude=/baluard.sources "$SRC/" "$SITE/repo/"
rsync -a --delete "$SRC/fdroid/repo/" "$SITE/fdroid/repo/"
touch "$SITE/.nojekyll"

# The package site clones back the org site's /repo and /fdroid subpaths on
# their own github.io hostnames; they are the offload backend if the custom
# domain ever routes there. Their dotfiles are author-owned, not mirrored.
rsync -a --delete --exclude=.git --exclude=.gitignore --exclude=.nojekyll \
  "$SITE/repo/" "$PKG_REPO_SITE/"
rsync -a --delete --exclude=.git --exclude=.gitignore --exclude=.nojekyll \
  "$SITE/fdroid/" "$PKG_FDROID_SITE/"
touch "$PKG_REPO_SITE/.nojekyll" "$PKG_FDROID_SITE/.nojekyll"
[[ -s "$PKG_REPO_SITE/arch/x86_64/baluard.db" ]] || fail "package repo site mirror incomplete"
[[ -s "$PKG_FDROID_SITE/repo/index-v2.json" ]] || fail "package fdroid site mirror incomplete"

echo "Repositories synchronized into $SITE"
echo "Package mirrors synchronized into $PKG_REPO_SITE and $PKG_FDROID_SITE"
echo "Review the site diff, then commit and push to publish."
