#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: sync-site-repos.sh <repo-out-dir> <baluard-org-dir> [packages-site]}"
SITE="${2:?usage: sync-site-repos.sh <repo-out-dir> <baluard-org-dir> [packages-site]}"
PKG_SITE="${3:-$(dirname "$SITE")/baluard-packages}"
# shellcheck source=release-common.sh disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/release-common.sh"
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
# The site repo no longer carries the package trees; packages.baluard.app
# serves them from the baluard-packages repository. Recreating the trees in
# the site would bloat every deploy with hundreds of megabytes of bytes.
[[ ! -e "$SITE/repo" && ! -e "$SITE/fdroid" ]] || fail "site still carries package trees: remove repo/ and fdroid/ from the site repo (packages publish to baluard-packages)"
[[ -d "$PKG_SITE" ]] || fail "package site clone missing: $PKG_SITE (git clone baluard-org/baluard-packages)"

# Packages publish straight from staging. The clone's dotfiles, the GitHub
# workflow that deploys it, and the author-owned install definitions are
# clone-only content the rsync must never mirror over (see release-common.sh);
# the CNAME binds the custom domain.
excludes=()
for f in "${AUTHOR_OWNED_EXCLUDED[@]}"; do excludes+=("--exclude=/$f"); done
rsync -a --delete "${excludes[@]}" --exclude=.git \
  "$SRC/" "$PKG_SITE/"
mkdir -p "$PKG_SITE/fdroid/repo"
rsync -a --delete --exclude=.git --exclude=.gitignore --exclude=.nojekyll \
  "$SRC/fdroid/repo/" "$PKG_SITE/fdroid/repo/"
touch "$PKG_SITE/.nojekyll"
[[ -s "$PKG_SITE/arch/x86_64/baluard.db" ]] || fail "package site mirror incomplete"
[[ -s "$PKG_SITE/fdroid/repo/index-v2.json" ]] || fail "package fdroid mirror incomplete"
check_author_owned_files "$PKG_SITE" || fail "the sync would publish a broken package site; restore the clone files above (git -C $PKG_SITE checkout .) and investigate the exclusion list"

echo "Packages synchronized into $PKG_SITE"
echo "Review the diff, then commit and push to publish."
