#!/usr/bin/env bash
# Publish the staged release: pre-flight the notes against the standing
# rules, create the GitHub release as latest, upload the stable set, and
# run the live-verify sweep. The notes file is the artifact of the human
# verbatim-approval step; this script gates it mechanically and refuses
# anything that breaks the release-body conventions before a byte lands.
#
# usage: release-publish.sh <tag> <notes-file>
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=release-common.sh disable=SC1091
source "$ROOT/scripts/release-common.sh"

TAG="${1:-}"
NOTES="${2:-}"
[[ -n "$TAG" && -n "$NOTES" ]] || {
  echo "usage: $0 <tag> <notes-file>" >&2
  echo "       notes must be approved verbatim first; this script enforces the conventions" >&2
  exit 1
}

die() { echo "release-publish: $*" >&2; exit 1; }

# Pre-flight: the tag must exist and match the workspace version (a
# workspace mid-bump publishes under the wrong name otherwise).
VERSION="$(version_from_cargo "$ROOT")"
[[ "$TAG" == "$VERSION" ]] || die "tag $TAG does not match the workspace version $VERSION"
git -C "$ROOT" rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
  || die "tag $TAG does not exist locally; cut it (and push it) first"
# gh release create otherwise tags the default-branch HEAD remotely when the
# tag was never pushed, publishing the wrong commit under the release.
git -C "$ROOT" ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null \
  || die "tag $TAG is not pushed; push the tag before publishing the release"
[[ -f "$NOTES" ]] || die "notes file not found: $NOTES"

# The published body ends with the standing closer on its own line after a
# blank one (release-protocol.md); a trailing blank line after the closer is
# fine. The live verifier re-checks this, but refusing here means a rejected
# upload never reaches the release at all.
if ! awk -v c="$RELEASE_NOTES_CLOSER" '
  { sub(/\r$/, ""); line[NR] = $0 }
  NF { last = NR; closer = $0 }
  END { exit !(closer == c && last > 1 && line[last - 1] ~ /^[[:space:]]*$/) }
' "$NOTES"; then
  die "notes must end with the standing closer on its own line, blank line before it"
fi

# The stable set must be staged; creating an empty release would strand the
# site's always-latest links.
for n in "${STABLE_REQUIRE[@]}" SHA256SUMS SHA256SUMS.sig; do
  [[ -f "$ROOT/release-upload/$n" ]] \
    || die "release-upload/$n missing; run just release-stage first"
done

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)" \
  || die "gh could not resolve the repository"
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  die "release $TAG already exists; upload with 'gh release upload $TAG --clobber release-upload/*' instead"
fi

echo "creating release $TAG on $REPO (latest)"
gh release create "$TAG" --verify-tag --latest --title "Baluard $TAG" --notes-file "$NOTES" --repo "$REPO" \
  || die "gh release create failed"
gh release upload "$TAG" --clobber "$ROOT/release-upload/"* --repo "$REPO" \
  || die "gh release upload failed; re-run the upload before publishing the channel"

if [[ "${BALUARD_RELEASE_PUBLISH_SKIP_VERIFY:-0}" == "1" ]]; then
  echo "release-publish: skipping live verify (BALUARD_RELEASE_PUBLISH_SKIP_VERIFY=1)"
  exit 0
fi
# Pre-republish sweep: only the release-side checks can pass here; the
# packages/F-Droid/apt/updates-channel gates run after the republish.
"$ROOT/scripts/verify-release-live.sh" "$TAG" --pre-publish
exit_code=$?
if ((exit_code == 0)); then
  echo "release side is green. After the packages repo republish + channel manifest, run:"
  echo "  scripts/verify-release-live.sh $TAG --packages-sha <republish-sha>"
fi
exit $exit_code
