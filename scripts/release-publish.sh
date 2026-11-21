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
[[ -f "$NOTES" ]] || die "notes file not found: $NOTES"

# The published body ends with the standing closer on its own line after a
# blank one (release-protocol.md). The live verifier re-checks this, but
# refusing here means a rejected upload never reaches the release at all.
LAST="$(awk 'NF {l=$0} END {print l}' "$NOTES" | tr -d '\r')"
PREV_RAW="$(tail -n 2 "$NOTES" | head -n 1 | tr -d '\r')"
[[ "$LAST" == "$RELEASE_NOTES_CLOSER" ]] \
  || die "notes must end with the standing closer on its own line; last non-empty line: ${LAST:-none}"
[[ -z "$PREV_RAW" ]] \
  || die "the closer line needs an empty line before it (found: $PREV_RAW)"

# The stable set must be staged; creating an empty release would strand the
# site's always-latest links.
[[ -f "$ROOT/release-upload/SHA256SUMS" ]] \
  || die "release-upload/SHA256SUMS missing; run just release-stage first"

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)" \
  || die "gh could not resolve the repository"
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  die "release $TAG already exists; upload with 'gh release upload $TAG --clobber release-upload/*' instead"
fi

echo "creating release $TAG on $REPO (latest)"
gh release create "$TAG" --latest --title "Baluard $TAG" --notes-file "$NOTES" --repo "$REPO" \
  || die "gh release create failed"
gh release upload "$TAG" --clobber "$ROOT/release-upload/"* --repo "$REPO" \
  || die "gh release upload failed; re-run the upload before publishing the channel"

if [[ "${BALUARD_RELEASE_PUBLISH_SKIP_VERIFY:-0}" == "1" ]]; then
  echo "release-publish: skipping live verify (BALUARD_RELEASE_PUBLISH_SKIP_VERIFY=1)"
  exit 0
fi
"$ROOT/scripts/verify-release-live.sh" "$TAG"
