#!/usr/bin/env bash
# Publish the desktop updater channel manifest for one release, with failure
# atomicity: back up the current channel manifest first, roll it back if any
# post-upload check fails, and refuse to publish anything whose version does
# not read back as the requested tag. Encodes the channel incidents recorded
# in docs/dev/release-protocol.md (wrong target, stale /tmp file, silent
# --clobber no-op, CDN staleness).
#
# usage: publish-updates-manifest.sh [--dry-run] <tag>
# env: BALUARD_MANIFEST_PROBE_TRIES (default 12), BALUARD_MANIFEST_PROBE_SLEEP
#      (default 10 seconds) bound the served-bytes convergence poll.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE_TRIES="${BALUARD_MANIFEST_PROBE_TRIES:-12}"
PROBE_SLEEP="${BALUARD_MANIFEST_PROBE_SLEEP:-10}"
fail() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "$*"; }

DRY_RUN=false
TAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    -*) fail "unknown flag $1" ;;
    *) TAG="$1" ;;
  esac
  shift
done
[[ -n "$TAG" ]] || fail "usage: $0 [--dry-run] <tag>"
[[ "$TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "tag '$TAG' is not an unprefixed semver"
# Channel routing follows the release dash rule the updater client uses.
CHANNEL="updates-stable"
[[ "$TAG" == *-* ]] && CHANNEL="updates-beta"

command -v gh >/dev/null 2>&1 || fail "gh is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"
cd "$ROOT" || fail "cannot enter $ROOT"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "run from inside the baluard repository (gh shells out to git)"

# Stable names only: staging never writes versioned copies, so a missing
# updater payload here means the release-stage run did not happen.
for f in Baluard-amd64.AppImage Baluard-amd64.AppImage.sig \
         Baluard-arm64.app.tar.gz Baluard-arm64.app.tar.gz.sig \
         Baluard-amd64-setup.exe Baluard-amd64-setup.exe.sig; do
  [[ -s "release-upload/$f" ]] || fail "release-upload/$f is missing; run just release-stage first"
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
START_EPOCH="$(date -u +%s)"

gh release view "$TAG" --json body -q .body > "$TMP/notes.md" \
  || fail "cannot read the release body for $TAG (is it published?)"
node scripts/generate-updates-manifest.mjs --tag "$TAG" \
  --artifacts-dir release-upload --out "$TMP/latest.json" \
  --notes-file "$TMP/notes.md" --strict --require-stamped \
  || fail "manifest generation failed; nothing uploaded"
[[ -s "$TMP/latest.json" ]] || fail "generator wrote an empty manifest"
version="$(jq -r .version "$TMP/latest.json")"
[[ "$version" == "$TAG" ]] || fail "generated manifest carries version $version, expected $TAG; refusing to publish"

if $DRY_RUN; then
  note "dry-run OK: manifest for $TAG would upload to $CHANNEL ($TMP/latest.json)"
  exit 0
fi

# Back up the live manifest so a failed publish can restore the channel.
BACKUP=""
mkdir -p "$TMP/backup"
if gh release download "$CHANNEL" --pattern latest.json --dir "$TMP/backup" >/dev/null 2>&1 \
   && [[ -s "$TMP/backup/latest.json" ]]; then
  BACKUP="$TMP/backup/latest.json"
fi

rollback() {
  if [[ -n "$BACKUP" ]]; then
    if gh release upload "$CHANNEL" "$BACKUP" --clobber >/dev/null 2>&1; then
      echo "ERROR: publish failed; the previous manifest was restored to $CHANNEL" >&2
    else
      echo "ERROR: publish failed AND the rollback upload failed" >&2
    fi
  else
    echo "ERROR: publish failed and there was no previous manifest to restore; $CHANNEL may be empty" >&2
  fi
  echo "manual recovery: gh release upload $CHANNEL <latest.json> --clobber" >&2
  exit 1
}

gh release upload "$CHANNEL" "$TMP/latest.json" --clobber \
  || rollback

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
assets="$(gh api "repos/$REPO/releases/tags/$CHANNEL")"
count="$(jq '[.assets[] | select(.name == "latest.json")] | length' <<<"$assets")"
[[ "$count" -eq 1 ]] || { rollback; }
size="$(jq -r '.assets[] | select(.name == "latest.json") | .size' <<<"$assets")"
[[ "$size" == "$(wc -c < "$TMP/latest.json" | tr -d ' ')" ]] \
  || { echo "channel size $size != local $(wc -c < "$TMP/latest.json" | tr -d ' ')" >&2; rollback; }
updated_at="$(jq -r '.assets[] | select(.name == "latest.json") | .updated_at' <<<"$assets")"
ts="$(date -u -d "$updated_at" +%s 2>/dev/null || echo 0)"
[[ "$ts" -ge "$START_EPOCH" ]] || { echo "channel asset updated_at $updated_at predates this upload" >&2; rollback; }

# The CDN serves the previous body for a while; converge on a hash match.
url="https://github.com/$REPO/releases/download/$CHANNEL/latest.json"
local_sha="$(sha256sum "$TMP/latest.json" | cut -d' ' -f1)"
served_ok=false
for _ in $(seq 1 "$PROBE_TRIES"); do
  served_sha="$(curl -sfL "$url" 2>/dev/null | sha256sum | cut -d' ' -f1 || true)"
  if [[ -n "${served_sha:-}" && "$served_sha" == "$local_sha" ]]; then
    served_ok=true
    break
  fi
  sleep "$PROBE_SLEEP"
done
$served_ok || { echo "served bytes never matched after $PROBE_TRIES probes" >&2; rollback; }

# A stray latest.json on the version release is the wrong-target incident
# class; remove it automatically and say so.
stray="$(gh api "repos/$REPO/releases/tags/$TAG" | jq '[.assets[] | select(.name == "latest.json")] | length')"
if [[ "$stray" -gt 0 ]]; then
  id="$(gh api "repos/$REPO/releases/tags/$TAG" | jq -r '.assets[] | select(.name == "latest.json") | .id')"
  gh api -X DELETE "repos/$REPO/releases/assets/$id" >/dev/null
  note "removed a stray latest.json from the $TAG release (wrong-target residue)"
fi

note "updates channel $CHANNEL serves version $TAG (asset verified, served bytes matched)"
