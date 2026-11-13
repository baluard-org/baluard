#!/usr/bin/env bash
# Publish the desktop updater channel manifest for one release, with failure
# atomicity: back up the current channel manifest first, roll it back if any
# post-upload check fails (including set -e deaths and signals, via the EXIT
# trap), and refuse to publish anything whose version does not read back as
# the requested tag. A channel already carrying this tag is a no-op unless
# --force. Encodes the channel incidents recorded in
# docs/dev/release-protocol.md (wrong target, stale /tmp file, silent
# --clobber no-op, CDN staleness).
#
# usage: publish-updates-manifest.sh [--dry-run] [--force] <tag>
# env: BALUARD_MANIFEST_PROBE_TRIES (default 18), BALUARD_MANIFEST_PROBE_SLEEP
#      (default 10 seconds) bound the served-bytes convergence poll.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE_TRIES="${BALUARD_MANIFEST_PROBE_TRIES:-18}"
PROBE_SLEEP="${BALUARD_MANIFEST_PROBE_SLEEP:-10}"
fail() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "$*"; }

DRY_RUN=false
FORCE=false
TAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --force) FORCE=true ;;
    -*) fail "unknown flag $1" ;;
    *) TAG="$1" ;;
  esac
  shift
done
[[ -n "$TAG" ]] || fail "usage: $0 [--dry-run] [--force] <tag>"
[[ "$TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "tag '$TAG' is not an unprefixed semver"
# Channel routing follows the release dash rule the updater client uses.
CHANNEL="updates-stable"
[[ "$TAG" == *-* ]] && CHANNEL="updates-beta"

command -v gh >/dev/null 2>&1 || fail "gh is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v flock >/dev/null 2>&1 || fail "flock is required"
cd "$ROOT" || fail "cannot enter $ROOT"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "run from inside the baluard repository (gh shells out to git)"
# One publish at a time: a second run's rollback could restore a stale
# manifest over the first run's good publish.
exec 9>"$ROOT/.git/updates-publish.lock" || fail "cannot open the publish lock"
flock -n 9 || fail "another updates-publish is already running"

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)" || fail "cannot read the GitHub repo"

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
# Pin pub_date to the release's real publish time so the same tag always
# generates byte-identical manifests (the generator defaults to wall clock).
PUB_DATE="$(gh release view "$TAG" --json publishedAt -q .publishedAt)" \
  || fail "cannot read the publish time for $TAG"
[[ -n "$PUB_DATE" ]] || fail "release $TAG has no publishedAt; is it a draft?"

node scripts/generate-updates-manifest.mjs --tag "$TAG" \
  --artifacts-dir release-upload --out "$TMP/latest.json" \
  --notes-file "$TMP/notes.md" --pub-date "$PUB_DATE" --strict --require-stamped \
  || fail "manifest generation failed; nothing uploaded"
[[ -s "$TMP/latest.json" ]] || fail "generator wrote an empty manifest"
version="$(jq -r .version "$TMP/latest.json")" || fail "cannot parse the generated manifest"
[[ "$version" == "$TAG" ]] || fail "generated manifest carries version $version, expected $TAG; refusing to publish"

if $DRY_RUN; then
  note "dry-run OK: manifest for $TAG would upload to $CHANNEL ($TMP/latest.json)"
  exit 0
fi

# Back up the live manifest so a failed publish can restore the channel.
# The API is the source of truth for whether a manifest exists: treating a
# failed download as "no previous manifest" would leave the channel
# unrollbackable on a transient gh error.
chan_json="$(gh api "repos/$REPO/releases/tags/$CHANNEL")" \
  || fail "cannot read the $CHANNEL channel state; refusing to publish"
chan_count="$(jq '[.assets[] | select(.name == "latest.json")] | length' <<<"$chan_json")" \
  || fail "cannot parse the channel asset list"
BACKUP=""
if [[ "$chan_count" -eq 1 ]]; then
  mkdir -p "$TMP/backup"
  gh release download "$CHANNEL" --pattern latest.json --dir "$TMP/backup" >/dev/null 2>&1 \
    && [[ -s "$TMP/backup/latest.json" ]] \
    || fail "the channel holds latest.json but it could not be backed up; refusing to publish"
  BACKUP="$TMP/backup/latest.json"
elif [[ "$chan_count" -gt 1 ]]; then
  fail "$CHANNEL holds $chan_count latest.json assets; delete the extras by hand first"
fi

# Rerunning a finished publish is a no-op (the backup already carries this
# tag and the API is not subject to CDN staleness); --force re-uploads.
if [[ -n "$BACKUP" ]] && ! $FORCE; then
  backup_version="$(jq -r .version "$BACKUP")" || fail "cannot parse the channel manifest"
  if [[ "$backup_version" == "$TAG" ]]; then
    note "$CHANNEL already serves $TAG; nothing to do (use --force to re-upload)"
    exit 0
  fi
fi

# Everything below can mutate the channel: any failure -- including set -e
# deaths and signals -- must roll the backup back. The EXIT trap owns that;
# individual checks just die with a message.
UPLOADED=false
FINISHED=false
rollback() {
  if [[ -n "$BACKUP" ]]; then
    if gh release upload "$CHANNEL" "$BACKUP" --clobber >/dev/null 2>&1; then
      rb_json="$(gh api "repos/$REPO/releases/tags/$CHANNEL" 2>/dev/null || true)"
      rb_count="$(jq '[.assets[] | select(.name == "latest.json")] | length' <<<"$rb_json" 2>/dev/null || echo 0)"
      rb_size="$(jq -r '.assets[] | select(.name == "latest.json") | .size' <<<"$rb_json" 2>/dev/null || echo 0)"
      want_size="$(wc -c < "$BACKUP" | tr -d ' ')"
      if [[ "$rb_count" -eq 1 && "$rb_size" == "$want_size" ]]; then
        echo "ERROR: publish failed; the previous manifest was verified restored to $CHANNEL" >&2
      else
        echo "ERROR: publish failed AND the rollback upload did not land (count=$rb_count size=$rb_size want=$want_size)" >&2
      fi
    else
      echo "ERROR: publish failed AND the rollback upload failed" >&2
    fi
  else
    echo "ERROR: publish failed and there was no previous manifest to restore; $CHANNEL may be empty" >&2
  fi
  echo "manual recovery: gh release upload $CHANNEL <latest.json> --clobber" >&2
}
on_exit() {
  local rc=$?
  if $UPLOADED && ! $FINISHED && [[ "$rc" -ne 0 ]]; then
    echo "publish aborted mid-flight (rc=$rc); rolling back" >&2
    rollback
  fi
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

die() { echo "ERROR: $*" >&2; exit 1; }

gh release upload "$CHANNEL" "$TMP/latest.json" --clobber || die "the channel upload failed"
UPLOADED=true

assets="$(gh api "repos/$REPO/releases/tags/$CHANNEL")" || die "cannot read the channel state after upload"
count="$(jq '[.assets[] | select(.name == "latest.json")] | length' <<<"$assets")" \
  || die "cannot parse the channel asset list"
[[ "$count" -eq 1 ]] || die "channel holds $count latest.json assets after upload"
size="$(jq -r '.assets[] | select(.name == "latest.json") | .size' <<<"$assets")" \
  || die "cannot read the channel asset size"
[[ "$size" == "$(wc -c < "$TMP/latest.json" | tr -d ' ')" ]] \
  || die "channel size $size != local $(wc -c < "$TMP/latest.json" | tr -d ' ')"
updated_at="$(jq -r '.assets[] | select(.name == "latest.json") | .updated_at' <<<"$assets")" \
  || die "cannot read the channel asset timestamp"
ts="$(date -u -d "$updated_at" +%s 2>/dev/null || echo 0)"
[[ "$ts" -ge "$START_EPOCH" ]] || die "channel asset updated_at $updated_at predates this upload"

# The CDN serves the previous body for a while; converge on a hash match.
url="https://github.com/$REPO/releases/download/$CHANNEL/latest.json"
local_sha="$(sha256sum "$TMP/latest.json" | cut -d' ' -f1)"
served_ok=false
for i in $(seq 1 "$PROBE_TRIES"); do
  served_sha="$(curl -sfL "$url" 2>/dev/null | sha256sum | cut -d' ' -f1 || true)"
  if [[ -n "${served_sha:-}" && "$served_sha" == "$local_sha" ]]; then
    served_ok=true
    break
  fi
  [[ "$i" -lt "$PROBE_TRIES" ]] && sleep "$PROBE_SLEEP"
done
$served_ok || die "served bytes never matched after $PROBE_TRIES probes"
FINISHED=true

# A stray latest.json on the version release is the wrong-target incident
# class; remove them automatically and say so.
stray_ids="$(gh api "repos/$REPO/releases/tags/$TAG" \
  | jq -r '.assets[] | select(.name == "latest.json") | .id' || true)"
for id in $stray_ids; do
  gh api -X DELETE "repos/$REPO/releases/assets/$id" >/dev/null
  note "removed a stray latest.json from the $TAG release (wrong-target residue)"
done

note "updates channel $CHANNEL serves version $TAG (asset verified, served bytes matched)"
