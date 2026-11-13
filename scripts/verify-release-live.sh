#!/usr/bin/env bash
# Post-publish verification sweep: the release "not done until green" gate.
# Encodes the probe traps recorded in docs/dev/release-protocol.md (download
# probes need redirect-following, F-Droid versioncodes are child elements,
# apt pool paths are PascalCase under full segments, gh run list needs the
# full commit SHA, CDN propagation needs polling). --report prints the table
# and always exits 0; without it, any FAIL exits 1.
#
# usage: verify-release-live.sh <tag> [--report] [--latest <expected-latest>]
#        [--packages-sha <full-sha>]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=release-common.sh disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/release-common.sh"

TAG="" REPORT=false EXPECTED_LATEST="" PACKAGES_SHA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report) REPORT=true ;;
    --latest) EXPECTED_LATEST="$2"; shift ;;
    --packages-sha) PACKAGES_SHA="$2"; shift ;;
    -*) echo "unknown flag $1" >&2; exit 1 ;;
    *) TAG="$1" ;;
  esac
  shift
done
[[ -n "$TAG" ]] || { echo "usage: $0 <tag> [--report] [--latest X] [--packages-sha <full-sha>]" >&2; exit 1; }
[[ -n "$EXPECTED_LATEST" ]] || EXPECTED_LATEST="$TAG"
[[ -z "$PACKAGES_SHA" || "$PACKAGES_SHA" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "ERROR: --packages-sha wants a full 40-char commit SHA" >&2; exit 1; }
cd "$ROOT"
command -v gh >/dev/null 2>&1 || { echo "ERROR: gh is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required" >&2; exit 1; }
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo baluard-org/baluard)"
CHANNEL="updates-stable"
[[ "$TAG" == *-* ]] && CHANNEL="updates-beta"
# The tag is the source of truth: a checkout mid-bump must still verify the
# cut version's artifacts.
VERSION="${TAG%%-*}"
VCODE="$(version_code "$VERSION")"
VERIFY_TRIES="${BALUARD_VERIFY_TRIES:-3}"
VERIFY_SLEEP="${BALUARD_VERIFY_SLEEP:-5}"

PASS=0; FAIL=0; WARN=0; FAILED_NAMES=()
check() {  # check <name> <ok-result> <detail>
  if [[ "$2" == ok ]]; then
    echo "PASS $1"; PASS=$((PASS + 1))
  elif [[ "$2" == warn ]]; then
    echo "WARN $1 ($3)"; WARN=$((WARN + 1))
  else
    echo "FAIL $1 ($3)"; FAIL=$((FAIL + 1)); FAILED_NAMES+=("$1")
  fi
}
# A range probe keeps the sweep from downloading whole release assets;
# GitHub's asset redirects serve 206 for ranges (200 when they do not).
http_code() { curl -s -o /dev/null -w '%{http_code}' -L -r 0-0 --max-time 20 "$1" 2>/dev/null || true; }
# shellcheck disable=SC2329  # invoked via retry_ok
asset_ok() { local c; c="$(http_code "$1")"; [[ "$c" == 200 || "$c" == 206 ]]; }

# A bounded retry so a verdict is stable right after a publish: CDN and
# Pages propagation lag single-shot probes.
retry_ok() {  # retry_ok <probe-fn> <args...>
  local i
  for i in $(seq 1 "$VERIFY_TRIES"); do
    "$@" && return 0
    [[ "$i" -lt "$VERIFY_TRIES" ]] && sleep "$VERIFY_SLEEP"
  done
  return 1
}

# 1. releases/latest resolves to the expected tag (prerelease cuts keep the
#    previous latest; pass --latest to pin the expectation).
got="$(gh api "repos/$REPO/releases/latest" -q .tag_name 2>/dev/null || echo unreachable)"
if [[ "$got" == "$EXPECTED_LATEST" ]]; then check "releases/latest" ok; else check "releases/latest" fail "got $got, expected $EXPECTED_LATEST"; fi

# 2. Twelve stable-name tag-scoped assets answer 200 (range probes).
for n in "${STABLE_ASSETS[@]}"; do
  if retry_ok asset_ok "https://github.com/$REPO/releases/download/$TAG/$n"; then
    check "asset/$n" ok
  else
    check "asset/$n" fail "HTTP $(http_code "https://github.com/$REPO/releases/download/$TAG/$n")"
  fi
done

# 3. The packages-site deploy for the republish SHA landed. GitHub evaluates
#    --commit against the full head SHA; a short prefix matches nothing.
#    A still-running deploy is retried, not failed outright.
# shellcheck disable=SC2329  # invoked via retry_ok
deploy_ok() {
  local run_json st cc
  run_json="$(gh run list --repo baluard-org/baluard-packages --workflow deploy-pages.yml \
      --commit "$PACKAGES_SHA" --limit 1 --json status,conclusion 2>/dev/null || echo '[]')"
  st="$(jq -r '.[0].status // "none"' <<<"$run_json" 2>/dev/null || echo none)"
  cc="$(jq -r '.[0].conclusion // "none"' <<<"$run_json" 2>/dev/null || echo none)"
  [[ "$st" == completed && "$cc" == success ]]
}
deploy_detail() {
  local run_json st cc
  run_json="$(gh run list --repo baluard-org/baluard-packages --workflow deploy-pages.yml \
      --commit "$PACKAGES_SHA" --limit 1 --json status,conclusion 2>/dev/null || echo '[]')"
  st="$(jq -r '.[0].status // "none"' <<<"$run_json" 2>/dev/null || echo none)"
  cc="$(jq -r '.[0].conclusion // "none"' <<<"$run_json" 2>/dev/null || echo none)"
  echo "status=$st conclusion=$cc"
}
if [[ -n "$PACKAGES_SHA" ]]; then
  if retry_ok deploy_ok; then check "packages-deploy" ok
  else check "packages-deploy" fail "$(deploy_detail)"; fi
elif $REPORT; then
  check "packages-deploy" warn "pass --packages-sha <republish-sha> to check the deploy run"
else
  check "packages-deploy" fail "the deploy run is not gated without --packages-sha <republish-sha>"
fi

# 4. F-Droid index carries the new versionCode as a CHILD ELEMENT (the
#    attribute form reads nothing).
# shellcheck disable=SC2329  # invoked via retry_ok
fdroid_ok() {
  fdroid="$(curl -sfL "https://packages.baluard.app/fdroid/repo/index.xml" 2>/dev/null || true)"
  grep -q "<versioncode>$VCODE</versioncode>" <<<"$fdroid"
}
if retry_ok fdroid_ok; then
  check "fdroid-versioncode" ok
else
  check "fdroid-versioncode" fail "served index lacks versioncode $VCODE"
fi

# 5. apt InRelease and the PascalCase pool deb answer 200.
if retry_ok asset_ok "https://packages.baluard.app/dists/stable/InRelease"; then
  check "apt-InRelease" ok
else
  check "apt-InRelease" fail "HTTP $(http_code "https://packages.baluard.app/dists/stable/InRelease")"
fi
if retry_ok asset_ok "https://packages.baluard.app/pool/main/b/baluard/Baluard_${VERSION}_amd64.deb"; then
  check "pool-deb" ok
else
  check "pool-deb" fail "HTTP $(http_code "https://packages.baluard.app/pool/main/b/baluard/Baluard_${VERSION}_amd64.deb")"
fi

# 6. The updates channel serves this release's manifest version.
# shellcheck disable=SC2329  # invoked via retry_ok
channel_ok() { [[ "$(served_manifest_version "$REPO" "$CHANNEL")" == "$TAG" ]]; }
if retry_ok channel_ok; then
  check "updates-channel" ok
else
  served="$(served_manifest_version "$REPO" "$CHANNEL")"
  check "updates-channel" fail "served ${served:-nothing}, expected $TAG"
fi

# 7. The author-owned package-site content survived (re-check without a sync).
owned_err="$(check_author_owned_files "${BALUARD_PACKAGES_SITE:-$ROOT/../baluard-packages}" 2>&1 || true)"
if [[ -z "$owned_err" ]]; then
  check "author-owned-files" ok
else
  check "author-owned-files" fail "$owned_err"
fi

# 8. The release body ends with the standing closer (own line, blank line
#    before it). The convention lives in release-protocol.md; this gate
#    keeps the published bytes honest.
body="$(gh release view "$TAG" --repo "$REPO" --json body -q .body 2>/dev/null || echo '')"
last_line="$(awk 'NF {l=$0} END {print l}' <<<"$body")"
if [[ "$last_line" == "As always, thanks for trying Baluard :)" ]]; then
  check "notes-closer" ok
else
  check "notes-closer" fail "the body must end with the standing closer; last non-empty line: ${last_line:-none}"
fi

echo "---"
echo "release-verify: $PASS passed, $FAIL failed, $WARN warned"
if [[ "$FAIL" -gt 0 ]]; then
  echo "failed: ${FAILED_NAMES[*]}"
  $REPORT && { echo "--report: exiting 0 despite failures"; exit 0; }
  exit 1
fi
$REPORT && echo "--report: all green"
exit 0
