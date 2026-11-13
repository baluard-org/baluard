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
cd "$ROOT"
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo baluard-org/baluard)"
CHANNEL="updates-stable"
[[ "$TAG" == *-* ]] && CHANNEL="updates-beta"
VERSION="$(version_from_cargo "$ROOT")"
VCODE="$(version_code "$VERSION")"

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
http_code() { curl -s -o /dev/null -w '%{http_code}' -L "$1" 2>/dev/null || echo 000; }

# 1. releases/latest resolves to the expected tag (prerelease cuts keep the
#    previous latest; pass --latest to pin the expectation).
got="$(gh api "repos/$REPO/releases/latest" -q .tag_name 2>/dev/null || echo unreachable)"
if [[ "$got" == "$EXPECTED_LATEST" ]]; then check "releases/latest" ok; else check "releases/latest" fail "got $got, expected $EXPECTED_LATEST"; fi

# 2. Twelve stable-name tag-scoped assets answer 200.
for n in "${STABLE_ASSETS[@]}"; do
  code="$(http_code "https://github.com/$REPO/releases/download/$TAG/$n")"
  if [[ "$code" == 200 ]]; then check "asset/$n" ok; else check "asset/$n" fail "HTTP $code"; fi
done

# 3. The packages-site deploy for the republish SHA landed. GitHub evaluates
#    --commit against the full head SHA; a short prefix matches nothing.
if [[ -n "$PACKAGES_SHA" ]]; then
  run_json="$(gh run list --repo baluard-org/baluard-packages --commit "$PACKAGES_SHA" --limit 1 --json status,conclusion 2>/dev/null || echo '[]')"
  st="$(jq -r '.[0].status // "none"' <<<"$run_json")"
  cc="$(jq -r '.[0].conclusion // "none"' <<<"$run_json")"
  if [[ "$st" == completed && "$cc" == success ]]; then check "packages-deploy" ok; else check "packages-deploy" fail "status=$st conclusion=$cc"; fi
else
  check "packages-deploy" warn "pass --packages-sha <republish-sha> to check the deploy run"
fi

# 4. F-Droid index carries the new versionCode as a CHILD ELEMENT (the
#    attribute form reads nothing).
fdroid="$(curl -sfL "https://packages.baluard.app/fdroid/repo/index.xml" 2>/dev/null || true)"
if grep -q "<versioncode>$VCODE</versioncode>" <<<"$fdroid"; then
  check "fdroid-versioncode" ok
else
  check "fdroid-versioncode" fail "served index lacks versioncode $VCODE"
fi

# 5. apt InRelease and the PascalCase pool deb answer 200.
code="$(http_code "https://packages.baluard.app/dists/stable/InRelease")"
if [[ "$code" == 200 ]]; then check "apt-InRelease" ok; else check "apt-InRelease" fail "HTTP $code"; fi
code="$(http_code "https://packages.baluard.app/pool/main/b/baluard/Baluard_${VERSION}_amd64.deb")"
if [[ "$code" == 200 ]]; then check "pool-deb" ok; else check "pool-deb" fail "HTTP $code"; fi

# 6. The updates channel serves this release's manifest version.
served="$(served_manifest_version "$REPO" "$CHANNEL")"
if [[ "$served" == "$TAG" ]]; then check "updates-channel" ok; else check "updates-channel" fail "served ${served:-nothing}, expected $TAG"; fi

# 7. The author-owned package-site content survived (re-check without a sync).
owned_err="$(check_author_owned_files "${BALUARD_PACKAGES_SITE:-$ROOT/../baluard-packages}" 2>&1 || true)"
if [[ -z "$owned_err" ]]; then
  check "author-owned-files" ok
else
  check "author-owned-files" fail "$owned_err"
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
