#!/usr/bin/env bash
# Hermetic suite for scripts/verify-release-live.sh: fake gh/curl shims only,
# PATH-first, network unreachable. Covers the parsing traps (F-Droid child
# element versioncodes, the full commit SHA for gh run list, channel version
# read-back) and the --report / gate exit modes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
PASS=0
FAILED=0
cleanup() { [[ -n "${KEEP_TMP:-}" ]] || rm -rf "$TMP"; }
trap cleanup EXIT
log() { echo "test-verify-release-live: $*"; }

FULLSHA="0123456789abcdef0123456789abcdef01234567"

make_repo() {
  local dir="$1"
  mkdir -p "$dir/scripts" "$dir/bin"
  cp "$SCRIPT_DIR/../verify-release-live.sh" "$dir/scripts/"
  cp "$SCRIPT_DIR/../release-common.sh" "$dir/scripts/"
  chmod +x "$dir/scripts/verify-release-live.sh"
  # A minimal package-site sibling for the author-owned check; cases delete
  # from it to force failures.
  mkdir -p "$dir/../baluard-packages/arch" "$dir/../baluard-packages/.github/workflows"
  for f in baluard.repo baluard.sources index.html CNAME .nojekyll .gitignore; do
    printf 'x\n' > "$dir/../baluard-packages/$f"
  done
  printf 'c\n' > "$dir/../baluard-packages/arch/baluard.conf"
  printf 'w\n' > "$dir/../baluard-packages/.github/workflows/deploy-pages.yml"

  cat > "$dir/bin/gh" <<'EOF'
#!/usr/bin/env bash
STATE="${SUB_STATE:?}"
echo "gh $*" >> "$STATE/gh.log"
case "$1 $2" in
  "repo view") echo "baluard-org/baluard" ;;
  "api repos/baluard-org/baluard/releases/latest")
    # the script reads -q .tag_name; gh prints the stripped value
    echo "${SUB_LATEST_TAG:-0.4.6}" ;;
  "run list")
    # --commit <sha>: match only the full 40-char fixture SHA.
    for a in "$@"; do
      if [[ "$a" == "$FULLSHA_VALUE" ]]; then
        printf '[{"status":"%s","conclusion":"%s"}]' "${SUB_RUN_STATUS:-completed}" "${SUB_RUN_CONCLUSION:-success}"
        exit 0
      fi
    done
    echo '[]' ;;
  *) echo '[]' ;;
esac
EOF
  cat > "$dir/bin/curl" <<'EOF'
#!/usr/bin/env bash
STATE="${SUB_STATE:?}"
url="${@: -1}"
echo "curl $*" >> "$STATE/curl.log"
case "$url" in
  *releases/download/*/Baluard-*|*releases/download/*/SHA256SUMS|*releases/download/*/updater.pub)
    printf '200' ;;
  *releases/download/*/latest.json)
    printf '{"version":"%s"}' "${SUB_CHANNEL_VERSION:-0.4.6}" ;;
  *fdroid/repo/index.xml)
    if [[ "${SUB_FDROID_MODE:-child}" == attr ]]; then
      printf '<application><package versioncode="4006" versionname="0.4.6"></package></application>'
    elif [[ "$SUB_FDROID_MODE" == missing ]]; then
      printf '<application><package versionname="0.4.6"></package></application>'
    else
      printf '<application><package versionname="0.4.6"><versioncode>4006</versioncode></package></application>'
    fi ;;
  *InRelease) printf '200' ;;
  *pool/main/b/baluard/*) printf '200' ;;
  *) exit 7 ;;
esac
EOF
  # curl's exit code 7 (connection failed) becomes HTTP 000 via || true.
  chmod +x "$dir/bin/gh" "$dir/bin/curl"
  # git init alone: no fixture revision (the sweep reads the tag, not the
  # tree, and recording one would inherit the user's signing config).
  git -C "$dir" init -q
  echo "$FULLSHA" > "$dir/.fixture-sha"
}

UNSET=(SUB_LATEST_TAG SUB_RUN_STATUS SUB_RUN_CONCLUSION SUB_FDROID_MODE SUB_CHANNEL_VERSION SUB_STATE)
for _v in "${UNSET[@]}"; do eval "$_v="; done
LAST_REPO=""
run_case() {
  local name="$1" expect_rc="$2"; shift 2
  local repo="$TMP/$name"
  make_repo "$repo"
  mkdir -p "$repo/state"; : > "$repo/state/gh.log"; : > "$repo/state/curl.log"
  local knob_args=() v
  for v in SUB_LATEST_TAG SUB_RUN_STATUS SUB_RUN_CONCLUSION SUB_FDROID_MODE SUB_CHANNEL_VERSION FULLSHA_VALUE; do
    [[ -n "${!v:-}" ]] && knob_args+=("$v=${!v}")
  done
  set +e
  ( cd "$repo" && env "${UNSET[@]/#/-u}" SUB_STATE="$repo/state" \
      FULLSHA_VALUE="$FULLSHA" \
      BALUARD_VERIFY_SLEEP=0 \
      "${knob_args[@]}" \
      PATH="$repo/bin:$PATH" \
      bash scripts/verify-release-live.sh "$@" ) > "$repo/out.log" 2> "$repo/err.log"
  local rc=$?
  set -e
  LAST_REPO="$repo"
  if [[ "$rc" != "$expect_rc" ]]; then
    log "FAIL $name: expected rc=$expect_rc got rc=$rc"
    head -5 "$repo/out.log" | sed 's/^/    /'; head -3 "$repo/err.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1))
  fi
}

run_case happy 0 0.4.6 --packages-sha "$FULLSHA"
r="$LAST_REPO"
grep -q "release-verify: .* 0 failed, 0 warned" "$r/out.log" \
  || { log "FAIL happy: not all green"; FAILED=$((FAILED + 1)); }
grep -qF "$FULLSHA" "$r/state/gh.log" \
  || { log "FAIL happy: run list did not carry the full SHA"; FAILED=$((FAILED + 1)); }
grep -q "PASS fdroid-versioncode" "$r/out.log" \
  || { log "FAIL happy: fdroid child-element read failed"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

export SUB_FDROID_MODE=attr
run_case fdroid-attr 1 0.4.6
r="$LAST_REPO"
unset SUB_FDROID_MODE
grep -q "FAIL fdroid-versioncode" "$r/out.log" \
  || { log "FAIL fdroid-attr: attribute-only index did not fail"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

SUB_FDROID_MODE=missing
run_case fdroid-missing 1 0.4.6
r="$LAST_REPO"
unset SUB_FDROID_MODE
grep -q "FAIL fdroid-versioncode" "$r/out.log" \
  || { log "FAIL fdroid-missing: codeless index not caught"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

export SUB_LATEST_TAG=0.4.5
run_case latest-mismatch 1 0.4.6
r="$LAST_REPO"
unset SUB_LATEST_TAG
grep -q "FAIL releases/latest" "$r/out.log" \
  || { log "FAIL latest-mismatch: no latest failure"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

# --latest pins the expectation for prerelease cuts; the channel still reads
# the cut tag.
export SUB_LATEST_TAG=0.4.5
run_case latest-pinned 0 0.4.6 --latest 0.4.5 --packages-sha "$FULLSHA"
r="$LAST_REPO"
unset SUB_LATEST_TAG
grep -q "PASS releases/latest" "$r/out.log" \
  || { log "FAIL latest-pinned: pinned expectation did not pass"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

export SUB_FDROID_MODE=attr
run_case report-mode 0 0.4.6 --report
r="$LAST_REPO"
unset SUB_FDROID_MODE
grep -q "FAIL fdroid-versioncode" "$r/out.log" \
  || { log "FAIL report-mode: failures not reported"; FAILED=$((FAILED + 1)); }
grep -q "exiting 0 despite failures" "$r/out.log" \
  || { log "FAIL report-mode: no report exit note"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

run_case no-sha-gate 1 0.4.6
grep -q "FAIL packages-deploy" "$LAST_REPO/out.log" \
  || { log "FAIL no-sha-gate: gate mode did not refuse a missing SHA"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

run_case no-sha-report 0 0.4.6 --report
grep -q "WARN packages-deploy" "$LAST_REPO/out.log" \
  || { log "FAIL no-sha-report: report mode lost its WARN"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

export SUB_CHANNEL_VERSION=0.4.5
run_case channel-stale 1 0.4.6
r="$LAST_REPO"
unset SUB_CHANNEL_VERSION
grep -q "FAIL updates-channel" "$r/out.log" \
  || { log "FAIL channel-stale: stale channel not caught"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

# Author-owned check: delete one file from the sibling, expect a FAIL line.
repo="$TMP/owned-missing"
make_repo "$repo"
rm "$repo/../baluard-packages/CNAME"
mkdir -p "$repo/state"; : > "$repo/state/gh.log"; : > "$repo/state/curl.log"
set +e
( cd "$repo" && env "${UNSET[@]/#/-u}" SUB_STATE="$repo/state" \
    PATH="$repo/bin:$PATH" \
    bash scripts/verify-release-live.sh 0.4.6 --report ) > "$repo/out.log" 2>&1
rc=$?
set -e
[[ $rc -eq 0 ]] || { log "FAIL owned-missing: report mode exited $rc"; FAILED=$((FAILED + 1)); }
grep -q "FAIL author-owned-files" "$repo/out.log" \
  || { log "FAIL owned-missing: survival failure not reported"; FAILED=$((FAILED + 1)); }
PASS=$((PASS + 1))

if [[ "$FAILED" -gt 0 ]]; then
  log "FAIL: $FAILED failing assertions across $PASS cases"
  exit 1
fi
log "PASS ($PASS cases)"
