#!/usr/bin/env bash
# Hermetic suite for scripts/publish-updates-manifest.sh: fake gh/curl/node
# shims only, PATH-first, network unreachable. Run via just test-release-scripts
# or directly: bash scripts/tests/test-publish-updates-manifest.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="$SCRIPT_DIR/../publish-updates-manifest.sh"
TMP="$(mktemp -d)"
PASS=0
FAILED=0

cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

log() { echo "test-publish-updates-manifest: $*"; }

# ---------------------------------------------------------------- scaffolding
make_repo() {
  local dir="$1"
  mkdir -p "$dir/scripts" "$dir/release-upload" "$dir/bin"
  cp "$UNDER_TEST" "$dir/scripts/"
  chmod +x "$dir/scripts/publish-updates-manifest.sh"
  # Fake node: stands in for generate-updates-manifest.mjs (that script has
  # its own suite). Honors --tag/--out, writes the version the case wants.
  cat > "$dir/bin/node" <<'EOF'
#!/usr/bin/env bash
out=""; tag=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "${SUB_NODE_FAIL:-}" ]] && exit 1
printf '{"version":"%s","platforms":{"linux-x86_64-appimage":{"url":"u","signature":"sig"}}}\n' \
  "${SUB_NODE_VERSION:-$tag}" > "$out"
EOF
  # Fake gh: dispatches the exact subcommands the script may call. Channel
  # state is one file so upload/download/api stay mutually consistent.
  cat > "$dir/bin/gh" <<'EOF'
#!/usr/bin/env bash
STATE="${SUB_STATE:?}"
LOG="$STATE/gh.log"
echo "gh $*" >> "$LOG"
cmd="$1"; shift
case "$cmd" in
  release)
    sub="$1"; shift
    case "$sub" in
      view) echo "Release notes body" ;;
      download)
        # gh release download <channel> --pattern latest.json --dir <dir>
        dir=""
        while [[ $# -gt 0 ]]; do case "$1" in --dir) dir="$2"; shift 2 ;; *) shift ;; esac; done
        if [[ -n "${SUB_CHANNEL_HAS_BACKUP:-}" ]]; then
          printf '{"version":"OLD"}\n' > "$dir/latest.json"
        fi
        ;;
      upload)
        f=""
        while [[ $# -gt 0 ]]; do case "$1" in --clobber) shift ;; *) f="$2"; shift 2 ;; esac; done
        echo "upload $f" >> "$LOG"
        if [[ -z "${SUB_UPLOAD_NOOP:-}" ]]; then cp "$f" "$STATE/channel.json"; fi
        ;;
    esac ;;
  repo) echo "baluard-org/baluard" ;;
  api)
    method="GET"; url=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -X|--method) method="$2"; shift 2 ;;
        *) url="$1"; shift ;;
      esac
    done
    if [[ "$method" == "DELETE" ]]; then echo "delete $url" >> "$LOG"; exit 0; fi
    sz=0
    [[ -f "$STATE/channel.json" ]] && sz=$(wc -c < "$STATE/channel.json")
    if [[ "$url" == *"releases/tags/${SUB_API_TAG:-updates-stable}"* ]]; then
      if [[ -n "${SUB_API_ZERO:-}" ]]; then
        echo '{"assets":[]}'
      else
        s="$sz"
        [[ -n "${SUB_API_SIZE_MISMATCH:-}" ]] && s=$((sz + 1))
        ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '{"assets":[{"name":"latest.json","size":%s,"updated_at":"%s"}]}' "$s" "$ts"
      fi
    else
      # version release: strays knob decides whether latest.json sits there
      if [[ -n "${SUB_STRAY:-}" ]]; then
        echo '{"assets":[{"name":"latest.json","id":4321,"size":1,"updated_at":"2026-01-01T00:00:00Z"}]}'
      else
        echo '{"assets":[{"name":"Baluard-amd64.deb","id":9,"size":2,"updated_at":"2026-01-01T00:00:00Z"}]}'
      fi
    fi ;;
esac
EOF
  # Fake curl: serves the channel state as the CDN would, with stale-body
  # knobs for the propagation cases.
  cat > "$dir/bin/curl" <<'EOF'
#!/usr/bin/env bash
STATE="${SUB_STATE:?}"
echo "curl $*" >> "$STATE/curl.log"
n=$(cat "$STATE/serve_count" 2>/dev/null || echo 0)
echo $((n + 1)) > "$STATE/serve_count"
if [[ -n "${SUB_SERVE_STALE_FOREVER:-}" ]]; then
  printf '{"version":"OLD"}\n'
elif [[ -n "${SUB_SERVE_STALE:-}" ]] && [[ "$n" -lt "$SUB_SERVE_STALE" ]]; then
  printf '{"version":"OLD"}\n'
else
  cat "$STATE/channel.json" 2>/dev/null || printf '{"version":"OLD"}\n'
fi
EOF
  chmod +x "$dir/bin/node" "$dir/bin/gh" "$dir/bin/curl"
  git -C "$dir" init -q
  git -C "$dir" config user.email t@t && git -C "$dir" config user.name t
  git -C "$dir" add -A && git -C "$dir" commit -qm init
  printf 'updater bytes\n' > "$dir/release-upload/Baluard-amd64.AppImage"
  cp "$dir/release-upload/Baluard-amd64.AppImage" "$dir/release-upload/Baluard-amd64.AppImage.sig"
  cp "$dir/release-upload/Baluard-amd64.AppImage" "$dir/release-upload/Baluard-arm64.app.tar.gz"
  cp "$dir/release-upload/Baluard-amd64.AppImage" "$dir/release-upload/Baluard-arm64.app.tar.gz.sig"
  cp "$dir/release-upload/Baluard-amd64.AppImage" "$dir/release-upload/Baluard-amd64-setup.exe"
  cp "$dir/release-upload/Baluard-amd64.AppImage" "$dir/release-upload/Baluard-amd64-setup.exe.sig"
}

# Run with a per-case knob environment; inherited machine knobs are scrubbed.
UNSET=(SUB_NODE_FAIL SUB_NODE_VERSION SUB_CHANNEL_HAS_BACKUP SUB_UPLOAD_NOOP
  SUB_API_ZERO SUB_API_SIZE_MISMATCH SUB_API_TAG SUB_STRAY SUB_SERVE_STALE
  SUB_SERVE_STALE_FOREVER)
run_case() {
  local name="$1"; shift
  local expect_rc="$1"; shift
  local repo="$TMP/$name"
  make_repo "$repo"
  mkdir -p "$repo/state" && : > "$repo/state/gh.log" && : > "$repo/state/curl.log"
  printf '{"version":"OLD"}\n' > "$repo/state/channel.json"
  # Forward any knob the case set as a shell variable; the -u scrub first
  # clears inherited machine env, then declared knobs are re-added explicitly.
  local knob_args=() v
  for v in SUB_NODE_FAIL SUB_NODE_VERSION SUB_CHANNEL_HAS_BACKUP SUB_UPLOAD_NOOP \
           SUB_API_ZERO SUB_API_SIZE_MISMATCH SUB_API_TAG SUB_STRAY \
           SUB_SERVE_STALE SUB_SERVE_STALE_FOREVER SUB_PROBE_TRIES SUB_PROBE_SLEEP; do
    [[ -n "${!v:-}" ]] && knob_args+=("$v=${!v}")
  done
  set +e
  ( cd "$repo" && env "${UNSET[@]/#/-u}" \
      SUB_STATE="$repo/state" \
      "${knob_args[@]}" \
      BALUARD_MANIFEST_PROBE_TRIES="${SUB_PROBE_TRIES:-3}" \
      BALUARD_MANIFEST_PROBE_SLEEP="${SUB_PROBE_SLEEP:-0}" \
      PATH="$repo/bin:$PATH" \
      bash scripts/publish-updates-manifest.sh "$@" ) > "$repo/out.log" 2> "$repo/err.log"
  local rc=$?
  set -e
  if [[ "$rc" != "$expect_rc" ]]; then
    log "FAIL $name: expected rc=$expect_rc got rc=$rc"
    sed 's/^/    out: /' "$repo/out.log" | head -5
    sed 's/^/    err: /' "$repo/err.log" | head -5
    FAILED=$((FAILED + 1))
  fi
  echo "$repo"
}

assert_log() {
  local repo="$1" pattern="$2" want="$3"
  local got=0
  if grep -qE -- "$pattern" "$repo/state/gh.log" 2>/dev/null || \
     grep -qE -- "$pattern" "$repo/state/curl.log" 2>/dev/null; then got=1; fi
  if [[ "$got" != "$want" ]]; then
    log "FAIL $(basename "$repo"): log pattern '$pattern' present=$got want=$want"
    FAILED=$((FAILED + 1))
  fi
}

# ---------------------------------------------------------------------- cases
r=$(run_case happy 0 0.4.6)
assert_log "$r" "upload .*latest.json --clobber" 1 || true
grep -q "release upload updates-stable" "$r/state/gh.log" \
  || { log "FAIL happy: upload line lacks the literal channel tag"; FAILED=$((FAILED+1)); }
grep -qE "( -sfL| -L)" "$r/state/curl.log" \
  || { log "FAIL happy: served probe did not follow redirects"; FAILED=$((FAILED+1)); }
grep -q "serves version 0.4.6" "$r/out.log" \
  || { log "FAIL happy: missing success line"; FAILED=$((FAILED+1)); }
grep -q "delete " "$r/state/gh.log" \
  && { log "FAIL happy: unexpected stray DELETE"; FAILED=$((FAILED+1)); } || true
PASS=$((PASS + 1))

r=$(run_case dry-run 0 --dry-run 0.4.6)
grep -q "release upload" "$r/state/gh.log" \
  && { log "FAIL dry-run: an upload ran"; FAILED=$((FAILED+1)); } || true
PASS=$((PASS + 1))

export SUB_NODE_FAIL=1
r=$(run_case generator-failure 1 0.4.6)
unset SUB_NODE_FAIL
grep -q "release upload" "$r/state/gh.log" \
  && { log "FAIL generator-failure: upload ran after failed generation"; FAILED=$((FAILED+1)); } || true
grep -qi "generation failed" "$r/err.log" \
  || { log "FAIL generator-failure: no diagnosis"; FAILED=$((FAILED+1)); }
PASS=$((PASS + 1))

export SUB_NODE_VERSION=9.9.9
r=$(run_case version-mismatch 1 0.4.6)
unset SUB_NODE_VERSION
grep -q "release upload" "$r/state/gh.log" \
  && { log "FAIL version-mismatch: upload ran"; FAILED=$((FAILED+1)); } || true
PASS=$((PASS + 1))

make_repo "$TMP/missing-name"
rm "$TMP/missing-name/release-upload/Baluard-amd64-setup.exe"
mkdir -p "$TMP/missing-name/state"; : > "$TMP/missing-name/state/gh.log"
set +e
( cd "$TMP/missing-name" && env "${UNSET[@]/#/-u}" SUB_STATE="$TMP/missing-name/state" PATH="$TMP/missing-name/bin:$PATH" \
    bash scripts/publish-updates-manifest.sh 0.4.6 ) > "$TMP/missing-name/out.log" 2>&1
rc=$?
set -e
[[ $rc -eq 1 ]] || { log "FAIL missing-name: expected rc=1 got $rc"; FAILED=$((FAILED+1)); }
grep -q "Baluard-amd64-setup.exe" "$TMP/missing-name/out.log" \
  || { log "FAIL missing-name: no artifact named"; FAILED=$((FAILED+1)); }
grep -q "release upload" "$TMP/missing-name/state/gh.log" \
  && { log "FAIL missing-name: upload ran"; FAILED=$((FAILED+1)); } || true
PASS=$((PASS + 1))

export SUB_UPLOAD_NOOP=1 SUB_CHANNEL_HAS_BACKUP=1
r=$(run_case silent-noop 1 0.4.6)
unset SUB_UPLOAD_NOOP SUB_CHANNEL_HAS_BACKUP
uploads=$(grep -c "upload .*latest.json" "$r/state/gh.log" || true)
[[ "$uploads" -ge 2 ]] \
  || { log "FAIL silent-noop: backup was not re-uploaded (uploads=$uploads)"; FAILED=$((FAILED+1)); }
grep -qiE "publish failed|manual recovery" "$r/err.log" "$r/out.log" \
  || { log "FAIL silent-noop: no recovery note"; FAILED=$((FAILED+1)); }
PASS=$((PASS + 1))

export SUB_API_SIZE_MISMATCH=1 SUB_CHANNEL_HAS_BACKUP=1
r=$(run_case size-mismatch 1 0.4.6)
unset SUB_API_SIZE_MISMATCH SUB_CHANNEL_HAS_BACKUP
grep -qiE "publish failed|manual recovery" "$r/err.log" "$r/out.log" \
  || { log "FAIL size-mismatch: no rollback"; FAILED=$((FAILED+1)); }
PASS=$((PASS + 1))

export SUB_SERVE_STALE=2
r=$(run_case stale-then-converge 0 0.4.6)
unset SUB_SERVE_STALE
PASS=$((PASS + 1))

export SUB_SERVE_STALE_FOREVER=1 SUB_PROBE_TRIES=2
r=$(run_case stale-forever 1 0.4.6)
unset SUB_SERVE_STALE_FOREVER SUB_PROBE_TRIES
grep -qiE "publish failed|manual recovery" "$r/err.log" "$r/out.log" \
  || { log "FAIL stale-forever: no rollback"; FAILED=$((FAILED+1)); }
PASS=$((PASS + 1))

export SUB_STRAY=1
r=$(run_case stray-latest 0 0.4.6)
unset SUB_STRAY
grep -q "delete " "$r/state/gh.log" \
  || { log "FAIL stray-latest: stray latest.json was not deleted"; FAILED=$((FAILED+1)); }
PASS=$((PASS + 1))

export SUB_API_TAG=updates-beta
r=$(run_case beta-channel 0 0.4.6-beta.1)
unset SUB_API_TAG
grep -q "release upload updates-beta" "$r/state/gh.log" \
  || { log "FAIL beta-channel: beta tag did not route to updates-beta"; FAILED=$((FAILED+1)); }
PASS=$((PASS + 1))

# --------------------------------------------------------------------- result
if [[ "$FAILED" -gt 0 ]]; then
  log "FAIL: $FAILED failing assertions across $PASS cases"
  exit 1
fi
log "PASS ($PASS cases)"
