#!/usr/bin/env bash
# Store verdicts for the browser extension without submitting anything:
# AMO version status via the API v5 JWT auth, Chrome item status via the
# Web Store v2 API. `--guard <version>` is the pre-submit gate: refuses
# (exit 1) when a store's newest entry is still in review and differs from
# <version>, so a new submission never stacks on an unfinished review. A
# probe that cannot reach a store warns and passes -- the guard refuses on
# a positive in-review verdict only, never on a network failure or an
# unconfigured store (the submit script treats unconfigured as a skip).
#
# usage: extension-verdicts.sh [--guard <version>]
set -euo pipefail

AMO_ID="${BALUARD_AMO_ADDON_ID:-baluard@actitud.xyz}"
CHROME_ID="${BALUARD_CHROME_EXTENSION_ID:-}"
CHROME_PUBLISHER="${BALUARD_CHROME_PUBLISHER_ID:-}"
GUARD_VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --guard)
      [[ -n "${2:-}" ]] || { echo "usage: $0 [--guard <version>]" >&2; exit 1; }
      GUARD_VERSION="$2"; shift ;;
    -*) echo "unknown flag $1" >&2; exit 1 ;;
    "") ;;
  esac
  shift
done

for tool in curl jq openssl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

REFUSALS=()
CLEANUP_DIRS=()

cleanup() { local d; for d in "${CLEANUP_DIRS[@]}"; do rm -rf "$d"; done; }
trap cleanup EXIT

# ── AMO ─────────────────────────────────────────────────────────────────────
amo_verdict() {
  if [[ -z "${BALUARD_AMO_JWT_KEY:-}" || -z "${BALUARD_AMO_JWT_SECRET:-}" ]]; then
    if [[ -n "${BALUARD_AMO_JWT_KEY:-}${BALUARD_AMO_JWT_SECRET:-}" ]]; then
      echo "amo: BALUARD_AMO_JWT_KEY and BALUARD_AMO_JWT_SECRET must be set together" >&2
      return 1
    fi
    echo "amo: not configured"
    return 3
  fi
  CLEANUP_DIRS+=("$(mktemp -d)")
  local sec="${CLEANUP_DIRS[-1]}"
  chmod 700 "$sec"
  local now b64 header payload sig resp version status
  now="$(date +%s)"
  b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
  header="$(printf '{"alg":"HS256","typ":"JWT"}' | b64)"
  payload="$(printf '{"iss":"%s","jti":"%s-%s","iat":%s,"exp":%s}' \
    "$BALUARD_AMO_JWT_KEY" "$now" "$RANDOM" "$((now - 5))" "$((now + 30))" | b64)"
  sig="$(printf '%s.%s' "$header" "$payload" \
    | BALUARD_AMO_JWT_SECRET="$BALUARD_AMO_JWT_SECRET" python3 -I -c 'import hmac,hashlib,sys,os; sys.stdout.buffer.write(hmac.new(os.environ["BALUARD_AMO_JWT_SECRET"].encode(), sys.stdin.buffer.read(), hashlib.sha256).digest())' \
    | b64)"
  # The signed JWT rides a 0700 file, never curl's argv.
  printf 'Authorization: JWT %s.%s.%s' "$header" "$payload" "$sig" > "$sec/jwt"
  if ! resp="$(curl -fsS --max-time 20 --header @"$sec/jwt" \
    "https://addons.mozilla.org/api/v5/addons/addon/$AMO_ID/versions/?filter=all_with_unlisted&page_size=3")"; then
    echo "amo: probe failed (network or API error)" >&2
    return 2
  fi
  # file.status enum (addons-server docs): public = approved,
  # unreviewed = awaiting review; also disabled/rejected. Newest entry by id.
  version="$(jq -r '[.results[]] | sort_by(.id) | reverse | .[0].version // empty' <<<"$resp")"
  status="$(jq -r '[.results[]] | sort_by(.id) | reverse | .[0].file.status // empty' <<<"$resp")"
  if [[ -z "$version" ]]; then
    echo "amo: probe returned no versions" >&2
    return 2
  fi
  echo "amo: $version $status"
  case "$status" in
    unreviewed | nominated | awaiting_review)
      if [[ -n "$GUARD_VERSION" && "$version" != "$GUARD_VERSION" ]]; then
        REFUSALS+=("amo: version $version is $status; submitting $GUARD_VERSION would stack on an open review")
        return 1
      fi
      ;;
  esac
  return 0
}

# ── Chrome Web Store (API v2) ───────────────────────────────────────────────
chrome_verdict() {
  local need=(BALUARD_CHROME_CLIENT_ID BALUARD_CHROME_CLIENT_SECRET
    BALUARD_CHROME_REFRESH_TOKEN BALUARD_CHROME_EXTENSION_ID
    BALUARD_CHROME_PUBLISHER_ID)
  local var missing=()
  for var in "${need[@]}"; do
    [[ -n "${!var:-}" ]] || missing+=("$var")
  done
  if ((${#missing[@]} > 0)); then
    if ((${#missing[@]} == ${#need[@]})); then
      echo "chrome: not configured"
      return 3
    fi
    echo "chrome: set all of ${missing[*]} together, not some" >&2
    return 1
  fi
  CLEANUP_DIRS+=("$(mktemp -d)")
  local sec="${CLEANUP_DIRS[-1]}"
  chmod 700 "$sec"
  printf '%s' "$BALUARD_CHROME_CLIENT_SECRET" > "$sec/client-secret"
  printf '%s' "$BALUARD_CHROME_REFRESH_TOKEN" > "$sec/refresh-token"
  local token_json token state
  if ! token_json="$(curl -fsS --max-time 20 \
    --data-urlencode grant_type=refresh_token \
    --data-urlencode "client_id=$BALUARD_CHROME_CLIENT_ID" \
    --data-urlencode "client_secret@$sec/client-secret" \
    --data-urlencode "refresh_token@$sec/refresh-token" \
    https://oauth2.googleapis.com/token)"; then
    echo "chrome: token exchange failed" >&2
    return 2
  fi
  token="$(jq -r '.access_token // empty' <<<"$token_json")"
  if [[ -z "$token" ]]; then
    echo "chrome: token exchange returned no access_token" >&2
    return 2
  fi
  printf 'Authorization: Bearer %s' "$token" > "$sec/bearer"
  # v2 fetchStatus: the pending review lives in submittedItemRevisionStatus
  # (ItemState enum: PENDING_REVIEW / STAGED / PUBLISHED / ...). v1.1 items
  # GET carries no review state at all, so it is useless as a guard probe.
  if ! state="$(curl -fsS --max-time 20 --header @"$sec/bearer" \
    "https://chromewebstore.googleapis.com/v2/publishers/$BALUARD_CHROME_PUBLISHER_ID/items/$BALUARD_CHROME_EXTENSION_ID:fetchStatus" \
    | jq -r '.submittedItemRevisionStatus.state // .publishedItemRevisionStatus.state // empty')"; then
    echo "chrome: probe failed (network or API error)" >&2
    return 2
  fi
  if [[ -z "$state" ]]; then
    echo "chrome: probe returned no revision state" >&2
    return 2
  fi
  echo "chrome: item $state"
  # v2 exposes no version on the submitted revision, so unlike the AMO
  # guard this refusal cannot be version-scoped: any open review blocks.
  case "$state" in
    PENDING_REVIEW)
      if [[ -n "$GUARD_VERSION" ]]; then
        REFUSALS+=("chrome: the item is $state; submitting $GUARD_VERSION would stack on an open review")
        return 1
      fi
      ;;
  esac
  return 0
}

rc_amo=0; amo_verdict || rc_amo=$?
rc_chrome=0; chrome_verdict || rc_chrome=$?

if ((${#REFUSALS[@]} > 0)); then
  printf '%s\n' "${REFUSALS[@]}" >&2
  echo "verdicts: refusing to submit; wait for the open review to clear" >&2
  exit 1
fi
if ((rc_amo == 1 || rc_chrome == 1)); then
  exit 1
fi
exit 0
