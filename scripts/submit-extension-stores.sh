#!/usr/bin/env bash
# Submit packaged browser extension zips to the Chrome Web Store and AMO.
# Explicit publishing recipe, never part of release-repositories: the store
# upload is the public boundary of the release flow. Credentials live in the
# environment only (Bitwarden keeps them); they never touch argv.
set -euo pipefail
umask 077

ART="${1:-dist}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for tool in jq curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

mkdir -p "$ART"
ART=$(cd "$ART" && pwd)

# Old-version zips accumulate in the staging dir, so the newest wins.
latest_version() {
  local store="$1" f v
  local versions=()
  for f in "$ART"/baluard-extension-*-"$store".zip; do
    [[ -e "$f" ]] || continue
    v="${f##*/baluard-extension-}"
    versions+=("${v%-"$store".zip}")
  done
  ((${#versions[@]} > 0)) || return 1
  printf '%s\n' "${versions[@]}" | sort -V | tail -n 1
}

# Pre-flight both stores before either submits: a stale dist must never cause
# a half-publish, and the rerun after fixing it must not resubmit a store
# that already went out.
for store in chrome firefox; do
  zip_version="$(latest_version "$store")" \
    || { echo "no packaged $store zip in $ART; run just ext-package first" >&2; exit 1; }
  dist_version="$(jq -er '.version | select(type == "string" and length > 0)' \
    "$ROOT/browser/$store/dist/manifest.json" 2>/dev/null)" \
    || { echo "missing or invalid version in browser/$store/dist/manifest.json; run just ext-package first" >&2; exit 1; }
  # Chrome and Firefox must ride out together: never publish mismatched versions.
  [[ -z "${first_dist_version:-}" ]] && first_dist_version="$dist_version"
  if [[ "$first_dist_version" != "$dist_version" ]]; then
    echo "chrome and firefox dists disagree on version: $first_dist_version vs $dist_version" >&2
    exit 1
  fi
  if [[ "$zip_version" != "$dist_version" ]]; then
    echo "browser/$store/dist is at $dist_version but the newest packaged $store zip is $zip_version" >&2
    echo "run just ext-package to repackage before submitting" >&2
    exit 1
  fi
done

SEC="$(mktemp -d)"
trap 'rm -rf "$SEC"' EXIT
chmod 700 "$SEC"

# web-ext 10 folded submit into sign: --channel listed is the public listing,
# approval-timeout 0 exits after the upload is accepted instead of waiting on
# human review. `|| return 1` matters: the caller runs submit_amo through
# `|| amo_rc=$?`, which disables set -e inside this function.
submit_amo() {
  if [[ -z "${BALUARD_AMO_JWT_KEY:-}" || -z "${BALUARD_AMO_JWT_SECRET:-}" ]]; then
    if [[ -z "${BALUARD_AMO_JWT_KEY:-}${BALUARD_AMO_JWT_SECRET:-}" ]]; then
      echo "firefox/AMO: skipped (set BALUARD_AMO_JWT_KEY and BALUARD_AMO_JWT_SECRET to enable)"
      return 3
    fi
    echo "firefox/AMO: BALUARD_AMO_JWT_KEY and BALUARD_AMO_JWT_SECRET must be set together" >&2
    return 1
  fi
  local args=(sign --channel listed --approval-timeout 0 --no-input
    --source-dir "$ROOT/browser/firefox/dist" --artifacts-dir "$ART")
  [[ -n "${AMO_METADATA:-}" ]] && args+=(--amo-metadata "$AMO_METADATA")
  [[ -n "${AMO_UPLOAD_SOURCE:-}" ]] && args+=(--upload-source-code "$AMO_UPLOAD_SOURCE")
  if command -v web-ext >/dev/null 2>&1; then
    WEB_EXT_API_KEY="$BALUARD_AMO_JWT_KEY" WEB_EXT_API_SECRET="$BALUARD_AMO_JWT_SECRET" \
      web-ext "${args[@]}" || return 1
  else
    command -v npx >/dev/null 2>&1 \
      || { echo "firefox/AMO: neither web-ext nor npx found" >&2; return 1; }
    WEB_EXT_API_KEY="$BALUARD_AMO_JWT_KEY" WEB_EXT_API_SECRET="$BALUARD_AMO_JWT_SECRET" \
      npx --yes web-ext@10.8.0 "${args[@]}" || return 1
  fi
  echo "firefox/AMO: submitted for listing (review happens on addons.mozilla.org)"
}

submit_chrome() {
  local need=(BALUARD_CHROME_CLIENT_ID BALUARD_CHROME_CLIENT_SECRET BALUARD_CHROME_REFRESH_TOKEN
    BALUARD_CHROME_EXTENSION_ID BALUARD_CHROME_PUBLISHER_ID)
  local var missing=()
  for var in "${need[@]}"; do
    [[ -n "${!var:-}" ]] || missing+=("$var")
  done
  if ((${#missing[@]} > 0)); then
    if ((${#missing[@]} == ${#need[@]})); then
      echo "chrome/store: skipped (set ${missing[*]} to enable)"
      return 3
    fi
    echo "chrome/store: set all of ${missing[*]} together, not some" >&2
    return 1
  fi
  local version zip
  version="$(latest_version chrome)"
  zip="$ART/baluard-extension-$version-chrome.zip"

  # Once the store item opts into Verified CRX Uploads, every upload must be
  # a CRX3 signed with the RSA key registered on the Package tab; signing
  # whenever the key exists keeps one code path across both states.
  local key_path="${BALUARD_CHROME_CRX_KEY:-$HOME/.baluard/chrome-crx-upload.key}"
  local upload_file="$zip"
  if [[ -r "$key_path" ]]; then
    local crx="$SEC/baluard-extension-$version-chrome.crx"
    if command -v crx3 >/dev/null 2>&1; then
      crx3 -p "$key_path" -o "$crx" < "$zip" \
        || { echo "chrome/store: CRX packaging failed" >&2; return 1; }
    else
      command -v npx >/dev/null 2>&1 \
        || { echo "chrome/store: neither crx3 nor npx found" >&2; return 1; }
      npx --yes crx3@2.0.0 -p "$key_path" -o "$crx" < "$zip" \
        || { echo "chrome/store: CRX packaging failed" >&2; return 1; }
    fi
    [[ -s "$crx" ]] || { echo "chrome/store: CRX packaging produced no output" >&2; return 1; }
    upload_file="$crx"
  else
    echo "chrome/store: no signing key at $key_path; uploading the unsigned zip" \
      "(rejected once Verified CRX Uploads is enabled on the Package tab)" >&2
  fi

  local token_json token
  printf 'grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s' \
    "$BALUARD_CHROME_CLIENT_ID" "$BALUARD_CHROME_CLIENT_SECRET" "$BALUARD_CHROME_REFRESH_TOKEN" > "$SEC/token-request"
  # name@ takes the value from stdin; it never touches argv.
  token_json="$(printf '%s' "$BALUARD_CHROME_CLIENT_SECRET" | curl -fsS \
    --data-urlencode grant_type=refresh_token \
    --data-urlencode client_id="$BALUARD_CHROME_CLIENT_ID" \
    --data-urlencode client_secret@ \
    --data-urlencode refresh_token@ \
    https://oauth2.googleapis.com/token)" \
    || { echo "chrome/store: token exchange failed" >&2; return 1; }
  token="$(jq -er '.access_token | select(type == "string" and length > 0)' <<< "$token_json")" \
    || { echo "chrome/store: token exchange returned no access_token" >&2; return 1; }
  printf 'Authorization: Bearer %s\n' "$token" > "$SEC/bearer"

  local upload_response
  upload_response="$(curl -fsS --fail-with-body -X POST -T "$upload_file" --header @"$SEC/bearer" \
    "https://chromewebstore.googleapis.com/upload/v2/publishers/$BALUARD_CHROME_PUBLISHER_ID/items/$BALUARD_CHROME_EXTENSION_ID:upload")" \
    || { echo "chrome/store: upload failed" >&2; return 1; }
  # The v2 enum spells the good state both ways.
  jq -e 'select(.uploadState == "SUCCESS" or .uploadState == "SUCCEEDED")' >/dev/null <<< "$upload_response" \
    || { echo "chrome/store: upload rejected: $upload_response" >&2; return 1; }

  local publish_response=""
  # The publish POST needs a body, or the gateway rejects it with 411.
  if ! publish_response="$(curl -fsS --fail-with-body -X POST -d '' --header @"$SEC/bearer" \
    "https://chromewebstore.googleapis.com/v2/publishers/$BALUARD_CHROME_PUBLISHER_ID/items/$BALUARD_CHROME_EXTENSION_ID:publish")"; then
    echo "chrome/store: publish failed: $publish_response" >&2
    return 1
  fi
  echo "chrome/store: uploaded and submitted for review (version $version)"
}

amo_rc=0; submit_amo || amo_rc=$?
chrome_rc=0; submit_chrome || chrome_rc=$?

if ((amo_rc == 3 && chrome_rc == 3)); then
  cat >&2 <<'EOF'
No store is configured, nothing was submitted.
Firefox AMO: set BALUARD_AMO_JWT_KEY and BALUARD_AMO_JWT_SECRET (API keys from addons.mozilla.org).
Chrome Web Store: set BALUARD_CHROME_CLIENT_ID, BALUARD_CHROME_CLIENT_SECRET, BALUARD_CHROME_REFRESH_TOKEN,
BALUARD_CHROME_EXTENSION_ID, and BALUARD_CHROME_PUBLISHER_ID (OAuth client per the Web Store API guide).
Store credentials stay in Bitwarden, never in the repo.
EOF
  exit 1
fi
((amo_rc != 0 && amo_rc != 3)) && exit 1
((chrome_rc != 0 && chrome_rc != 3)) && exit 1
exit 0
