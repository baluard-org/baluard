#!/usr/bin/env bash
# Generate native messaging host manifests for the Linux deb/rpm bundles.
#
# The manifests register /usr/bin/baluard-nmh (the packaged NMH binary) with
# each browser. Firefox is authorized by the AMO id, which is known; the
# chrome-family browsers are authorized by the Chrome Web Store id, which
# Google assigns on first upload and does not exist yet. Until it does, set
# BALUARD_CHROME_EXTENSION_ID at build time to bake the real origin in; without
# it the chrome manifests ship a placeholder origin that matches nothing and
# the browser bridge stays dev-only via `just install-nmh-manifest`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/desktop/src-tauri/nmh-manifests"
HOST_NAME="app.baluard.browser"
LEGACY_NAME="xyz.actitud.baluard"
NMH_PATH="/usr/bin/baluard-nmh"

CHROME_ID="${BALUARD_CHROME_EXTENSION_ID:-}"
FF_ID="${BALUARD_FIREFOX_EXTENSION_ID:-baluard@actitud.xyz}"

if [[ -n "$CHROME_ID" && ! "$CHROME_ID" =~ ^[a-p]{32}$ ]]; then
  echo "BALUARD_CHROME_EXTENSION_ID must be 32 chars a-p (Chrome Web Store id), got: $CHROME_ID" >&2
  exit 1
fi
if [[ -z "$CHROME_ID" ]]; then
  CHROME_ID="baluard-unconfigured"
  echo "WARNING: BALUARD_CHROME_EXTENSION_ID is not set; chrome/chromium/edge" >&2
  echo "WARNING: manifests get a placeholder origin and the store bridge will" >&2
  echo "WARNING: not connect. Set it when the Chrome Web Store id exists." >&2
fi

mkdir -p "$OUT"

# Browsers key a host manifest by its filename matching the `name` field.
# The -legacy files carry the pre-rename name so the in-review 0.1.0 store
# bundles keep pairing with freshly installed packages until extension
# 0.1.1 flips NMH_HOST to the new name.
write_chrome_family() {
  local browser="$1"
  cat > "$OUT/$browser.json" <<EOF
{"name":"$HOST_NAME","description":"Baluard bridge","path":"$NMH_PATH","type":"stdio","allowed_origins":["chrome-extension://$CHROME_ID/"]}
EOF
  cat > "$OUT/$browser-legacy.json" <<EOF
{"name":"$LEGACY_NAME","description":"Baluard bridge","path":"$NMH_PATH","type":"stdio","allowed_origins":["chrome-extension://$CHROME_ID/"]}
EOF
  echo "wrote $browser.json + $browser-legacy.json"
}

write_chrome_family chrome
write_chrome_family chromium
write_chrome_family edge

cat > "$OUT/firefox.json" <<EOF
{"name":"$HOST_NAME","description":"Baluard bridge","path":"$NMH_PATH","type":"stdio","allowed_extensions":["$FF_ID"]}
EOF
cat > "$OUT/firefox-legacy.json" <<EOF
{"name":"$LEGACY_NAME","description":"Baluard bridge","path":"$NMH_PATH","type":"stdio","allowed_extensions":["$FF_ID"]}
EOF
echo "wrote firefox.json + firefox-legacy.json"
