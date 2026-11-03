#!/usr/bin/env bash
# Sign every release artifact with the minisign updater key and refresh
# SHA256SUMS (signed too). Safe to re-run: signatures are overwritten.
#
# The key file is the base64-wrapped minisign format the Tauri CLI accepts
# through TAURI_SIGNING_PRIVATE_KEY (the same secret release.yml uses); the
# -k file path expects an unwrapped format and will not decode it.
set -euo pipefail

DIR="${1:?usage: sign-release-artifacts.sh <artifacts-dir>}"
KEY="${BALUARD_UPDATER_KEY:-$HOME/.tauri/baluard-updater.key}"
[[ -f "$KEY" ]] || { echo "updater key not found at $KEY" >&2; exit 1; }
export TAURI_SIGNING_PRIVATE_KEY
TAURI_SIGNING_PRIVATE_KEY="$(cat "$KEY")"

TAURI_CLI="@tauri-apps/cli@2.12.4"

cd "$DIR"
shopt -s nullglob
files=()
for f in *.AppImage *.deb *.rpm *.tar.gz; do
  [[ -f "$f" ]] || continue
  files+=("$f")
done
[[ ${#files[@]} -gt 0 ]] || { echo "no artifacts found in $DIR" >&2; exit 1; }

for f in "${files[@]}"; do
  echo "signing $f"
  npx --yes "$TAURI_CLI" signer sign "$f"
done

sha256sum "${files[@]}" > SHA256SUMS
echo "signing SHA256SUMS"
npx --yes "$TAURI_CLI" signer sign SHA256SUMS

echo
cat SHA256SUMS
