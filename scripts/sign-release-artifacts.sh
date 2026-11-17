#!/usr/bin/env bash
# Sign every release artifact with the minisign updater key and refresh
# SHA256SUMS (signed too). Safe to re-run: signatures are overwritten.
#
# The key file is the base64-wrapped minisign format the Tauri CLI accepts
# through TAURI_SIGNING_PRIVATE_KEY (the same secret release.yml uses); the
# -k file path expects an unwrapped format and will not decode it.
set -euo pipefail

DIR="${1:?usage: sign-release-artifacts.sh <artifacts-dir>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_VERSION="$(awk -F'"' '/^\[workspace.package\]/{section=1; next} section && /^version =/{print $2; exit}' "$ROOT/Cargo.toml")"
[[ "$WORKSPACE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
  || { echo "cannot read workspace version from $ROOT/Cargo.toml" >&2; exit 1; }
WORKSPACE_CORE="${WORKSPACE_VERSION%%-*}"

KEY="${BALUARD_UPDATER_KEY:-$HOME/.tauri/baluard-updater.key}"
[[ -f "$KEY" ]] || { echo "updater key not found at $KEY" >&2; exit 1; }
export TAURI_SIGNING_PRIVATE_KEY
TAURI_SIGNING_PRIVATE_KEY="$(cat "$KEY")"

TAURI_CLI="@tauri-apps/cli@2.12.4"

cd "$DIR"

# Refuse files from another release before signing anything: the stage
# guard that would reject them runs only later, after the repositories
# are already packaged. Only the X.Y.Z core is compared so the rpm
# release suffix (-1) and prerelease tags stay out of the way.
stale=()
while IFS= read -r f; do
  v="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<<"${f##*/}" | head -n1 || true)"
  [[ -z "$v" || "$v" == "$WORKSPACE_CORE" ]] || stale+=("${f##*/}")
done < <(find . -maxdepth 1 -type f)
if [[ ${#stale[@]} -gt 0 ]]; then
  echo "refusing: files from another release than workspace version $WORKSPACE_VERSION:" >&2
  printf '  %s\n' "${stale[@]}" >&2
  exit 1
fi

shopt -s nullglob
files=()
for f in *.AppImage *.deb *.rpm *.tar.gz *.zip *.exe; do
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
