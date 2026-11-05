#!/usr/bin/env bash
# Re-sign the three updater artifacts with version-bearing trusted comments.
#
# tauri-plugin-updater's requireSignedVersion check compares the version in
# the signature's trusted comment against the manifest's announced version,
# and the Tauri CLI (2.12.4) writes no such comment. This script signs the
# artifacts with rsign (the same format the Tauri key wraps) so published
# manifests always carry version-stamped signatures. Artifact bytes do not
# change; only the .sig files are rewritten.
#
# Usage: scripts/sign-updater-sigs.sh --version <X.Y.Z> <artifacts-dir>
#
# Requires: rsign (cargo install rsign2) and python3 (to unwrap the
# base64-wrapped Tauri key once per run).

set -euo pipefail

RSIGN="${RSIGN:-rsign}"
UPDATER_KEY="${BALUARD_UPDATER_KEY:-$HOME/.tauri/baluard-updater.key}"

usage() {
	echo "usage: $0 --version <X.Y.Z> <artifacts-dir>" >&2
	exit 2
}

VERSION=""
DIR=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	--version)
		VERSION="${2:?}"
		shift 2
		;;
	-*) usage ;;
	*)
		DIR="$1"
		shift
		;;
	esac
done

[[ -n "$VERSION" && -n "$DIR" ]] || usage
[[ -d "$DIR" ]] || {
	echo "artifacts dir missing: $DIR" >&2
	exit 1
}

command -v "$RSIGN" >/dev/null || {
	echo "rsign not found; install with: cargo install --locked rsign2" >&2
	exit 1
}
[[ -f "$UPDATER_KEY" ]] || {
	echo "updater key missing: $UPDATER_KEY (set BALUARD_UPDATER_KEY)" >&2
	exit 1
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The Tauri key file is the base64 wrapping of the rsign secret-key
# document; rsign needs the document itself.
python3 - "$UPDATER_KEY" "$TMP/inner.key" <<'PYEOF'
import base64, sys
raw = open(sys.argv[1]).read()
doc = base64.b64decode("".join(raw.split()))
if not doc.startswith(b"untrusted comment:"):
    sys.exit("unexpected updater key format: not a wrapped rsign secret key")
open(sys.argv[2], "wb").write(doc)
PYEOF
chmod 600 "$TMP/inner.key"

STAMPED=0
shopt -s nullglob
for artifact in "$DIR"/*.AppImage "$DIR"/*.app.tar.gz "$DIR"/*-setup.exe; do
	base="$(basename "$artifact")"
	sig="$artifact.sig"
	[[ -f "$artifact" ]] || continue
	tmpsig="$TMP/$base.sig"
	"$RSIGN" sign -W -s "$TMP/inner.key" \
		-t "timestamp:$(date +%s)	file:$base	version:$VERSION" \
		-x "$tmpsig" "$artifact"
	mv "$tmpsig" "$sig"
	STAMPED=$((STAMPED + 1))
done

if [[ "$STAMPED" -eq 0 ]]; then
	echo "no updater artifacts found in $DIR" >&2
	exit 1
fi
echo "stamped $STAMPED updater signatures with version $VERSION"
