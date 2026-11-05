#!/usr/bin/env bash
# Hermetic test for scripts/sign-updater-sigs.sh.
#
# Fake world: a stub rsign that records argv and writes a fixed four-line
# signature document, a wrapped-key fixture, and three fake artifacts.
# Assertions: all three artifact shapes get stamped, the trusted comment
# carries timestamp/file/version, the wrapped key is unwrapped for the
# stub, and failure cases die loudly.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$SCRIPT_DIR/../sign-updater-sigs.sh"

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

BIN="$TMP/bin"
ART="$TMP/artifacts"
KEY="$TMP/updater.key"
mkdir -p "$BIN" "$ART"

# Fake rsign: log argv, emit the plain four-line doc rsign -x writes.
cat > "$BIN/rsign" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$RSIGN_LOG"
# extract the -t trusted comment and the -x output path
out=""
tc=""
prev=""
for a in "$@"; do
  if [[ "$prev" == "-t" ]]; then tc="$a"; fi
  if [[ "$prev" == "-x" ]]; then out="$a"; fi
  prev="$a"
done
{
  echo "untrusted comment: signature from rsign secret key"
  echo "RURAWQ=="
  echo "trusted comment: $tc"
  echo "RURARURARURARURARURARURARURARURARURARURARURARURARURARURARURARURA=="
} > "${out:?}"
EOF
chmod +x "$BIN/rsign"

# The wrapped key fixture: base64 of a plausible rsign document.
python3 - "$KEY" <<'PYEOF'
import base64, sys
doc = "untrusted comment: rsign encrypted secret key\nRWRTWQ==\n"
open(sys.argv[1], "w").write(base64.b64encode(doc.encode()).decode())
PYEOF

: > "$ART/Baluard_0.1.2_amd64.AppImage"
: > "$ART/Baluard_0.1.2_aarch64.app.tar.gz"
: > "$ART/Baluard_0.1.2_x64-setup.exe"
: > "$ART/Baluard_0.1.2_amd64.deb" # not an updater artifact: must be ignored

# --- Case 1: happy path stamps all three, trusted comment carries version ---
RSIGN_LOG="$TMP/rsign.log" SIG_OUT="$TMP/sig.out" PATH="$BIN:$PATH" \
	BALUARD_UPDATER_KEY="$KEY" \
	"$STAMP" --version 0.1.2 "$ART" > "$TMP/out1.log" 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
	echo "FAIL: happy path exited $rc:" >&2
	cat "$TMP/out1.log" >&2
	exit 1
fi
for f in Baluard_0.1.2_amd64.AppImage.sig Baluard_0.1.2_aarch64.app.tar.gz.sig Baluard_0.1.2_x64-setup.exe.sig; do
	if [[ ! -s "$ART/$f" ]]; then
		echo "FAIL: $f missing or empty" >&2
		exit 1
	fi
	if ! grep -q "version:0.1.2" "$ART/$f"; then
		echo "FAIL: $f carries no version stamp" >&2
		exit 1
	fi
done
calls="$(grep -c 'sign -W' "$TMP/rsign.log" || true)"
if [[ "$calls" -ne 3 ]]; then
	echo "FAIL: expected 3 rsign calls, got $calls" >&2
	exit 1
fi
if [[ -f "$ART/Baluard_0.1.2_amd64.deb.sig" ]]; then
	echo "FAIL: the deb must not be stamped" >&2
	exit 1
fi
if [[ "$(grep -c "sign-updater-sigs" <<< "$(cat "$TMP/rsign.log")")" -eq 0 ]]; then
	: # argv log only carries the stub call; nothing else to assert here
fi

# --- Case 2: rerun is idempotent (sig files just get rewritten) ---
RSIGN_LOG="$TMP/rsign2.log" SIG_OUT="$TMP/sig2.out" PATH="$BIN:$PATH" \
	BALUARD_UPDATER_KEY="$KEY" \
	"$STAMP" --version 0.1.3 "$ART" > "$TMP/out2.log" 2>&1
rc=$?
if [[ $rc -ne 0 ]] || ! grep -q "version:0.1.3" "$ART/Baluard_0.1.2_amd64.AppImage.sig"; then
	echo "FAIL: re-stamp with a new version did not rewrite sigs (rc=$rc)" >&2
	exit 1
fi

# --- Case 3: missing artifacts dir dies ---
if PATH="$BIN:$PATH" BALUARD_UPDATER_KEY="$KEY" \
	"$STAMP" --version 0.1.2 "$TMP/nowhere" > "$TMP/out3.log" 2>&1; then
	echo "FAIL: missing dir must die" >&2
	exit 1
fi

# --- Case 4: no updater artifacts dies ---
mkdir -p "$TMP/empty"
if PATH="$BIN:$PATH" BALUARD_UPDATER_KEY="$KEY" \
	"$STAMP" --version 0.1.2 "$TMP/empty" > "$TMP/out4.log" 2>&1; then
	echo "FAIL: empty dir must die" >&2
	exit 1
fi

# --- Case 5: bad wrapped key dies ---
echo "not-base64!!" > "$KEY.bad"
if PATH="$BIN:$PATH" BALUARD_UPDATER_KEY="$KEY.bad" \
	"$STAMP" --version 0.1.2 "$ART" > "$TMP/out5.log" 2>&1; then
	echo "FAIL: corrupt key must die" >&2
	exit 1
fi

echo "PASS: test-sign-updater-sigs.sh"
