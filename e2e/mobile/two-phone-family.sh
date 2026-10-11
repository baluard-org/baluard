#!/usr/bin/env bash
# Two-phone family-sharing journey (box = founder/admin, phone = joiner).
#
# Prereqs (one-time): dedicated joiner phone over USB (debugging allowed,
# no screen lock, stay awake); the E2E APK installed on it; a test GitHub
# account plus a repo-scoped token; ideally a SECOND account for the
# joiner so the read-only clone seat is exercised (with one account the
# journey still works — the seat grant reports an error and the joiner,
# owning the repo, sees it anyway); `baluard` + `baluard-daemon` built
# with the e2e-hooks features.
#
# Usage:
#   GH_USER=<founder-account-username> \
#   GH_PAT=<founder-token> \
#   JOINER_SERIAL=<serial> \
#   e2e/mobile/two-phone-family.sh
#
# Everything synthetic; the sandbox lives in a tempdir that is left in
# place for inspection (path printed at the end). The PAT transits env
# and stdin only and is never echoed.
set -euo pipefail

cd "$(dirname "$0")/../.."

: "${GH_USER:?set GH_USER to the founder account username}"
: "${GH_PAT:?set GH_PAT to the founder account token}"
: "${JOINER_SERIAL:?set JOINER_SERIAL to the joiner phone serial}"

WORK="$(mktemp -d /tmp/baluard-twophone.XXXXXX)"
MASTER_PW="joiner-e2e-pw1"
REPO="baluard-family-$(date +%s)"
export BALUARD_DATA_DIR="$WORK/data"
export BALUARD_DISABLE_KEYRING=1
BALUARD="target/debug/baluard"
DAEMON="target/debug/baluard-daemon"
SLUG=""

cleanup() {
  [[ -n "${DMN_PID:-}" ]] && kill "$DMN_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "── [box 1/8] scratch daemon"
"$DAEMON" --socket "$WORK/d.sock" &
DMN_PID=$!
for _ in $(seq 1 50); do
  [[ -S "$WORK/d.sock" ]] && break
  sleep 0.2
done
export BALUARD_SOCKET="$WORK/d.sock"

echo "── [box 2/8] family vault (founder)"
INIT_JSON="$("$BALUARD" init --family --name Founder --slug family-e2e --json \
  <<< "$MASTER_PW")"
SLUG="$(python3 -c '
import json,sys
d = json.loads([l for l in sys.stdin if l.startswith("{")][0])
print(d["slug"])' <<< "$INIT_JSON")"
"$BALUARD" --vault "$SLUG" unlock <<< "$MASTER_PW" > /dev/null

echo "── [box 3/8] provider connect + repo $REPO"
"$BALUARD" provider connect github --pat <<< "$GH_PAT" > /dev/null
"$BALUARD" provider create-repo github "$REPO" > /dev/null
"$BALUARD" sync remote "https://github.com/$GH_USER/$REPO.git" > /dev/null

echo "── [box 4/8] invite for the joiner (seat grants clone access)"
INVITE_JSON="$("$BALUARD" members invite --role editor --username "$GH_USER")"
INVITE_CODE="$(awk '/^[A-Za-z0-9+\/=_-]{200,}$/{print $0}' <<< "$INVITE_JSON" | tail -1)"
[[ -n "$INVITE_CODE" ]] || { echo "FAIL: no invite code in output"; echo "$INVITE_JSON"; exit 1; }
echo "invite minted (${#INVITE_CODE} chars)"
# The invite file must be on the remote before the phone clones.
"$BALUARD" --vault "$SLUG" sync push > /dev/null

echo "── [box 5/8] joiner phone: clone + join (Maestro)"
BALUARD_E2E_MASTER_PW="$MASTER_PW" \
BALUARD_E2E_INVITE="$INVITE_CODE" \
BALUARD_E2E_PAT="$GH_PAT" \
BALUARD_E2E_REPO="$REPO" \
mobile/scripts/run-maestro.sh --pin-locale --flow 10-join-family.yaml \
  "$JOINER_SERIAL" > "$WORK/maestro.log" 2>&1 &
MAESTRO_PID=$!

echo "── [box 6/8] reading the joiner's intro reply from logcat"
INTRO_CODE=""
for _ in $(seq 1 60); do
  sleep 3
  kill -0 "$MAESTRO_PID" 2>/dev/null || break
  INTRO_CODE="$(adb -s "$JOINER_SERIAL" logcat -d 2>/dev/null \
    | python3 -c '
import re, sys
m = re.findall(r"JoinSpace.*intro=(\S+)", sys.stdin.read())
print(m[-1] if m else "")' || true)"
  [[ -n "$INTRO_CODE" ]] && break
done
if [[ -z "$INTRO_CODE" ]]; then
  echo "logcat empty; falling back to a UI dump"
  adb -s "$JOINER_SERIAL" exec-out uiautomator dump /dev/tty > /dev/null 2>&1 || \
    { adb -s "$JOINER_SERIAL" shell uiautomator dump /sdcard/ui.xml > /dev/null 2>&1; \
      adb -s "$JOINER_SERIAL" pull /sdcard/ui.xml "$WORK/ui.xml" > /dev/null; }
  INTRO_CODE="$(python3 -c '
import re, sys
tree = open(sys.argv[1]).read()
m = re.findall(r"text=\"([A-Za-z0-9+\/=_-]{300,})\"", tree)
print(m[-1] if m else "")' "$WORK/ui.xml" 2>/dev/null || true)"
fi
[[ -n "$INTRO_CODE" ]] || { echo "FAIL: intro code not found"; tail -20 "$WORK/maestro.log"; exit 1; }
echo "intro captured (${#INTRO_CODE} chars)"

echo "── [box 7/8] stage + approve"
"$BALUARD" --vault "$SLUG" unlock <<< "$MASTER_PW" > /dev/null
STAGE_OUT="$("$BALUARD" --vault "$SLUG" members stage "$INTRO_CODE")"
echo "$STAGE_OUT"
REQ_ID="$(python3 -c '
import re, sys
m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", sys.stdin.read())
print(m.group(0) if m else "")' <<< "$STAGE_OUT")"
[[ -n "$REQ_ID" ]] || { echo "FAIL: no req_id"; exit 1; }
"$BALUARD" --vault "$SLUG" members approve-join "$REQ_ID"
echo "approved; the joiner unlocks on its next poll"

echo "── [box 8/8] wait for the joiner to land in the vault"
if wait "$MAESTRO_PID"; then
  echo "PASS: joiner joined, approved, and unlocked."
else
  echo "FAIL: Maestro flow did not complete"; tail -30 "$WORK/maestro.log"; exit 1
fi
echo "sandbox kept for inspection: $WORK"
