#!/usr/bin/env bash
# Roles matrix journey — the box (owner) drives the probe phone's member
# through viewer -> editor, probing real capabilities on the phone after
# each change, then proves the admin trust dial refuses box-side.
#
#   box    owner/admin (CLI)   role changes + grant + push
#   phone  the member under test (cold-start, unlock, probes)
#
# The admin PHONE leg is deliberately absent: promoting a joined member
# demands the Level 2 verified-contact ceremony, which has no box-side
# surface — the journey asserts that refusal honestly instead.
#
# Usage:
#   WORK=/tmp/baluard-twophone.kknjkx SERIAL=<probe-serial> \
#   e2e/mobile/roles-journey.sh
#
# The sandbox is the two-phone family journey's kept workspace: it
# carries the family vault, its GitHub remote, and the stored token.
# Successful legs drop ONE finished-screen screenshot each into
# ~/Dev/baluard-e2e-shots/ for Esteban; failures drop nothing.
set -euo pipefail

cd "$(dirname "$0")/../.."

: "${WORK:?sandbox dir, e.g. /tmp/baluard-twophone.kknjkx}"
: "${SERIAL:?probe phone serial}"
: "${SLUG:=baluard-family-e2e}"
: "${COLLECTION:=Roles}"
BOX_PW="${BOX_PW:-joiner-e2e-pw1}"
export BALUARD_E2E_MASTER_PW="${BALUARD_E2E_MASTER_PW:-joiner-e2e-pw1}"

export BALUARD_DATA_DIR="$WORK/data"
export BALUARD_DISABLE_KEYRING=1
# Explicit pushes only: autosync's debounced cover commits would race
# them (NotFastForward) and split pushes mid-leg.
export BALUARD_AUTOSYNC=0
# Box-side CLI calls resolve the password from the env (no TTY here).
export BALUARD_PASSWORD="$BOX_PW"
REAL_HOME="$HOME"
mkdir -p "$WORK/emptyhome"
export HOME="$WORK/emptyhome"   # hermetic libgit2 (see two-phone-family.sh)
SHOTS="${SHOTS:-$REAL_HOME/Dev/Screenshots}"
BALUARD="target/debug/baluard"
DAEMON="target/debug/baluard-daemon"
SOCKET="$WORK/roles.sock"
LEG=0

B() { "$BALUARD" --socket "$SOCKET" --vault "$SLUG" "$@"; }

cleanup() {
  [[ -n "${DMN_PID:-}" ]] && kill "$DMN_PID" 2>/dev/null || true
}
trap cleanup EXIT

# keep_shot <label> — after a PASSED leg, screencap the phone as it
# sits (the finished, working screen) into the Dev folder. One file per
# leg; failures copy nothing. Maestro only saves step pngs for failed
# steps, so the shot comes straight from the device.
keep_shot() {
  local label="$1"
  mkdir -p "$SHOTS"
  if adb -s "$SERIAL" exec-out screencap -p > "$SHOTS/${label}.png" 2>/dev/null \
      && [[ -s "$SHOTS/${label}.png" ]]; then
    echo "shot: $SHOTS/${label}.png"
  fi
}

leg() { # <role> <flow-file> <label>
  local role="$1" flow="$2" label="$3"
  echo "== leg: $role =="
  B members set-role "$SUBJECT" "$role" > /dev/null
  B sync push > /dev/null
  mobile/scripts/run-maestro.sh --flow "$flow" "$SERIAL"
  LEG=$((LEG+1))
  keep_shot "${label}-${LEG}"
}

echo "daemon on $SOCKET"
"$DAEMON" --socket "$SOCKET" >"$WORK/roles-daemon.log" 2>&1 &
DMN_PID=$!
sleep 1
B unlock > /dev/null
# The phone pushes its own client commits between runs; converge first
# so every later push fast-forwards.
B sync pull > /dev/null 2>&1 || true
echo "vault unlocked; mapping the probe phone's member row"

# Map the phone's member id: its vault's device id names a binding file
# under exactly one member's devices/ directory.
DEVDIR="$(adb -s "$SERIAL" shell run-as app.baluard.mobile ls files/vaults 2>/dev/null | tr -d '\r' | grep -v '^$' | head -1)"
[[ -n "$DEVDIR" ]] || { echo "FAIL: no vault dir on $SERIAL"; exit 1; }
PHONE_DEV="$(timeout 8 adb -s "$SERIAL" shell run-as app.baluard.mobile cat "files/vaults/$DEVDIR/meta/device-id" 2>/dev/null | tr -d '\r')"
if [[ ! "$PHONE_DEV" =~ ^[0-9a-f-]{36}$ ]]; then
  echo "FAIL: no device id from $SERIAL (dir=$DEVDIR, got: $PHONE_DEV)"
  exit 1
fi
SUBJECT=""
MLIST="$(B members list)"
for M in $(awk '$2 != "owner" && NF > 2 {print $1}' <<<"$MLIST"); do
  if grep -rq "\"device_id\"[[:space:]]*:[[:space:]]*\"$PHONE_DEV\"" \
      "$BALUARD_DATA_DIR/vaults/$SLUG/meta/members/$M/devices/" 2>/dev/null; then
    SUBJECT="$M"
    break
  fi
done
[[ -n "$SUBJECT" ]] || { echo "FAIL: no member row binds device $PHONE_DEV"; exit 1; }
echo "subject member: $SUBJECT (device $PHONE_DEV)"

# A dedicated collection with Write for the subject, so the editor leg
# has somewhere its adds route (Shared is Read-only for it).
# Grants never lift rank: a viewer cannot be handed Write. Normalize to
# editor first so reruns after a mid-leg crash can always re-grant.
B members set-role "$SUBJECT" editor > /dev/null
# Resolve by id: capture the list fully (early-exit pipes make the CLI
# panic on EPIPE, and pipefail then flips the guard), create only when
# the name is truly absent, and grant by id so duplicate names from
# older runs cannot break resolution.
CLIST="$(B collections list)"
CID="$(grep -F "  $COLLECTION  (" <<<"$CLIST" | head -1 | awk '{print $1}')"
if [[ -z "$CID" ]]; then
  B collections create "$COLLECTION" > /dev/null
  echo "created collection $COLLECTION"
  CLIST="$(B collections list)"
  CID="$(grep -F "  $COLLECTION  (" <<<"$CLIST" | head -1 | awk '{print $1}')"
fi
[[ -n "$CID" ]] || { echo "FAIL: could not resolve $COLLECTION"; exit 1; }
B collections grant "$CID" --kind member --target-id "$SUBJECT" --access write > /dev/null
B sync push > /dev/null
echo "Write grant on $COLLECTION pushed"

adb -s "$SERIAL" logcat -c 2>/dev/null || true  # card capture hygiene: this run only
leg viewer 13-viewer.yaml roles-viewer
leg editor 13-editor.yaml roles-editor

# Trust dial (box-side): promoting a joined member without the Level 2
# verified-contact ceremony must refuse...
echo "== leg: admin (trust dial, then the real check) =="
# Make the refusal probe deterministic: a previous run may have already
# verified this contact. Drop the row so the dial re-arms, then promote
# through the real Level 2 ceremony below.
# Empty the book: this sandbox's only contact is the subject, and any
# leftover verified row would skip the dial. The import below re-adds.
while read -r PK; do
  [[ -n "$PK" ]] && B contacts remove "$PK" > /dev/null 2>&1 || true
done < <(B contacts list | awk '/^[0-9a-f]{16,}/ {print $1}')
if B members set-role "$SUBJECT" admin 2>"$WORK/roles-admin.err"; then
  echo "FAIL: admin promotion should have been refused (trust dial)"
  exit 1
fi
grep -q "verified contact" "$WORK/roles-admin.err" ||
  { echo "FAIL: unexpected refusal: $(cat "$WORK/roles-admin.err")"; exit 1; }
echo "refused as designed: $(cat "$WORK/roles-admin.err")"

# ...then run the real Level 2 check. The member's signed card is the
# out-of-band share: in e2e the phone logs it (Settings shows every
# member's verification code; the card rides the e2e log line). Import
# it, record the code match, and promote. The phone leg asserts the
# admin surfaces.
# Cards are logged when a flow leg opens Settings (viewer/editor legs
# both do); the buffer was cleared at run start, so the captured card
# is from this run.
CARD="$(adb -s "$SERIAL" logcat -d 2>/dev/null | grep -o 'ContactCard.*card=[A-Za-z0-9_=-]*' | tail -1 | sed 's/.*card=//')"
[[ -n "$CARD" ]] || { echo "FAIL: member card code not found in logcat (open Settings on the phone first)"; exit 1; }
B contacts import "$CARD" > /dev/null
# The trust word sits in field 2 of each book row (own card is never
# in the book).
CL="$(B contacts list)"
PUBKEY="$(awk '$2 == "channel" || $2 == "verified" {print $1; exit}' <<<"$CL")"
[[ -n "$PUBKEY" ]] || { echo "FAIL: member contact not in the address book"; exit 1; }
B contacts verify "$PUBKEY"
B members set-role "$SUBJECT" admin > /dev/null
B sync pull > /dev/null 2>&1 || true
B sync push > /dev/null
leg admin 13-admin.yaml roles-admin

# Leave the member as it started (demotion is allowed; only the owner
# row is untouchable).
B members set-role "$SUBJECT" editor > /dev/null
B sync pull > /dev/null 2>&1 || true
B sync push > /dev/null

echo "PASS: roles matrix green (viewer + editor on $SERIAL, admin dial refuses)"
