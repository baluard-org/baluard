#!/usr/bin/env bash
# Two-phone ORGANIZATION journey — 1:1 with reality:
#   Pixel 8   founder: creates a vault on the phone, wires its Git
#             backup, flips it to an organization from mobile Settings,
#             mints the invite, later stages + approves the joiner
#   Pixel 3a  invited joiner (editor): clones through the invited
#             collaborator seat, joins by invite code, and is refused a
#             grantless org add; then adds a personal second vault
#
# Assertions carried by the flows:
#   14c  admin flat add lands; stage + approve from the phone UI
#   14d  grantless org editor refused ("No collection is open for your
#        edits"); second-vault creation via the switcher
#   14e  the org entry NEVER merges into the founder's personal hub
#        search (G24 §4.2: org Spaces are never merge-eligible)
#
# The box orchestrates only: it reads one-time codes from the phones'
# logcats, raises the GitHub clone seat (read-level invites 422 between
# brand-new accounts), accepts the invitation on the joiner's behalf,
# and waits for the founder's autosync push before the clone.
#
# Usage:
#   GH_USER=<founder-username> GH_PAT=<founder-repo-token> \
#   GH_USER2=<joiner-username> GH_PAT2=<joiner-token> \
#   SERIAL_FOUNDER=<pixel8> SERIAL_JOINER=<pixel3a> \
#   e2e/mobile/two-phone-org.sh
#
# Everything synthetic. Tokens/passwords transit env only, never echoed.
set -euo pipefail
cd "$(dirname "$0")/../.."

: "${GH_USER:?founder username}"
: "${GH_PAT:?founder repo token}"
: "${GH_USER2:?joiner username}"
: "${GH_PAT2:?joiner token}"
: "${SERIAL_FOUNDER:?founder phone serial}"
: "${SERIAL_JOINER:?joiner phone serial}"

WORK="$(mktemp -d /tmp/baluard-org.XXXXXX)"
FOUNDER_PW="org-founder-pw1"
JOINER_PW="org-joiner-pw1"
PERSONAL_PW="org-personal-pw1"
REPO="baluard-org-$(date +%s)"
FOUNDER_PW_2="org-personal-pw1"

shots="$(mktemp -d /tmp/baluard-org-shots.XXXXXX)"
keep_shot() { # <serial> <name> — only on PASSED legs (standing directive)
  adb -s "$1" exec-out screencap -p > "/home/esteban/Dev/Screenshots/org-$2.png" 2>/dev/null || true
}

invite_from_logcat() { # <serial>
  adb -s "$1" logcat -d 2>/dev/null | python3 -c '
import re, sys
m = re.findall(r"JoinInvite.*invite=(\S+)", sys.stdin.read())
print(m[-1] if m else "")'
}

intro_from_logcat() { # <serial>
  adb -s "$1" logcat -d 2>/dev/null | python3 -c '
import re, sys
m = re.findall(r"JoinSpace.*intro=(\S+)", sys.stdin.read())
print(m[-1] if m else "")'
}

maestro() { # <serial> <flow> <env...>
  local serial="$1" flow="$2"; shift 2
  env "$@" mobile/scripts/run-maestro.sh --flow "$flow" "$serial"
}

echo "── [1/6] founder phone: create, git backup, flip to org, invite"
adb -s "$SERIAL_FOUNDER" logcat -c 2>/dev/null || true
maestro "$SERIAL_FOUNDER" 14a-org-founder.yaml \
  "MASTER_PW=$FOUNDER_PW" "BALUARD_E2E_MASTER_PW=$FOUNDER_PW" "BALUARD_E2E_PAT=$GH_PAT" \
  "BALUARD_E2E_REPO=$REPO" "BALUARD_E2E_GH_USER2=$GH_USER2" \
  # No adb while the flow runs: every adb client restarts the server the
# runner just killed and the driver dies silently at startup. Run the
# flow to completion, then read the invite from the accumulated logcat.
if ! maestro "$SERIAL_FOUNDER" 14a-org-founder.yaml \
    "MASTER_PW=$FOUNDER_PW" "BALUARD_E2E_MASTER_PW=$FOUNDER_PW" "BALUARD_E2E_PAT=$GH_PAT" \
    "BALUARD_E2E_REPO=$REPO" "BALUARD_E2E_GH_USER2=$GH_USER2" \
    > "$WORK/maestro-14a.log" 2>&1; then
  echo "FAIL: founder flow failed"; tail -30 "$WORK/maestro-14a.log"; exit 1
fi
keep_shot "$SERIAL_FOUNDER" "14a-founder"
INVITE="$(adb -s "$SERIAL_FOUNDER" logcat -d 2>/dev/null | python3 -c "
import re, sys
m = re.findall(r'JoinInvite.*invite=(\S+)', sys.stdin.read())
print(m[-1] if m else '')" || true)"
[[ -n "$INVITE" ]] || { echo "FAIL: invite code not captured on founder phone"; tail -20 "$WORK/maestro-14a.log"; exit 1; }
echo "    invite captured (${#INVITE} chars)"

# The invite must be on the remote before the joiner clones: the
# founder's autosync pushes it (5s debounce). Commit COUNTS lie here:
# the git-backup push made the repo non-empty before the invite even
# existed, so poll the contents API for meta/invites itself.
echo "── [2/6] waiting for the founder's push"
for _ in $(seq 1 45); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 15 -H "Authorization: Bearer $GH_PAT" \
    "https://api.github.com/repos/$GH_USER/$REPO/contents/meta/invites")"
  [[ "$CODE" == "200" ]] && break
  sleep 4
done
[[ "$CODE" == "200" ]] || { echo "FAIL: invite never reached the remote"; exit 1; }
echo "    invite file on the remote"

# Read-level collaborator invites 422 between brand-new accounts: raise
# the seat to push (the approval would upgrade it anyway), then accept
# on the joiner's behalf — the real-world invite click.
curl -s -o /dev/null -X PUT -H "Authorization: Bearer $GH_PAT" \
  -H "Content-Type: application/json" -d '{"permission":"push"}' \
  "https://api.github.com/repos/$GH_USER/$REPO/collaborators/$GH_USER2" || true
INV_ID="$(curl -s -m 15 -H "Authorization: Bearer $GH_PAT2" https://api.github.com/user/repository_invitations | python3 -c "
import json, sys
d = json.load(sys.stdin)
inv = [i['id'] for i in d if i.get('repository', {}).get('full_name', '').endswith('/$REPO')]
print(inv[0] if inv else '')")"
if [[ -n "$INV_ID" ]]; then
  curl -s -o /dev/null -X PATCH -H "Authorization: Bearer $GH_PAT2" \
    "https://api.github.com/user/repository_invitations/$INV_ID"
  echo "    repo invitation accepted for $GH_USER2"
fi

echo "── [3/6] joiner phone: clone, join, wait"
adb -s "$SERIAL_JOINER" logcat -c 2>/dev/null || true
maestro "$SERIAL_JOINER" 14b-org-joiner.yaml \
  "MASTER_PW=$JOINER_PW" "BALUARD_E2E_MASTER_PW=$JOINER_PW" "BALUARD_E2E_PAT=$GH_PAT2" \
  "BALUARD_E2E_REPO=$REPO" "BALUARD_E2E_INVITE=$INVITE" \
  > "$WORK/maestro-14b.log" 2>&1 &
MPID_B=$!

INTRO=""
for _ in $(seq 1 60); do
  sleep 3
  INTRO="$(intro_from_logcat "$SERIAL_JOINER" || true)"
  [[ -n "$INTRO" ]] && break
  kill -0 "$MPID_B" 2>/dev/null || break
done
[[ -n "$INTRO" ]] || { echo "FAIL: intro not captured on joiner phone"; tail -20 "$WORK/maestro-14b.log"; exit 1; }
echo "    intro captured (${#INTRO} chars)"

echo "── [4/6] founder phone: add entry, stage + approve"
# One long inputText wedges Maestro's per-key typing; hand the flow the
# intro in 8 chunks (empty-padded so every var always resolves).
CHUNK_ENV=()
for i in $(seq 0 7); do
  CHUNK_ENV+=("BALUARD_E2E_INTRO_$((i+1))=$(printf '%s' "$INTRO" | cut -c $((i*200+1))-$(((i+1)*200)))")
done
maestro "$SERIAL_FOUNDER" 14c-org-approve.yaml \
  "MASTER_PW=$FOUNDER_PW" "BALUARD_E2E_MASTER_PW=$FOUNDER_PW" "${CHUNK_ENV[@]}" \
  > "$WORK/maestro-14c.log" 2>&1
keep_shot "$SERIAL_FOUNDER" "14c-approved"

if wait "$MPID_B"; then
  echo "    joiner joined and unlocked."
  keep_shot "$SERIAL_JOINER" "14b-joined"
else
  echo "FAIL: joiner flow did not complete"
  tail -30 "$WORK/maestro-14b.log"; exit 1
fi

echo "── [5/6] joiner phone: grantless refusal + personal second vault"
maestro "$SERIAL_JOINER" 14d-org-joiner-second.yaml \
  "BALUARD_E2E_ORG_PW=$JOINER_PW" "BALUARD_E2E_MASTER_PW_2=$PERSONAL_PW" "BALUARD_E2E_REPO=$REPO" \
  > "$WORK/maestro-14d.log" 2>&1
keep_shot "$SERIAL_JOINER" "14d-joiner-personal"

echo "── [6/6] founder phone: personal second vault, merge exclusion"
maestro "$SERIAL_FOUNDER" 14e-org-exclusion.yaml \
  "BALUARD_E2E_ORG_PW=$FOUNDER_PW" "BALUARD_E2E_MASTER_PW_2=$FOUNDER_PW_2" "BALUARD_E2E_REPO=$REPO" \
  > "$WORK/maestro-14e.log" 2>&1
keep_shot "$SERIAL_FOUNDER" "14e-exclusion"

echo "PASS: org share journey green (join, refusal, merge exclusion)."
echo "sandbox kept for inspection: $WORK"
