#!/usr/bin/env bash
# Two-phone family journey — 1:1 with reality:
#   box            founder/admin desktop (CLI), owns account 1's repo
#   Pixel 8        founder's own phone, signs in with account 1, joins as co-guardian
#   Pixel 3a       invited joiner, signs in with account 2 (real clone-seat path)
#
# Prereqs (one-time): both phones over USB, debugging allowed, NO screen
# lock, stay awake, E2E APK installed; GitHub OAuth app for the device
# flow live; `baluard` + `baluard-daemon` built with e2e-hooks.
#
# Usage:
#   GH_USER=<account1-username> \
#   GH_PAT=<account1-repo-token> \
#   GH_PASS1=<account1-password> \
#   GH_USER2=<account2-username> GH_PASS2=<account2-password> \
#   SERIAL_FOUNDER=<pixel8-serial> SERIAL_JOINER=<pixel3a-serial> \
#   e2e/mobile/two-phone-family.sh
#
# Everything synthetic; the sandbox stays for inspection (path printed at
# the end). Tokens/passwords transit env and stdin only, never echoed.
set -euo pipefail

cd "$(dirname "$0")/../.."

: "${GH_USER:?account1 username (founder)}"
: "${GH_PAT:?account1 repo token}"
: "${GH_USER2:?account2 username (invited joiner)}"
: "${GH_PAT2:?account2 token (the joiner phone connects with its own account)}"
: "${SERIAL_FOUNDER:?founder phone serial (Pixel 8)}"
: "${SERIAL_JOINER:?joiner phone serial (Pixel 3a)}"

WORK="$(mktemp -d /tmp/baluard-twophone.XXXXXX)"
MASTER_PW="joiner-e2e-pw1"
REPO="baluard-family-$(date +%s)"
export BALUARD_DATA_DIR="$WORK/data"
export BALUARD_DISABLE_KEYRING=1
# Box-side CLI calls resolve the password from the env (no TTY here).
export BALUARD_PASSWORD="$MASTER_PW"
# Hermetic git config: the daemon's libgit2 reads the developer's global
# config, where a pushInsteadOf rewrite to SSH hangs a headless push (no
# key, no agent) until the op timeout. libgit2 ignores GIT_CONFIG_GLOBAL,
# so move HOME: with an empty home the global rewrite is out of reach.
mkdir -p "$WORK/emptyhome"
export HOME="$WORK/emptyhome"
BALUARD="target/debug/baluard"
DAEMON="target/debug/baluard-daemon"
SLUG=""

cleanup() {
  [[ -n "${DMN_PID:-}" ]] && kill "$DMN_PID" 2>/dev/null || true
}
trap cleanup EXIT

# authorize_github_device <serial> <user_code>
# GitHub's device page no longer pre-fills from the URL, so the harness
# types the code the app revealed and walks the two consent screens.
intro_from_logcat() { # <serial>
  adb -s "$1" logcat -d 2>/dev/null | python3 -c '
import re, sys
m = re.findall(r"JoinSpace.*intro=(\S+)", sys.stdin.read())
print(m[-1] if m else "")'
}

req_id_from() { # <stage output>
  python3 -c '
import re, sys
m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", sys.stdin.read())
print(m.group(0) if m else "")' <<< "$1"
}

# join_phone <serial> <invite-username> <github-pat> <label>
join_phone() {
  local serial="$1" invite_user="$2" pat="$3" label="$4"
  echo "── [phone $label] invite, clone + join, approve"
  # The invited seat grants clone access at mint time; inviting the repo
  # owner reports a seat error and is fine (founder's own phone).
  local invite_out code
  invite_out="$("$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" members invite --role editor --username "$invite_user" || true)"
  code="$(awk '/^[A-Za-z0-9+\/=_-]{200,}$/{print $0}' <<< "$invite_out" | tail -1)"
  [[ -n "$code" ]] || { echo "FAIL: no invite code for $invite_user"; echo "$invite_out"; exit 1; }
  # The invite file must be on the remote before the phone clones.
  "$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" sync push > /dev/null

  adb -s "$serial" logcat -c 2>/dev/null || true

  # One flow drives the whole joiner side; the orchestrator acts during
  # the waiting hold.
  BALUARD_E2E_MASTER_PW="$MASTER_PW" \
  BALUARD_E2E_INVITE="$code" \
  BALUARD_E2E_PAT="$pat" \
  BALUARD_E2E_REPO="$REPO" \
  mobile/scripts/run-maestro.sh --pin-locale --flow 12-join-pat.yaml \
    "$serial" > "$WORK/maestro-$label.log" 2>&1 &
  local mpid=$!

  # The joiner's one-time reply surfaces on logcat in e2e builds.
  local intro=""
  for _ in $(seq 1 60); do
    sleep 3
    kill -0 "$mpid" 2>/dev/null || break
    intro="$(intro_from_logcat "$serial" || true)"
    [[ -n "$intro" ]] && break
  done
  [[ -n "$intro" ]] || { echo "FAIL: intro not captured on $serial"; tail -20 "$WORK/maestro-$label.log"; exit 1; }
  echo "    intro captured (${#intro} chars)"

  "$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" unlock > /dev/null
  local stage_out req_id
  stage_out="$("$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" members stage "$intro")"
  req_id="$(req_id_from "$stage_out")"
  [[ -n "$req_id" ]] || { echo "FAIL: no req_id"; echo "$stage_out"; exit 1; }
  "$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" members approve-join "$req_id"
  # The approval commit must reach the remote before the next phone clones.
  "$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" sync push > /dev/null

  if wait "$mpid"; then
    echo "    $label joined, approved, and unlocked."
  else
    echo "FAIL: Maestro flow on $label did not complete"
    tail -30 "$WORK/maestro-$label.log"; exit 1
  fi
}

echo "── [box 1/5] scratch daemon"
"$DAEMON" --socket "$WORK/d.sock" &
DMN_PID=$!
for _ in $(seq 1 50); do
  [[ -S "$WORK/d.sock" ]] && break
  sleep 0.2
done
export BALUARD_SOCKET="$WORK/d.sock"

echo "── [box 2/5] family vault + remote (founder, account 1)"
INIT_JSON="$("$BALUARD" --socket "$WORK/d.sock" init --family --name Founder --slug family-e2e --json)"
SLUG="$(python3 -c '
import json,sys
d = json.loads([l for l in sys.stdin if l.startswith("{")][0])
print(d["slug"])' <<< "$INIT_JSON")"
"$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" unlock > /dev/null
"$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" provider connect github --pat <<< "$GH_PAT" > /dev/null
# GH_REPO reuses an existing repo (rate-limit-friendly reruns); without
# it a fresh private repo is created.
if [[ -n "${GH_REPO:-}" ]]; then
  REPO="$GH_REPO"
  # Strip refs a previous run left behind so the fresh vault's history
  # pushes fast-forward onto an effectively empty remote. The token
  # rides the URL (git's pushInsteadOf rewrite only matches the bare
  # github.com prefix, so this URL is transported as-is).
  for ref in $(git ls-remote "https://actitudapps:$GH_PAT@github.com/$GH_USER/$REPO.git" | awk '{print $2}' | grep -v '^refs/pull'); do
    git push "https://actitudapps:$GH_PAT@github.com/$GH_USER/$REPO.git" --delete "$ref" > /dev/null 2>&1 || true
  done
else
  "$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" provider create-repo github "$REPO" > /dev/null
fi
"$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" sync remote "https://github.com/$GH_USER/$REPO.git" > /dev/null

join_phone "$SERIAL_FOUNDER" "$GH_USER" "$GH_PAT" "founder-phone"

echo "── [box 3/5] invited joiner phone (account 2, real clone seat)"
join_phone "$SERIAL_JOINER" "$GH_USER2" "$GH_PAT2" "joiner-phone"

echo "── [box 4/5] roster"
"$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" unlock > /dev/null
"$BALUARD" --socket "$WORK/d.sock" --vault "$SLUG" members list

echo "── [box 5/5] DONE"
echo "PASS: family vault with founder + two phones on two accounts."
echo "sandbox kept for inspection: $WORK"
