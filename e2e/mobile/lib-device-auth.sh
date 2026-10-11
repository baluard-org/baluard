#!/usr/bin/env bash
# adb/uiautomator helpers for the two-phone journey's GitHub device
# authorization. Sourced by e2e/mobile/two-phone-family.sh.

# bounds_of <serial> <xml-file> <text> — center coords of a text node.
bounds_of() {
  python3 - "$2" "$3" <<'PYEOF'
import re, sys
t = open(sys.argv[1], encoding='utf-8', errors='replace').read()
m = re.search(r'(?:text|content-desc)="' + re.escape(sys.argv[2]) + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', t)
if m:
    print((int(m.group(1)) + int(m.group(3))) // 2, (int(m.group(2)) + int(m.group(4))) // 2)
PYEOF
}

# tap_text_on <serial> <text>
tap_text_on() {
  adb -s "$1" exec-out uiautomator dump /dev/tty > /tmp/tap_dump.xml 2>/dev/null
  local p
  p="$(bounds_of "$1" /tmp/tap_dump.xml "$2")"
  [[ -n "$p" ]] && adb -s "$1" shell input tap $p
}

# wait_text_on <serial> <text-regex> <tries> — poll until the text shows.
wait_text_on() {
  local serial="$1" pattern="$2" tries="${3:-20}"
  for _ in $(seq 1 "$tries"); do
    adb -s "$serial" exec-out uiautomator dump /dev/tty 2>/dev/null \
      | grep -qE "(text|content-desc)=\"[^\"]*$pattern" && return 0
    sleep 2
  done
  return 1
}

# authorize_github_device <serial> <user_code>
# GitHub's mobile-web walk: session confirm ("Continue as <user>"), then
# the manual code entry page, then the authorize consent.
authorize_github_device() {
  local serial="$1" code="$2"
  echo "    driving GitHub device activation"
  if wait_text_on "$serial" "Continue as " 15; then
    tap_text_on "$serial" "Continue as "
  fi
  wait_text_on "$serial" "Authorize your device" 20 || {
    echo "FAIL: code entry page never appeared"; return 1; }
  # The first code box is focused on load; type the 8 chars (no dash).
  adb -s "$serial" shell input text "$(tr -d '-' <<< "$code")"
  sleep 1
  tap_text_on "$serial" "Continue"
  wait_text_on "$serial" "Authorize Baluard" 20 || {
    echo "FAIL: authorize page never appeared"; return 1; }
  tap_text_on "$serial" "Authorize Baluard"
  wait_text_on "$serial" "Congratulations|all set|authorized" 20 || {
    echo "FAIL: authorization never completed"; return 1; }
  echo "    GitHub authorized the device."
}
