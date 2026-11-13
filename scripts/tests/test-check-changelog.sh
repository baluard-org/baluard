#!/usr/bin/env bash
# Hermetic suite for scripts/check-changelog.sh over fixture changelogs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER="$SCRIPT_DIR/../check-changelog.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILED=0
log() { echo "test-check-changelog: $*"; }

expect() {  # expect <name> <rc> <file> [pattern]
  local name="$1" rc="$2" file="$3" pattern="${4:-}"
  set +e
  bash "$UNDER" 0.4.6 "$file" > "$TMP/out.log" 2>&1
  local got=$?
  set -e
  if [[ "$got" != "$rc" ]]; then
    log "FAIL $name: expected rc=$rc got $got"; cat "$TMP/out.log" | sed 's/^/    /'
    FAILED=$((FAILED + 1)); return
  fi
  if [[ -n "$pattern" ]] && ! grep -q "$pattern" "$TMP/out.log"; then
    log "FAIL $name: missing diagnosis '$pattern'"; FAILED=$((FAILED + 1))
  fi
}

printf 'good' > "$TMP/good.md"
cat >> "$TMP/good.md" <<'EOF'

## [UNRELEASED]

- No user-facing changes yet.

## 0.4.6 - 2026-11-12

- shipped thing
## 0.4.5 - 2026-11-10

- older
EOF
expect good-holds 0 "$TMP/good.md"

cat > "$TMP/bulleted.md" <<'EOF'
## [UNRELEASED]

- No user-facing changes yet.
- real bullet landed

## 0.4.6 - 2026-11-12

- shipped thing
EOF
expect placeholder-with-bullets 1 "$TMP/bulleted.md" "placeholder coexists"

cat > "$TMP/dup.md" <<'EOF'
## [UNRELEASED]
## [UNRELEASED]

## 0.4.6 - 2026-11-12
EOF
expect duplicate-unreleased 1 "$TMP/dup.md" "exactly one"

cat > "$TMP/stranded.md" <<'EOF'
## 0.4.6 - 2026-11-12

- shipped
## [UNRELEASED]

## 0.4.5 - 2026-11-10

- older
EOF
expect stranded-unreleased 1 "$TMP/stranded.md" "sits below"

cat > "$TMP/nosection.md" <<'EOF'
## [UNRELEASED]

- something
EOF
expect missing-section 1 "$TMP/nosection.md" "no section for"

if [[ "$FAILED" -gt 0 ]]; then
  log "FAIL: $FAILED failing assertions"
  exit 1
fi
log "PASS (5 cases)"
