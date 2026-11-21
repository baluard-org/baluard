#!/usr/bin/env bash
# Freshness table for the crates the release checklist names manually
# (libgit2-sys security patches ride cargo update, not distro updates).
# Compares the locked version against the newest crates.io release and
# prints a verdict per crate. Advisory only: exits 0 always; the release
# day decides whether a stale row justifies an upgrade.
#
# usage: dep-freshness.sh [crate ...]   (default list below)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_CRATES=(libgit2-sys git2 zip tokio rustls reqwest)
CRATES=("${@:-${DEFAULT_CRATES[@]}}")
UA="baluard-release-tools (+https://github.com/baluard-org/baluard)"

command -v curl >/dev/null 2>&1 || { echo "missing tool: curl" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "missing tool: python3" >&2; exit 1; }

printf '%-16s %-12s %-12s %s\n' CRATE LOCKED LATEST VERDICT
for name in "${CRATES[@]}"; do
  latest="$(curl -fsSL --max-time 20 -A "$UA" "https://crates.io/api/v1/crates/$name" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin).get("crate", {}).get("max_stable_version", ""))' 2>/dev/null || true)"
  if [[ -z "$latest" ]]; then
    printf '%-16s %-12s %-12s %s\n' "$name" "?" "?" "lookup failed"
    continue
  fi
  locked="$(python3 - "$ROOT/Cargo.lock" "$name" <<'PY'
import sys, tomllib
name = sys.argv[2]
with open(sys.argv[1], "rb") as fh:
    lock = tomllib.load(fh)
versions = {p["version"] for p in lock.get("package", []) if p.get("name") == name}
print(",".join(sorted(versions)) or "?")
PY
  )"
  verdict="ok"
  # 0.x crates break on the minor axis (cargo semver convention), so the
  # second component is the compatibility line there.
  # libgit2 security fixes ride the build metadata (+1.9.x libgit2 line),
  # the crate's own reason to flag drift even inside one semver line.
  locked_meta="${locked#*+}"; latest_meta="${latest#*+}"
  if [[ "$locked" == *+* && "$latest" == *+* && "$locked_meta" != "$latest_meta" ]]; then
    verdict="STALE (libgit2 behind)"
  elif [[ "$locked" == 0.* && "$latest" == 0.* ]]; then
    l1="${locked#*.}"; l2="${latest#*.}"
    [[ "${l1%%.*}" == "${l2%%.*}" ]] || verdict="STALE (0.x minor behind)"
  else
    [[ "${locked%%.*}" == "${latest%%.*}" ]] || verdict="STALE (major behind)"
  fi
  printf '%-16s %-12s %-12s %s\n' "$name" "$locked" "$latest" "$verdict"
done
