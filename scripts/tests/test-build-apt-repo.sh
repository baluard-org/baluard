#!/usr/bin/env bash
# Hermetic test for build-apt-repo.sh: a real fixture .deb (ar + tar, both on
# the host) drives the script, while gpg is a PATH fake. Covers the served
# retention (newest KEEP) and the matching history-directory prune.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/../build-apt-repo.sh"
TMP="$(mktemp -d)"
cleanup() { [[ "${1:-0}" -eq 0 ]] || echo "KEEP $TMP"; rm -rf "$TMP"; }
trap 'cleanup "$?"' EXIT

die() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "test-build-apt-repo: PASS"; }

# A minimal but real deb: the script ar-extracts it to read Version.
make_deb() {
  local dir="$1" ver="$2" name="$3"
  mkdir -p "$dir/data/usr/bin" "$dir/ctl"
  printf '#!/bin/sh\necho baluard %s\n' "$ver" > "$dir/data/usr/bin/baluard"
  tar -czf "$dir/data.tar.gz" -C "$dir/data" usr
  printf 'Package: baluard\nVersion: %s\nArchitecture: amd64\nMaintainer: t <t@t>\nDescription: fixture\n' "$ver" \
    > "$dir/ctl/control"
  (cd "$dir/ctl" && tar -czf "$dir/control.tar.gz" ./control)
  echo "debian-binary" > "$dir/debian-binary"
  ar rc "$dir/$name" "$dir/debian-binary" "$dir/control.tar.gz" "$dir/data.tar.gz"
}

# gpg shim: the script needs the keyring preflight, a clearsign, and a
# detach-sign. Every action writes deterministic output.
cat > "$TMP/gpg" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GPG_LOG"
case " $* " in
  *--list-secret-keys*) exit 0 ;;
  *--clearsign*)
    out=""; prev=""
    for a in "$@"; do
      [[ "$prev" == "-o" ]] && out="$a"
      prev="$a"
    done
    [[ -n "$out" ]] || exit 1
    cp "${*: -1}" "$out"
    ;;
  *--detach-sign*)
    out=""; prev=""
    for a in "$@"; do
      [[ "$prev" == "-o" ]] && out="$a"
      prev="$a"
    done
    [[ -n "$out" ]] || exit 1
    printf 'FAKESIG\n' > "$out"
    ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$TMP/gpg"

make_sandbox() {
  local sb="$1"
  mkdir -p "$sb/artifacts" "$sb/repo-out" "$sb/gnupg" "$sb/history/deb" "$sb/bin"
  cp "$TMP/gpg" "$sb/bin/gpg"
  export BALUARD_RELEASE_GNUPGHOME="$sb/gnupg"
  export BALUARD_LINUX_REPO_HISTORY="$sb/history"
  export GPG_LOG="$sb/gpg.log"
  export PATH="$sb/bin:$PATH"
}

run_apt() {
  (cd "$SB" && "$SCRIPT" "$SB/artifacts" "$SB/repo-out")
}

# ── Case 1: default retention keeps the newest two in the pool AND history ──
SB="$TMP/case1"
make_sandbox "$SB"
make_deb "$TMP/w1" "0.1.0" "Baluard_0.1.0_amd64.deb"
make_deb "$TMP/w2" "0.2.0" "Baluard_0.2.0_amd64.deb"
mv "$TMP/w1/Baluard_0.1.0_amd64.deb" "$SB/history/deb/"
mv "$TMP/w2/Baluard_0.2.0_amd64.deb" "$SB/history/deb/"
make_deb "$TMP/w3" "0.3.0" "Baluard_0.3.0_amd64.deb"
mv "$TMP/w3/Baluard_0.3.0_amd64.deb" "$SB/artifacts/"

run_apt >/dev/null || die "apt run failed"

for f in Baluard_0.2.0_amd64.deb Baluard_0.3.0_amd64.deb; do
  [[ -f "$SB/history/deb/$f" ]] || die "history must retain $f"
done
[[ -f "$SB/history/deb/Baluard_0.1.0_amd64.deb" ]] && die "history must prune 0.1.0"

for f in Baluard_0.2.0_amd64.deb Baluard_0.3.0_amd64.deb; do
  [[ -f "$SB/repo-out/pool/main/b/baluard/$f" ]] || die "pool must serve $f"
done
[[ -f "$SB/repo-out/pool/main/b/baluard/Baluard_0.1.0_amd64.deb" ]] && die "pool must prune 0.1.0"

[[ $(grep -c '^Filename:' "$SB/repo-out/dists/stable/main/binary-amd64/Packages") -eq 2 ]] \
  || die "Packages must list exactly the retained pool entries"
[[ -f "$SB/repo-out/dists/stable/InRelease" ]] || die "metadata must be signed"

# ── Case 2: BALUARD_LINUX_REPO_KEEP still overrides the count ──
SB="$TMP/case2"
make_sandbox "$SB"
for v in 0.1.0 0.2.0 0.3.0; do
  make_deb "$TMP/ov-$v" "$v" "Baluard_${v}_amd64.deb"
  mv "$TMP/ov-$v/Baluard_${v}_amd64.deb" "$SB/history/deb/"
done
make_deb "$TMP/ov-new" "0.4.0" "Baluard_0.4.0_amd64.deb"
mv "$TMP/ov-new/Baluard_0.4.0_amd64.deb" "$SB/artifacts/"

BALUARD_LINUX_REPO_KEEP=3 "$SCRIPT" "$SB/artifacts" "$SB/repo-out" >/dev/null \
  || die "apt run with KEEP override failed"

# Newest three of four: 0.1.0 prunes, and 0.2.0 survives only because of
# the override (the default two would prune it).
[[ -f "$SB/history/deb/Baluard_0.2.0_amd64.deb" ]] || die "KEEP=3 must retain 0.2.0 in history"
[[ -f "$SB/repo-out/pool/main/b/baluard/Baluard_0.2.0_amd64.deb" ]] || die "KEEP=3 must retain 0.2.0 in the pool"
[[ -f "$SB/history/deb/Baluard_0.1.0_amd64.deb" ]] && die "KEEP=3 must still prune 0.1.0 from history"
[[ -f "$SB/repo-out/pool/main/b/baluard/Baluard_0.1.0_amd64.deb" ]] && die "KEEP=3 must still prune 0.1.0 from the pool"

# ── Case 3: missing release key refuses ──
SB="$TMP/case3"
make_sandbox "$SB"
make_deb "$TMP/w4" "0.3.0" "Baluard_0.3.0_amd64.deb"
mv "$TMP/w4/Baluard_0.3.0_amd64.deb" "$SB/artifacts/"
# The preflight is the first gpg call, so an always-failing shim models a
# missing release key.
printf '#!/usr/bin/env bash\nexit 1\n' > "$SB/bin/gpg"
chmod +x "$SB/bin/gpg"

"$SCRIPT" "$SB/artifacts" "$SB/repo-out" >/dev/null 2>&1 && die "missing key must fail"
pass
