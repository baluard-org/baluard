#!/usr/bin/env bash
# Hermetic test for build-arch-repo.sh: a real fixture .deb (ar + tar, both on
# the host) drives the script, while podman and gpg are PATH fakes. The fake
# podman parses the real mount arguments, simulates the container's outputs,
# and preserves the staged PKGBUILD for assertions.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/../build-arch-repo.sh"
TMP="$(mktemp -d)"
cleanup() { [[ "${1:-0}" -eq 0 ]] || echo "KEEP $TMP"; rm -rf "$TMP"; }
trap 'cleanup "$?"' EXIT

die() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "test-build-arch-repo: PASS"; }

UNSET=(-u BALUARD_RELEASE_GNUPGHOME -u BALUARD_LINUX_REPO_KEEP -u BALUARD_ARCH_IMAGE)

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

SB="$TMP/sb"
mkdir -p "$SB/bin" "$SB/gnupg" "$SB/artifacts" "$SB/repo-out" "$SB/aur"
make_deb "$TMP/debwork" "0.2.5" "Baluard_0.2.5_amd64.deb"
mv "$TMP/debwork/Baluard_0.2.5_amd64.deb" "$SB/artifacts/"
DEB_SHA=$(sha256sum "$SB/artifacts/Baluard_0.2.5_amd64.deb" | awk '{print $1}')

# Trimmed AUR PKGBUILD fixture, seeded one release behind so the bump is
# observable.
cat > "$SB/aur/PKGBUILD" <<'EOF'
# Maintainer: Test <t@t>
pkgname=baluard-bin
pkgver=0.1.0
pkgrel=1
pkgdesc="Git-native password manager. No accounts, no servers."
arch=('x86_64')
url="https://baluard.app"
license=('GPL-3.0-only')
depends=('gtk3')
optdepends=('gnome-keyring: storage')
provides=('baluard')
conflicts=('baluard')
options=('!strip' '!debug')
source=("https://github.com/baluard-org/baluard/releases/download/0.1.0/Baluard-amd64.deb")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')

package() {
  install -Dm755 "$srcdir/Baluard-amd64.deb" "$pkgdir/usr/bin/baluard"
}
EOF

cat > "$SB/bin/gpg" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "${FAKE_LOG:-/nonexistent}/gpg.log"
[[ "$1 $2" == "--homedir --list-secret-keys" ]] || { printf 'FAKESIG\n'; exit 0; }
exit 0
EOF
chmod +x "$SB/bin/gpg"

# The fake podman acts on the real mount arguments: it emits the package, its
# signature, the database files, and the rendered .SRCINFO, and preserves the
# staged PKGBUILD so the test can assert what makepkg would have consumed.
cat > "$SB/bin/podman" <<'EOF'
#!/usr/bin/env bash
log="${FAKE_LOG:?FAKE_LOG unset}"
printf '%s\n' "$*" >> "$log/podman.log"
mnt="" image="" pkgver="" stage="" out="" aur=""
while [[ $# -gt 0 ]]; do
  case $1 in
    -v) mnt+=$'\n'"$2"; shift 2 ;;
    -e) [[ "$2" == PKGVER=* ]] && pkgver="${2#PKGVER=}"; shift 2 ;;
    *) [[ "$1" != -* && -z "$image" ]] && image="$1"; shift ;;
  esac
done
while IFS= read -r pair; do
  case $pair in
    *":/build"*) stage="${pair%%:*}" ;;
    *":/out"*) out="${pair%%:*}" ;;
    *":/aur"*) aur="${pair%%:*}" ;;
  esac
done <<< "$mnt"
[[ -n "$stage" && -n "$out" && -n "$aur" && -n "$pkgver" ]] || exit 9
cp "$stage/PKGBUILD" "$log/staged-PKGBUILD"
echo "package fixture" > "$out/baluard-${pkgver}-1-x86_64.pkg.tar.zst"
echo "FAKESIG" > "$out/baluard-${pkgver}-1-x86_64.pkg.tar.zst.sig"
echo "db fixture" > "$out/baluard.db.tar.zst"
echo "FAKEDBSIG" > "$out/baluard.db.tar.zst.sig"
echo "FAKEDBSIG" > "$out/baluard.files.tar.zst.sig"
cp "$out/baluard.db.tar.zst" "$out/baluard.db"
echo "files fixture" > "$out/baluard.files.tar.zst"
cp "$out/baluard.files.tar.zst" "$out/baluard.files"
printf 'pkgbase = baluard-bin\n\tpkgver = %s\n\npkgname = baluard-bin\n' "$pkgver" > "$aur/.SRCINFO"
EOF
chmod +x "$SB/bin/podman"

LOG="$TMP/log"; mkdir -p "$LOG"
export FAKE_LOG="$LOG"

run_arch() {
  env "${UNSET[@]}" \
    PATH="$SB/bin:$PATH" \
    BALUARD_RELEASE_GNUPGHOME="$SB/gnupg" \
    BALUARD_AUR_DIR="$SB/aur" \
    "$SCRIPT" "$SB/artifacts" "$SB/repo-out"
}

# ── Case 1: happy path ──
run_arch || die "happy path exited nonzero"
ARCHDIR="$SB/repo-out/arch/x86_64"
[[ -f "$ARCHDIR/baluard-0.2.5-1-x86_64.pkg.tar.zst" ]] || die "package not staged"
[[ -f "$ARCHDIR/baluard-0.2.5-1-x86_64.pkg.tar.zst.sig" ]] || die "package signature missing"
[[ -f "$ARCHDIR/baluard.db" && -f "$ARCHDIR/baluard.db.tar.zst" ]] || die "database files missing"
[[ -f "$ARCHDIR/baluard.files" ]] || die "files database missing"
if [[ -L "$ARCHDIR/baluard.db" ]]; then die "baluard.db must be a real copy, not a symlink"; fi
cmp -s "$ARCHDIR/baluard.db" "$ARCHDIR/baluard.db.tar.zst" || die "baluard.db copy drift"
[[ -f "$ARCHDIR/baluard.db.sig" ]] || die "database signature missing"
grep -q "Server = https://baluard.app/repo/arch/x86_64" "$SB/repo-out/arch/baluard.conf" \
  || die "served baluard.conf missing or wrong"
grep -q "^pkgver=0.2.5$" "$SB/aur/PKGBUILD" || die "aur pkgver not bumped"
grep -q "sha256sums=('$DEB_SHA')" "$SB/aur/PKGBUILD" || die "aur checksum not bumped"
[[ "$(tr -d '\t' < "$SB/aur/.SRCINFO")" == *"pkgver = 0.2.5"* ]] || die ".SRCINFO not refreshed"
grep -q '^pkgname=baluard$' "$LOG/staged-PKGBUILD" || die "repo package name wrong"
grep -q 'source=("Baluard_0.2.5_amd64.deb")' "$LOG/staged-PKGBUILD" || die "source not local"
grep -q "sha256sums=('$DEB_SHA')" "$LOG/staged-PKGBUILD" || die "staged checksum wrong"
grep -q 'archlinux:latest' "$LOG/podman.log" || die "default image not used"
grep -q -- '--list-secret-keys' "$LOG/gpg.log" || die "GPG preflight did not run"
if grep -q '^conflicts=' "$LOG/staged-PKGBUILD"; then
  die "repo package must not conflict its own name"
fi

# ── Case 2: retention prunes past KEEP and names pruned entries ──
rm -rf "$SB/repo-out" && mkdir -p "$ARCHDIR"
for v in 0.2.0 0.2.1 0.2.2 0.2.3 0.2.4; do
  echo old > "$ARCHDIR/baluard-$v-1-x86_64.pkg.tar.zst"
done
run_arch >/dev/null || die "retention run failed"
[[ -f "$ARCHDIR/baluard-0.2.5-1-x86_64.pkg.tar.zst" ]] || die "new package missing after retention"
[[ -f "$ARCHDIR/baluard-0.2.4-1-x86_64.pkg.tar.zst" ]] || die "0.2.4 should be retained"
[[ -f "$ARCHDIR/baluard-0.2.3-1-x86_64.pkg.tar.zst" ]] || die "0.2.3 should be retained"
[[ -f "$ARCHDIR/baluard-0.2.2-1-x86_64.pkg.tar.zst" ]] && die "0.2.2 should be pruned"
grep -qF 'repo-add --sign baluard.db.tar.zst baluard-*-1-x86_64.pkg.tar.zst' "$LOG/podman.log" \
  || die "database is not rebuilt from the retained packages"

# ── Case 3: missing artifacts ──
rm -rf "$SB/artifacts" && mkdir -p "$SB/artifacts"
run_arch >/dev/null 2>&1 && die "missing deb must fail"
[[ -f "$ARCHDIR/baluard-0.2.5-1-x86_64.pkg.tar.zst" ]] || die "earlier run must survive a failed one"

# ── Case 4: wrong version shape in the control file ──
make_deb "$TMP/debwork2" "1.0-1deb8u1" "Baluard_1.0_amd64.deb"
mv "$TMP/debwork2/Baluard_1.0_amd64.deb" "$SB/artifacts/"
run_arch >/dev/null 2>&1 && die "non-semver deb version must fail"

# ── Case 5: missing GPG key ──
make_deb "$TMP/debwork3" "0.2.5" "Baluard_0.2.5_amd64.deb"
mv "$TMP/debwork3/Baluard_0.2.5_amd64.deb" "$SB/artifacts/"
cat > "$SB/bin/gpg" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$SB/bin/gpg"
run_arch >/dev/null 2>&1 && die "missing GPG key must fail"

# ── Case 6: podman absent ──
cat > "$SB/bin/gpg" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SB/bin/gpg"
env "${UNSET[@]}" PATH="$TMP/empty-path" BALUARD_RELEASE_GNUPGHOME="$SB/gnupg" \
  "$SCRIPT" "$SB/artifacts" "$SB/repo-out" >/dev/null 2>&1 \
  && die "missing podman must fail"

# ── Case 7: missing aur/PKGBUILD ──
rm "$SB/aur/PKGBUILD"
run_arch >/dev/null 2>&1 && die "missing aur/PKGBUILD must fail"

pass
