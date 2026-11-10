#!/usr/bin/env bash
# Build a pacman repository (arch/x86_64: package + signed database) from the
# newest Baluard amd64 .deb in an artifacts directory, and refresh aur/ so the
# AUR submission tracks the release. Arch tooling only exists in a container,
# so the build runs in a throwaway podman archlinux image (the same pattern as
# build-rpm-repo.sh), signing with the release GPG key.
set -euo pipefail

ART="${1:?usage: build-arch-repo.sh <artifacts-dir> <repo-out-dir>}"
OUT="${2:?usage: build-arch-repo.sh <artifacts-dir> <repo-out-dir>}"
# The container mounts these paths, so both must be absolute.
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ART=$(cd "$ART" && pwd)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
AUR_DIR="${BALUARD_AUR_DIR:-$ROOT/aur}"
GNUPGHOME="${BALUARD_RELEASE_GNUPGHOME:-$HOME/.baluard/release-gnupg}"
export GNUPGHOME
EMAIL="baluard@actitud.xyz"
gpg --homedir "$GNUPGHOME" --list-secret-keys "$EMAIL" >/dev/null 2>&1 \
  || { echo "release GPG key missing; run scripts/gen-release-signing-key.sh" >&2; exit 1; }
command -v podman >/dev/null 2>&1 \
  || { echo "podman is required (arch tooling runs in a container)" >&2; exit 1; }
IMAGE="${BALUARD_ARCH_IMAGE:-docker.io/library/archlinux:latest}"

deb=$(find "$ART" -maxdepth 1 -name 'Baluard_*_amd64.deb' | sort -rV | tail -1)
[[ -n "$deb" ]] || { echo "no Baluard_*_amd64.deb in $ART" >&2; exit 1; }
deb=$(cd "$(dirname "$deb")" && pwd)/$(basename "$deb")
name=$(basename "$deb")
sha=$(sha256sum "$deb" | awk '{print $1}')

# The version comes from the deb control: the artifact is the source of truth.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(
  cd "$tmp"
  ar x "$deb"
  # Full extraction on purpose: dpkg stores the member as ./control while
  # tauri-bundler stores it as control; both land at tmp/control.
  tar -xzf control.tar.gz
)
VER=$(awk '/^Version:/ {print $2; exit}' "$tmp/control")
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || { echo "unexpected deb version in $(basename "$deb"): $VER" >&2; exit 1; }

# Serve only the newest versions (same retention as apt/dnf/fdroid); the
# machine-local deb history keeps every version rebuildable. The incoming
# version is part of the retention math: pruning happens before the container
# writes the new package, so the set must include it to stay within KEEP.
ARCH="$OUT/arch/x86_64"
mkdir -p "$ARCH"
KEEP="${BALUARD_LINUX_REPO_KEEP:-3}"
while IFS= read -r old; do
  rm -f "$ARCH/$old" "$ARCH/$old.sig"
done < <({ find "$ARCH" -maxdepth 1 -name 'baluard-*-1-x86_64.pkg.tar.zst' -printf '%f\n'; \
    echo "baluard-$VER-1-x86_64.pkg.tar.zst"; } \
  | sed -E 's/^baluard-([0-9.]+)-1-x86_64\.pkg\.tar\.zst$/\1 \0/' | sort -rV \
  | awk -v k="$KEEP" 'NR>k{print $2}')

# Refresh aur/PKGBUILD to the new release before the container renders
# .SRCINFO from it.
[[ -f "$AUR_DIR/PKGBUILD" ]] || { echo "aur/PKGBUILD is missing" >&2; exit 1; }
sed -i -e "s/^pkgver=.*/pkgver=$VER/" \
  -e "s/^sha256sums=(.*/sha256sums=('$sha')/" "$AUR_DIR/PKGBUILD"
grep -q "^pkgver=$VER$" "$AUR_DIR/PKGBUILD" \
  || { echo "aur/PKGBUILD version bump did not land" >&2; exit 1; }
grep -q "$sha" "$AUR_DIR/PKGBUILD" \
  || { echo "aur/PKGBUILD checksum bump did not land" >&2; exit 1; }

# The repo package is the AUR PKGBUILD with the name un-suffixed and the
# source pointed at the local deb; one file list, no drift between channels.
stage="$tmp/stage"
mkdir -p "$stage"
sed -e 's/^pkgname=.*/pkgname=baluard/' \
  -e "s/^pkgver=.*/pkgver=$VER/" \
  -e "s|^source=(.*|source=(\"$name\")|" \
  -e "s/^sha256sums=(.*/sha256sums=('$sha')/" \
  -e '/^conflicts=/d' \
  -e "s/Baluard-amd64\.deb/$name/g" \
  "$AUR_DIR/PKGBUILD" > "$stage/PKGBUILD"
cp "$deb" "$stage/"

podman run --rm \
  -v "$stage":/build:Z -v "$ARCH":/out:Z -v "$AUR_DIR":/aur:Z \
  -v "$GNUPGHOME":/gnupg:Z -e GNUPGHOME=/gnupg \
  -e PKGVER="$VER" \
  "$IMAGE" bash -euc '
    pacman -Sy --noconfirm fakeroot debugedit >/dev/null
    useradd -M builder
    chown -R builder:builder /build
    su builder -c "cd /build && makepkg -f -d"
    chown -R root:root /build
    pkg="baluard-${PKGVER}-1-x86_64.pkg.tar.zst"
    mv "/build/$pkg" /out/
    # A same-version re-run must not trip gpg overwrite refusal.
    rm -f "/out/$pkg.sig"
    gpg --batch --detach-sign "/out/$pkg"
    cd /out
    # Rebuild the database from scratch: a rebuilt DB cannot carry the
    # SELinux xattrs of an old one, whose restore fails inside the container.
    rm -f baluard.db.tar.zst baluard.db.sig baluard.files.tar.zst baluard.files.sig
    repo-add --sign baluard.db.tar.zst baluard-*-1-x86_64.pkg.tar.zst >/dev/null
    chown builder:builder /aur
    su builder -c "cd /aur && makepkg --printsrcinfo" > /aur/.SRCINFO.new
    mv /aur/.SRCINFO.new /aur/.SRCINFO
    # Container uid 0 maps to the host user (uid 1000 here); the files the
    # builder user wrote land on a subuid the host cannot delete in sticky tmp.
    chown -R 0:0 /build /out /aur
  '

# repo-add leaves plain-name symlinks beside the archives; git hosting cannot
# carry symlinks, so the served plain names are real copies.
for pair in db files; do
  rm -f "$ARCH/baluard.$pair" "$ARCH/baluard.$pair.sig"
  cp -f "$ARCH/baluard.$pair.tar.zst" "$ARCH/baluard.$pair"
  cp -f "$ARCH/baluard.$pair.tar.zst.sig" "$ARCH/baluard.$pair.sig"
done

# The site install snippet fetches this file; the pipeline authors it so the
# rsync mirror needs no site-authored exclusion.
cat > "$OUT/arch/baluard.conf" <<EOF
[baluard]
SigLevel = Required DatabaseOptional
Server = https://baluard.app/repo/arch/x86_64
EOF

echo "arch repo written to $ARCH (baluard $VER)"
