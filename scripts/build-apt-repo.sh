#!/usr/bin/env bash
# Build an apt repository fragment (pool/ + dists/stable) from the .deb files
# in an artifacts directory, signing the metadata with the release GPG key.
# Pure shell on purpose: no dpkg-dev or apt-utils needed on the build host.
set -euo pipefail

ART="${1:?usage: build-apt-repo.sh <artifacts-dir> <repo-out-dir>}"
OUT="${2:?usage: build-apt-repo.sh <artifacts-dir> <repo-out-dir>}"
# The control-extraction step cds into a temp dir, so both paths must be
# absolute or the relative ones break mid-script.
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ART=$(cd "$ART" && pwd)
GNUPGHOME="${BALUARD_RELEASE_GNUPGHOME:-$HOME/.baluard/release-gnupg}"
export GNUPGHOME
EMAIL="baluard@actitud.xyz"
gpg --homedir "$GNUPGHOME" --list-secret-keys "$EMAIL" >/dev/null 2>&1 \
  || { echo "release GPG key missing; run scripts/gen-release-signing-key.sh" >&2; exit 1; }

POOL="$OUT/pool/main/b/baluard"
DIST="$OUT/dists/stable/main/binary-amd64"
HISTORY="${BALUARD_LINUX_REPO_HISTORY:-$HOME/.baluard/linux-repo-history}"
mkdir -p "$POOL" "$DIST" "$HISTORY/deb"
cp -f "$ART"/*.deb "$HISTORY/deb/"
cp -f "$HISTORY/deb"/*.deb "$POOL/"

# Serve only the newest versions; the machine-local history mirrors the same
# window. Keeps the Pages deploy small, like the F-Droid APK retention.
KEEP="${BALUARD_LINUX_REPO_KEEP:-2}"
find "$POOL" -maxdepth 1 -name 'Baluard_*_amd64.deb' -printf '%f\n' \
  | sed -E 's/^Baluard_([0-9.]+)_amd64\.deb$/\1 \0/' | sort -rV \
  | awk -v k="$KEEP" 'NR>k{print $2}' \
  | while IFS= read -r old; do rm -f "$POOL/$old"; done
find "$HISTORY/deb" -maxdepth 1 -name 'Baluard_*_amd64.deb' -printf '%f\n' \
  | sed -E 's/^Baluard_([0-9.]+)_amd64\.deb$/\1 \0/' | sort -rV \
  | awk -v k="$KEEP" 'NR>k{print $2}' \
  | while IFS= read -r old; do rm -f "$HISTORY/deb/$old"; done

# One stanza per deb: fields from the deb's control file plus the repo-added
# location, size, and hashes apt needs.
: > "$DIST/Packages"
for deb in "$POOL"/*.deb; do
  name=$(basename "$deb")
  size=$(stat -c %s "$deb")
  sha256=$(sha256sum "$deb" | awk '{print $1}')
  sha512=$(sha512sum "$deb" | awk '{print $1}')
  md5=$(md5sum "$deb" | awk '{print $1}')

  tmp=$(mktemp -d)
  (
    cd "$tmp"
    ar x "$deb"
    tar -xf control.tar.*
  )
  control="$tmp/control"
  [[ -f "$control" ]] || { echo "no control in $name" >&2; exit 1; }

  # Copy the maintainer-written fields verbatim (Description spans lines),
  # then append the repo-added fields.
  awk 'BEGIN{p=1} /^$/{p=0} p' "$control" >> "$DIST/Packages"
  {
    echo "Filename: pool/main/b/baluard/$name"
    echo "Size: $size"
    echo "MD5sum: $md5"
    echo "SHA256: $sha256"
    echo "SHA512: $sha512"
    echo
  } >> "$DIST/Packages"
  rm -rf "$tmp"
done
gzip -n -9 -c "$DIST/Packages" > "$DIST/Packages.gz"

# Release: checksum entries group under ONE header per hash type, the way
# apt-ftparchive writes them. One repeated header per entry makes apt's tag
# parser drop duplicates and the repo silently loses its index targets.
# The Date needs the UTC-named RFC 1123 form; a numeric offset (-0300) is
# rejected and the whole repo silently loses its Packages.
date_r=$(date -u '+%a, %d %b %Y %H:%M:%S UTC')
{
  echo "Origin: Baluard"
  echo "Label: Baluard"
  echo "Suite: stable"
  echo "Codename: stable"
  echo "Architectures: amd64"
  echo "Components: main"
  echo "Description: Baluard package repository"
  echo "Date: $date_r"
  for alg in md5sum sha256sum sha512sum; do
    case $alg in md5sum) H=MD5Sum ;; sha256sum) H=SHA256 ;; sha512sum) H=SHA512 ;; esac
    echo "$H:"
    for f in Packages Packages.gz; do
      p="main/binary-amd64/$f"
      echo " $($alg "$DIST/$f" | awk '{print $1}') $(stat -c %s "$DIST/$f") $p"
    done
  done
} > "$OUT/dists/stable/Release"

rm -f "$OUT/dists/stable/InRelease" "$OUT/dists/stable/Release.gpg"
gpg --batch --clearsign -o "$OUT/dists/stable/InRelease" "$OUT/dists/stable/Release"
gpg --batch --armor --detach-sign -o "$OUT/dists/stable/Release.gpg" "$OUT/dists/stable/Release"
echo "apt repo written to $OUT"
