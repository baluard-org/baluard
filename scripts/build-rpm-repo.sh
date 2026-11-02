#!/usr/bin/env bash
# Build an RPM repository (rpms/ + signed repodata) from the .rpm files in an
# artifacts directory. Uses host createrepo_c when present, else a throwaway
# podman Fedora container, so the build host needs no dnf tooling installed.
set -euo pipefail

ART="${1:?usage: build-rpm-repo.sh <artifacts-dir> <repo-out-dir>}"
OUT="${2:?usage: build-rpm-repo.sh <artifacts-dir> <repo-out-dir>}"
# The createrepo step cds into the output tree, so both paths must be
# absolute or the relative ones break mid-script.
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ART=$(cd "$ART" && pwd)
GNUPGHOME="${BALUARD_RELEASE_GNUPGHOME:-$HOME/.baluard/release-gnupg}"
export GNUPGHOME
EMAIL="baluard@actitud.xyz"
gpg --homedir "$GNUPGHOME" --list-secret-keys "$EMAIL" >/dev/null 2>&1 \
  || { echo "release GPG key missing; run scripts/gen-release-signing-key.sh" >&2; exit 1; }

mkdir -p "$OUT/rpms"
cp -f "$ART"/*.rpm "$OUT/rpms/"

# Sign the packages BEFORE building metadata: rpmsign rewrites the file, so
# the repodata hashes must be taken over the signed bytes. dnf's gpgcheck=1
# refuses an unsigned package even when the repo metadata verifies.
if command -v rpmsign >/dev/null 2>&1; then
  rpmsign --define "_gpg_name $EMAIL" --define "_gpg_path $GNUPGHOME" \
    --addsign "$OUT"/rpms/*.rpm
else
  podman run --rm -v "$OUT/rpms":/rpms:Z -v "$GNUPGHOME":/gnupg:Z -e GNUPGHOME=/gnupg \
    registry.fedoraproject.org/fedora:latest \
    sh -c "dnf install -y rpm-sign >/dev/null 2>&1 && cd /rpms && \
      rpmsign --define '_gpg_name $EMAIL' --define '_gpg_path /gnupg' --addsign *.rpm"
fi

if command -v createrepo_c >/dev/null 2>&1; then
  (cd "$OUT/rpms" && createrepo_c .)
else
  podman run --rm -v "$OUT/rpms":/rpms:Z registry.fedoraproject.org/fedora:latest \
    sh -c "dnf install -y createrepo_c >/dev/null 2>&1 && cd /rpms && createrepo_c ."
fi

rm -f "$OUT/rpms/repodata/repomd.xml.asc"
gpg --batch --armor --detach-sign \
  -o "$OUT/rpms/repodata/repomd.xml.asc" "$OUT/rpms/repodata/repomd.xml"
echo "rpm repo written to $OUT/rpms"
