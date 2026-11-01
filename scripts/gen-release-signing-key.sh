#!/usr/bin/env bash
# Generate the Baluard Linux package-repo signing key (GPG) in a dedicated
# GNUPGHOME, so the entire signing state is one directory to back up.
# Idempotent: exits 0 without touching an existing key.
set -euo pipefail

GNUPGHOME="${BALUARD_RELEASE_GNUPGHOME:-$HOME/.baluard/release-gnupg}"
UID_NAME="Baluard Release"
UID_EMAIL="baluard@actitud.xyz"

if gpg --homedir "$GNUPGHOME" --list-secret-keys "$UID_EMAIL" >/dev/null 2>&1; then
  echo "release key already exists in $GNUPGHOME"
  gpg --homedir "$GNUPGHOME" --list-secret-keys --with-colons "$UID_EMAIL" \
    | awk -F: '/^fpr/{print "fingerprint: " $10; exit}'
  exit 0
fi

mkdir -p -m 700 "$GNUPGHOME"

# No passphrase: the key file itself is the secret, protected by the host and
# the offline backup. Same posture as the minisign updater key.
gpg --homedir "$GNUPGHOME" --batch --passphrase '' --quick-generate-key \
  "$UID_NAME <$UID_EMAIL>" ed25519 sign never

gpg --homedir "$GNUPGHOME" --armor --export "$UID_EMAIL" \
  > "$GNUPGHOME/baluard-release.asc"
chmod 644 "$GNUPGHOME/baluard-release.asc"

echo "fingerprint:"
gpg --homedir "$GNUPGHOME" --list-secret-keys --with-colons "$UID_EMAIL" \
  | awk -F: '/^fpr/{print "  " $10; exit}'
echo
echo "public key (safe to publish): $GNUPGHOME/baluard-release.asc"
echo "back up this whole directory: $GNUPGHOME"
