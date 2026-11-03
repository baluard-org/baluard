# Linux repositories

Baluard ships Linux packages through its own apt and dnf repository, signed with the Baluard release GPG key. Installing through the repository gives you GPG-verified installs and updates through your package manager, with no manual downloads. Direct downloads from GitHub Releases carry detached minisign signatures and a signed `SHA256SUMS` manifest as the verification path.

## Ubuntu and Debian (apt)

Run these commands as yourself; only the two write steps need sudo, and you run them:

```sh
curl -fsSL https://baluard.app/repo/baluard-release.asc | sudo gpg --dearmor -o /usr/share/keyrings/baluard-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/baluard-archive-keyring.gpg] https://baluard.app/repo stable main" | sudo tee /etc/apt/sources.list.d/baluard.list
sudo apt update && sudo apt install baluard
```

The key fingerprint is `223310EA BF1A B6FE E6BD DF3E 2A53 1D54 E6D7 4804` (Baluard Release <baluard@actitud.xyz>). Verify it before trusting the repository.

## Fedora (dnf)

```sh
sudo tee /etc/yum.repos.d/baluard.repo <<'EOF'
[baluard]
name=Baluard
baseurl=https://baluard.app/repo/rpms
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://baluard.app/repo/baluard-release.asc
EOF
sudo dnf install baluard
```

dnf checks the repository metadata signature (`repo_gpgcheck`) and the package signature (`gpgcheck`), and shows the key fingerprint for you to confirm on first use.

## Direct downloads

Every artifact on GitHub Releases carries a `.sig` sidecar made with the updater signing key, and the release directory contains `SHA256SUMS` with its own `.sig`:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

`SHA256SUMS.sig` is made with the same minisign key that signs desktop updates; the public key is pinned in `tauri.conf.json`. Verify it with any minisign implementation after base64-decoding the published key file, since the published form is base64-wrapped.

## Maintainer release flow

The signing keys live outside the repository and are Esteban's to hold and back up. The release flow from locally built artifacts (default staging dir `./dist`, gitignored):

Build the desktop and Android release artifacts first, then run:

```sh
just release-repositories
```

This command verifies the APK first, signs `./dist`, regenerates the apt, dnf, and F-Droid trees in `./repo-out`, and mirrors them into `../baluard-org`. Each step stops the pipeline on failure. Synchronization removes stale generated files, preserves the repository directory guards, and does not touch other website files. Linux package history persists in `~/.baluard/linux-repo-history/`, so deleting `repo-out` does not remove older packages from the next build. Already-signed RPMs are not signed again.

Review the resulting diff in `baluard-org`, then commit and push it to publish. The pipeline never commits or pushes automatically. The Linux trees map to `repo/`; the F-Droid tree maps to the site root at `fdroid/`. See `docs/dev/fdroid-repository.md`.

The individual steps remain available as `just release-sign`, `just repo-stage`, and `just repo-sync`.
