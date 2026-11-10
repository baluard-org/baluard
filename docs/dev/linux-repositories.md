# Linux repositories

Baluard ships Linux packages through its own apt and dnf repository, signed with the Baluard release GPG key. Installing through the repository gives you GPG-verified installs and updates through your package manager, with no manual downloads. Direct downloads from GitHub Releases carry detached minisign signatures and a signed `SHA256SUMS` manifest as the verification path.

## Ubuntu and Debian (apt)

Run these commands as yourself; only the two write steps need sudo, and you run them:

```sh
curl -fsSL https://packages.baluard.app/baluard-release.asc | sudo gpg --dearmor -o /usr/share/keyrings/baluard-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/baluard-archive-keyring.gpg] https://packages.baluard.app stable main" | sudo tee /etc/apt/sources.list.d/baluard.list
sudo apt update && sudo apt install baluard
```

The key fingerprint is `223310EA BF1A B6FE E6BD DF3E 2A53 1D54 E6D7 4804` (Baluard Release <baluard@actitud.xyz>). Verify it before trusting the repository.

## Fedora (dnf)

```sh
sudo tee /etc/yum.repos.d/baluard.repo <<'EOF'
[baluard]
name=Baluard
baseurl=https://packages.baluard.app/rpms
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.baluard.app/baluard-release.asc
EOF
sudo dnf install baluard
```

dnf checks the repository metadata signature (`repo_gpgcheck`) and the package signature (`gpgcheck`), and shows the key fingerprint for you to confirm on first use.

## Arch Linux (pacman)

```sh
curl -s https://packages.baluard.app/baluard-release.asc | sudo pacman-key --add -
sudo pacman-key --lsign-key 223310EABF1AB6FEE6BDDF3E2A531D54E6D74804
sudo tee /etc/pacman.d/baluard.conf <<'EOF'
[baluard]
SigLevel = Required DatabaseOptional
Server = https://packages.baluard.app/arch/x86_64
EOF
grep -q baluard.conf /etc/pacman.conf || echo "Include = /etc/pacman.d/baluard.conf" | sudo tee -a /etc/pacman.conf
sudo pacman -Syu baluard
```

Pacman verifies the database and package signatures against the imported release key before installing. The repository also feeds the AUR package `baluard-bin`, which repackages the same upstream artifacts.

### AUR (parked, do not retry yet)

The `baluard-bin` submission is prepared but parked: aur.archlinux.org has closed new-account registration while it deals with a wave of automated account creation (no manual queue; reopening is announced on the aur-general mailing list and the Arch news feed). Everything else works normally, and the pacman repository above fully serves Arch users in the meantime. When registration reopens: create the account, add an SSH key under My Account, then import the three files the pipeline keeps fresh in `aur/` (PKGBUILD, .SRCINFO, LICENSE) per the submission recipe — a clone of `ssh://aur@aur.archlinux.org/baluard-bin.git` expecting the empty-repository warning, copy, commit, push. Until that blocker resolves, do not retry registration or script checks against it.

## Direct downloads

Every artifact on GitHub Releases carries a `.sig` sidecar made with the updater signing key, and the release directory contains `SHA256SUMS` with its own `.sig`:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

`SHA256SUMS.sig` is made with the same minisign key that signs desktop updates; the public key is pinned in `tauri.conf.json`. Verify it with any minisign implementation after base64-decoding the published key file, since the published form is base64-wrapped.

## Maintainer release flow

The full shipping runbook lives in `docs/dev/release-protocol.md` (version bump, keys, build matrix, store publishing, update channels). The Linux-specific summary:

The signing keys live outside the repository and are Esteban's to hold and back up. The release flow from locally built artifacts (default staging dir `./dist`, gitignored):

Build the desktop and Android release artifacts first, then run:

```sh
just release-repositories
```

This command first rebuilds the browser extension bundles and packages the store zips into `./dist` (`baluard-extension-<version>-chrome.zip` / `-firefox.zip`), failing if the rebuild drifts from the committed dists. It then verifies the APK, signs `./dist`, regenerates the apt, dnf, Arch, and F-Droid trees in `./repo-out`, and publishes them to the package site checkout `../baluard-packages` (the `baluard-org/baluard-packages` repository, which `packages.baluard.app` serves as a custom domain). The main site carries no package bytes. Each step stops the pipeline on failure. Synchronization removes stale generated files, preserves the repository directory guards, and does not touch other website files. The apt, dnf, and Arch repos keep only the newest two package versions (`BALUARD_LINUX_REPO_KEEP` overrides the count), mirrored by the `~/.baluard/linux-repo-history/` archive so deleting `repo-out` does not remove recent packages from the next build. Full history lives in the package-site git repository and the GitHub releases. Already-signed RPMs are not signed again.

Review the resulting diff in `baluard-org`, then commit and push it to publish. The pipeline never commits or pushes automatically. The Linux trees map to `repo/`; the F-Droid tree maps to the site root at `fdroid/`. See `docs/dev/fdroid-repository.md`.

Before running the pipeline for a new release, bump the version with `just bump-version X.Y.Z`. It moves every version source together (Cargo workspace, desktop Cargo/package, Android `versionName`/`versionCode`, the extension manifest and package, the mobile about-string), then rebuilds the committed extension dists so the bump commit carries fresh dists. It refuses non-semver and non-increasing versions.

Store upload is a separate deliberate step after this pipeline: `just ext-submit` publishes the extension, building the Firefox AMO submission from `browser/firefox/dist` and uploading the packaged Chrome zip to the Chrome Web Store. See `browser/README.md` for the credential setup.

The individual steps remain available as `just release-sign`, `just repo-stage`, and `just repo-sync`.
