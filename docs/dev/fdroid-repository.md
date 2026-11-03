# F-Droid repository

Baluard operates a simple binary F-Droid repository at `https://baluard.app/fdroid/repo/`. Users can add that URL in F-Droid under Settings, Repositories, or open it on a device with F-Droid installed.

The repository signing-key SHA-256 fingerprint is `C5A690013893C46F208A506AEA9217D37FF007C0A2B0A2514039FE28DD58C7A8`. Confirm this fingerprint when adding the repository.

## Local setup

Install the pinned repository tools in a virtual environment:

```sh
python3 -m venv ~/.baluard/fdroidserver-venv
~/.baluard/fdroidserver-venv/bin/pip install fdroidserver==2.4.5
```

Build the signed release APK with `mobile/scripts/build-android-apk.sh --release`, then stage the repository:

```sh
just fdroid-stage
```

The script verifies the application ID, signing certificate, and `versionName` before signing the release artifacts. The expected APK certificate is committed in `fdroid/allowed-signing-key.sha256`. `fdroid update` also receives that fingerprint through `AllowedAPKSigningKeys`.

The full `just release-repositories` command stages every package repository and synchronizes the website worktree. Only `repo-out/fdroid/repo/` is public. Build status files, local paths, passwords, and keys are excluded. Review and push the website changes to publish.

## Updates

Copy each newly built release APK into the repository and regenerate the indexes. `fdroid-stage` does both. F-Droid offers an update when the APK has the same application ID and signing certificate and a higher `versionCode`. Change `versionCode` in `mobile/androidApp/build.gradle.kts` for every release. Replacing an APK without increasing `versionCode` produces a warning and does not update installed clients. Do not set `CurrentVersionCode`; that would pin automatic updates to an older release.

The repository retains the latest three APK versions by default. Set `BALUARD_FDROID_APK_RETENTION` to change this limit. Unchanged inputs do not regenerate the indexes, which avoids timestamp-only changes.

Play Store installs use Play's signing certificate and cannot update through this repository. Use the same distribution channel for subsequent updates.

## Keys and backups

The repository signing key is separate from the APK signing key. Back up these three files off-machine:

```text
~/.baluard/fdroid/config.yml
~/.baluard/fdroid/keystore.p12
~/.baluard/fdroid/allowed-apk-signing-key
```

They contain the repository identity, its password-bearing configuration, and the expected APK certificate. Never publish them or place them in a git repository. Losing the repository key requires users to remove and re-add the repository.

The build uses these official F-Droid references:

- https://f-droid.org/docs/Setup_an_F-Droid_App_Repo/
- https://f-droid.org/docs/Signing_Process/
- https://f-droid.org/docs/Build_Metadata_Reference/
