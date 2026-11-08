# Baluard Fellowship

Baluard Fellowship is a tiny companion APK for invited friends and family who help test and polish Baluard. While its genuine APK is installed, the Play flavor of Baluard unlocks the same features as an active Supporter subscription. Removing it returns Baluard to the normal Play entitlement check.

The companion has no network permission, accounts, activation, expiry, billing, vault access, or backend. Its only screen thanks the user and confirms the active Fellowship access.

## Signing

The package name alone is not a credential. Baluard accepts only `app.baluard.mobile.fellowship` signed by a certificate pinned in the comma-separated `FELLOWSHIP_CERTIFICATES_SHA256` setting in `mobile/androidApp/build.gradle.kts`. The pinned fingerprints are public; private signing keys are not. A rotated certificate can match through signing history. If Play uses hybrid signing with multiple current signers, every current signer must match a pinned fingerprint.

Keep the dedicated keystore and its passwords backed up in Bitwarden. The current local path is `~/.baluard/fellowship/fellowship-upload-v2.keystore`. Never commit the keystore or passwords.

Configure signing in the git-ignored `mobile/local.properties`:

```properties
fellowship.storeFile=/absolute/path/to/fellowship-upload.keystore
fellowship.storePassword=YOUR_PASSWORD
fellowship.keyPassword=YOUR_PASSWORD
fellowship.keyAlias=fellowship
```

For PKCS12 keystores, set `fellowship.keyPassword` to the same value as `fellowship.storePassword`. Java's PKCS12 implementation protects the private key with the store password, even if keytool accepted a different key password during generation.

The equivalent environment variables are `BALUARD_FELLOWSHIP_KEYSTORE`, `BALUARD_FELLOWSHIP_STORE_PASSWORD`, `BALUARD_FELLOWSHIP_KEY_PASSWORD`, and `BALUARD_FELLOWSHIP_KEY_ALIAS`.

Create a new key interactively only if no Fellowship key exists:

```bash
mkdir -p ~/.baluard/fellowship
keytool -genkeypair -v \
  -keystore ~/.baluard/fellowship/fellowship-upload.keystore \
  -alias fellowship -keyalg RSA -keysize 4096 -validity 10000 \
  -dname 'CN=Baluard Fellowship,O=Baluard Org'
```

The local key is the Play upload key. Play App Signing signs delivered APKs with its own identity. The current Play app-signing SHA-256 pin is the default `fellowshipPlayCertificatesSha256` value in `mobile/androidApp/build.gradle.kts`. During rotation, copy every applicable fingerprint from Play Console > Protected with Play > Play Store protection > Play app signing, remove the colons, and update the default or supply a comma-separated `baluard.fellowshipPlayCertificatesSha256` Gradle property or `BALUARD_FELLOWSHIP_PLAY_CERTIFICATES_SHA256` environment value. The build combines Play pins with the local upload pin in `FELLOWSHIP_CERTIFICATES_SHA256`.

Play release builds refuse a blank or malformed Play pin list. Ship the pinned Baluard update and verify a Play-installed companion before inviting users. The upload certificate alone cannot authenticate a Play-installed companion. Remove the local upload pin after verification if directly signed test APKs no longer need access; retaining it deliberately keeps those APKs valid as bearer licenses.

## Build

From `mobile/` with JDK 17:

```bash
./gradlew :fellowship:assembleRelease :fellowship:bundleRelease
```

The signed APK is `fellowship/build/outputs/apk/release/fellowship-release.apk`. The signed Play upload artifact is `fellowship/build/outputs/bundle/release/fellowship-release.aab`. Release builds fail when signing is not configured.

Verify both certificates before distribution:

```bash
apksigner verify --print-certs fellowship/build/outputs/apk/release/fellowship-release.apk
keytool -printcert -jarfile fellowship/build/outputs/bundle/release/fellowship-release.aab
```

Distribute the app through an invite-only Play internal-testing release, not a draft release. Internal testing supports up to 100 invited testers, and testers install a paid app free. No production release or promo codes are required. If closed testing is used instead, testers must purchase the paid app or redeem a paid-app promo code.

Upload from the repository root with `scripts/upload-play-release.sh`. Set `BALUARD_PLAY_PACKAGE_NAME=app.baluard.mobile.fellowship`, `BALUARD_PLAY_VERSION_NAME` and `BALUARD_PLAY_VERSION_CODE` to the values from `mobile/fellowship/build.gradle.kts`, and `BALUARD_PLAY_TRACK=internal`; pass the Fellowship AAB as the script argument. These overrides prevent the script from using Baluard's workspace version. Individual tester emails are managed in Play Console because the API supports only Google Groups.

The icon masters are `assets/baluard-fellowship-appicon.svg` and `assets/baluard-fellowship-lock.svg`. They preserve the Baluard lock and B, with the complete lock rendered in gold.
