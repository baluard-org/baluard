# ADR 0104. Fellowship Companion Entitlement

> Status: Accepted. A signature-verified companion app unlocks Play-gated features for invited testers while it remains installed.

## Context

Close friends and family help test and polish Baluard. They need continuing access to subscription-gated features without buying a subscription, creating an account, activating a license, or depending on a backend. Google Play does not provide the desired gift-subscription path.

A package-name check is insufficient because another developer could publish an APK with the same application ID. A separate repository would duplicate the Android build configuration and make the companion contract harder to test with the main app.

## Decision

1. The main repository contains the independent Android application module `mobile/fellowship`, with application ID `app.baluard.mobile.fellowship`. It shares no vault, billing, Rust, or networking code with Baluard.
2. The companion displays one thank-you screen. It requests no network permission and stores no data. Its icon uses the Baluard lock and B with the complete lock in gold.
3. The Play manifest makes only this package visible. Baluard reads its signing information and requires a certificate in its signing history to match a pinned SHA-256 fingerprint. The pin setting accepts the local upload certificate and Play's app-signing certificates. Hybrid signing with multiple current signers requires every current signer to match a pinned fingerprint. Missing packages, malformed pins, missing certificates, and wrong signatures fail closed.
4. A valid installed companion provides a distinct Fellowship fallback. Baluard still queries Play so acknowledgment and server verification continue, and a verified Play purchase wins over Fellowship. Without a verified purchase, Fellowship unlocks even when Play is unavailable. That offline fallback preserves an existing paid or trial cache; a definite inactive Play result replaces a stale paid cache with Fellowship. The effective rule is Fellowship OR verified Play subscription.
5. Fellowship has no expiry. Uninstalling the companion removes Fellowship access at the next entitlement refresh, including when Baluard resumes. Its distinct cached phase lets an unavailable Play result revoke Fellowship without revoking an ordinary paid user's offline cache. The F-Droid flavor remains ungated and unchanged.
6. The companion uses a dedicated upload key stored outside the repository. Only public certificate fingerprints are committed. Its signed AAB is distributed as a one-time paid app through an invite-only Play internal-testing release, where up to 100 testers can install it free. It remains off production. Play App Signing signs the delivered APKs, so Baluard must pin the Play app-signing fingerprints as well as any directly signed test identity it supports. Play release builds fail without a valid Play pin list.

## Consequences

The companion is deliberately a bearer license: anyone who obtains a genuine signed APK can install it. Play's invited tester list controls normal distribution, not obfuscation or DRM. This is appropriate for trusted testers and is not a general DRM mechanism.

The upload key and passwords require a durable backup, although Play can reset a lost upload key. Certificate rotation requires accepting the signing history and, for a new pinned identity, a Baluard Play update. Play's app-signing fingerprints must be added before the Play-installed companion can unlock Baluard.

Fellowship access works offline and adds no data transfer. Existing Play verification continues unchanged, including purchase-token transfer for paid users. Play server verification remains the authority for ordinary subscriptions, so this addition does not weaken purchase validation for other users.
