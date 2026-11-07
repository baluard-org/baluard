# ADR 0102. Sync, Sharing, and TOTP Subscription on Store Builds

> Status: Accepted. The Play listing is free, and sync, sharing, and TOTP code generation on the store build are paid through an in-app subscription. F-Droid and desktop stay free without gating.

## Context

Baluard is GPL-3.0 free software with no server backend. Sync is the user's own Git repository on their own provider, so serving a user costs Baluard nothing per user. The project's costs are structural, recurring, and independent of user count:

| Cost | Nature | Status |
|---|---|---|
| Hosting for baluard.app and the package repos | Recurring, yearly | Active |
| Domain renewals (baluard.app and the org domains) | Recurring, yearly | Active |
| Apple Developer Program | 99 USD per year, mandatory for any App Store presence | Pending, required before iOS ships |
| Windows code-signing certificate | Recurring, to remove the SmartScreen warning | Planned |
| API tokens and paid services used in development | Recurring, variable | Active |
| GitHub Actions minutes beyond the free tier | Recurring, appears with CI growth | Future |
| Esteban's time, machines, and their wear | Continuous, uncompensated | Active |

One-time sales cannot meet recurring costs. A paid listing cannot recur, and Play forbids in-app products on paid apps, so the two store monetization models are mutually exclusive. The chosen model is a recurring subscription sold through Google Play Billing, which carries a flat 15 percent service fee.

The audience splits cleanly. Average users install from a store and never learn what F-Droid is. Technical users can add an F-Droid repository or pull a release from GitHub. Charging the store path a small recurring fee while the free paths stay free is a convenience and sustainability fee, not a feature ransom. This framing must stay visible in the store listing copy to stay honest.

## Decision

1. The Google Play listing is a free app forever. Google forbids converting a free app to paid, and the listing must never charge at install. Monetization rides an in-app subscription only.
2. The subscription is a single product: one base plan, one year, auto-renewing at 4.99 USD, with a 14-day free-trial offer attached. Google runs the trial clock, payment collection, and expiry; the app only checks entitlement. The nominal price is "5 USD a year".
3. Sync, sharing, and TOTP code generation are the gated features on the Play build of the mobile app. Sync gates completely: provider connect, sync setup, manual sync, and automatic sync all require an active subscription or an active trial. Sharing gates completely: creating a shared vault, inviting, joining, and every member surface for family, team, or organization spaces require it. Single-user vaults stay fully free. TOTP is gated at generation only: storing, viewing, and editing a TOTP seed stays free, but the app does not generate live codes for a locked subscription, the same split Bitwarden draws with its premium tier.
4. The gate lives in the mobile app layer behind a Gradle flavor split. The `play` flavor ships Google Play Billing and gates sync. The `fdroid` flavor contains no billing code at all, because Google's billing library is proprietary and F-Droid policy forbids it, and its sync stays free and ungated. Both flavors share the applicationId, signing key, versionName, and versionCode.
5. The core library never gates anything. `baluard-core` exposes sync to desktop and mobile identically, and desktop sync stays free forever. The gate is a product surface of the store build, not a property of the codebase. A future iOS build gates the same way through StoreKit 2 with the same product terms.
6. A lapsed or refused subscription disables sync in the app only. The local vault keeps working fully offline, the user's Git repository on their provider remains theirs and untouched, and the desktop app can always sync the same vault for free. Nothing is deleted, locked, or held hostage.
7. Entitlement is checked through `queryPurchasesAsync` at app start and resume, with the last known state cached so offline use never locks a paying user out mid-flight. Revocations and refunds take effect at the next check.
8. No other existing feature is ever retro-gated. Entries, passkeys, and everything else shipped before this decision stay free on every channel. Three exceptions are disclosed up front: sync, sharing, and TOTP code generation on the Play mobile build. Forward-only gating beyond these three keeps the split honest: store builds pay for sync, sharing, and live codes, every other path keeps everything free.

## Consequences

The Android build grows two flavors, and the F-Droid publishing pipeline must keep producing the ungated flavor while the Play pipeline produces the gated bundle. The release tooling needs both artifacts to carry the same version code so the stores stay aligned.

The store listing must disclose the subscription plainly: what it unlocks (sync, sharing, and live TOTP codes), the price and term (4.99 USD per year after a 14-day free trial), and the fact that the app remains a fully functional single-user offline password manager without it. Play review checks this disclosure, and the honesty requirement is also the brand requirement.

Subscriptions convert poorly when they gate nothing, so this decision deliberately gates the features a multi-device or multi-user life actually wants. A single-device, single-user, no-TOTP user never meets the paywall. That is the intended shape: the fee lands on the moments where the product grows beyond one person and one device, which is also where store distribution starts to matter.

The costs table above is the reason this exists, and it should be revisited whenever a new recurring cost appears (a notarization service, a mirror, a new store fee). If recurring revenue ever exceeds recurring costs, the correct move is to lower the price or ungated sync again, not to accumulate surplus.
