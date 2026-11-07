# Google Play runbook

Baluard ships to Google Play as a free listing with an in-app subscription (ADR 0102). This runbook records the console setup that already happened, the rules that burned us once, and the per-release flow. The F-Droid repository runbook is [fdroid-repository.md](fdroid-repository.md); the subscription decision is [ADR 0102](../adr/0102-store-sync-subscription.md).

## App identity

- Package: `app.baluard.mobile`. Developer account: `baluardorg@gmail.com` (developer id 6959677981119303519, personal account).
- Console: play.google.com/console, app card "Baluard". Until the first production review passes, testers see the temporary name `app.baluard.mobile (unreviewed)`.
- The upload vehicle is an AAB; Play accepts AAB only for new apps. `just android-apk-release` emits both artifacts from the flavor split (ADR 0102): the F-Droid APK (ungated) at `mobile/androidApp/build/outputs/apk/fdroid/release/androidApp-fdroid-release.apk` and the AAB (for Play) at `mobile/androidApp/build/outputs/bundle/play/release/androidApp-play-release.aab`.

## Signing

Play App Signing is set up, and the store and F-Droid share one identity:

- The upload keystore is `~/.baluard/baluard-android-upload.keystore`, alias `baluard-upload` (distinct from the F-Droid repo keystore at `~/.baluard/fdroid/keystore.p12`). Passwords come from `BALUARD_ANDROID_STORE_PASSWORD` / `BALUARD_ANDROID_KEY_PASSWORD` in the environment; the keystore is backed up in Bitwarden.
- The Play app signing key is the same `baluard-release` key, transferred through the PEPK flow (`java -jar pepk.jar` answering keystore prompts from a pty driver so passwords never hit argv; the transfer key zip uploaded on the App signing page). The console's in-use App signing certificate SHA-256 must equal `9cdf3df5ef4a228d51cc5bfabaa303d65bd534c306c12aa0a8857cea223130ff`, which is the same fingerprint pinned in the F-Droid metadata `AllowedAPKSigningKeys`. Verify both sides stay equal after any signing change.
- The signing key cannot be changed after a release rolls out to open testing or production. Closed and internal testing do not lock it.

## Version codes

Version codes burn permanently on the first processed upload, even when the draft release is later discarded. Codes 1007 and 1008 are consumed this way and must never be reused. The formula is the workspace standard: `major*1000000 + minor*1000 + patch`, so 0.1.9 shipped as 1009 and the next usable code is 1010.

Play rejects uploads whose `targetSdk` is below the current policy floor (36 as of late 2026). `compileSdk` and `targetSdk` live in `mobile/androidApp/build.gradle.kts` and `mobile/shared/build.gradle.kts`; both must move together.

Never bump the Play version ahead of F-Droid for the same `versionName`: a Play 1010 over an F-Droid 1009 for the same release would block Play-to-F-Droid downgrades until the next release. Stores always ship the same versionCode.

## Tracks

- Internal testing: up to 100 testers, no Google review, installs immediate. Does NOT count toward the personal-account production requirement (12 continuous opted-in testers for 14 days).
- Closed testing: the track that satisfies the 12-testers/14-days production runway. Carry the same AAB there when the clock should start.
- Testers install through the opt-in link on each track's Testers tab. Testers get paid products and subscriptions free while in a testing track, so nothing charges until production.
- Release naming convention in the forms: `0.1.9 (1009)` style, version visible to testers. Tester-facing release notes: what changed, what to try, report to support@baluard.app, end with "Thanks for testing."

## Console setup already done

- App content declarations: privacy policy `https://baluard.app/privacy/`, ads No, IARC rating questionnaire (lands Everyone / PEGI 3), data safety "no data collected or shared" per the privacy page's network-egress inventory, audience 18 and over only, Online content No, category Productivity.
- App access: restricted = Yes, with reviewer instructions: Baluard is a local password manager with no accounts; reviewers create a vault with any master password; biometric unlock is optional. Credential form: name "Review vault", username and password fields empty.
- Google Payments merchant profile: business name Baluard Org, website baluard.app, what you sell Computer Software, support email support@baluard.app, statement name Baluard.
- Store listing kit lives in `assets/store/play/`: `app-icon-512.png`, `feature-graphic-1024x500.png`, `phone/`, `tablet-7/`, `tablet-10/`, and `desktop/` screenshots. Listing copy was drafted in esteban-voice: title "Baluard Password Manager", short description "Passwords, passkeys and TOTP on your device. No accounts, no servers.", full description grounded in the privacy page with honest beta status.

## Monetization (ADR 0102)

- The listing must be FREE. Google forbids converting a free app to paid, and paid apps cannot carry in-app products, so the subscription model requires the free listing. Keep it free permanently.
- Subscription product (create it only once the billing build exists on a test track): product ID `baluard_supporter_yearly`, one base plan, 1 year auto-renew at 4.99 USD, plus a 14-day free-trial offer. Google runs the trial clock; the app only checks entitlement.
- The gated surfaces on the store build are sync, sharing, and TOTP code generation. The F-Droid APK is a separate ungated build (the flavor split carries no Google billing library, which F-Droid policy forbids). Desktop stays free.
- Add tester emails as license testers so purchases are free during testing.

### Billing implementation facts (landed in the play flavor)

- Gate mechanics: `mobile/shared/src/commonMain/kotlin/app/baluard/mobile/monetization/Monetization.kt` holds the pure entitlement model. The persisted cache encodes `EntitlementPhase.name`, so `androidApp/proguard-rules.pro` pins that enum's fields — R8 renaming the constants would silently break decode across releases.
- The store contract is two suspend calls: `query()` and `purchase()` returning a `PurchaseOutcome`. The gate queries first and loads the cache after, so a purchase landing mid-flight wins, and identical query results never rewrite the cache.
- `PlayBillingStore` (androidApp/src/play) uses the billing-ktx suspend extensions `queryPurchasesAsync` and `queryProductDetails` — note the product-details one has NO Async suffix in 7.1.1 — from `com.android.billingclient.api`. `launchBillingFlow` needs an Activity, so the store tracks the resumed activity via lifecycle callbacks registered by `PlayMonetizationApplication`.
- Acknowledgment happens in the purchases-updated listener; Google refunds unacknowledged subscriptions after 3 days.
- The fdroid build seeds an in-memory permanently-unlocked cache: nothing persists and no fresh-install window can ever gate an F-Droid user.
- Release guard: `mobile/scripts/build-android-apk.sh` greps the fdroid APK's dex pool for `com/android/billingclient` and fails the build if any billing class reaches it.

## Store listing disclosure

- The full description must disclose the subscription in plain terms: sync, authenticator codes, and shared-vault member management are part of the Baluard Supporter subscription (4.99 USD per year, auto-renewing, with a 14-day free trial through Google Play); the vault always stays on the device and nothing locks existing data.
- Add the free-elsewhere line to defuse the GPL tension: the same app is available free on F-Droid.
- Google's subscription policy also requires the price, term, and trial to be visible before purchase — the Google Play purchase sheet carries those, so the app copy only needs the plain-language disclosure.

## Automation

No official Play MCP or CLI exists. The path is the Google Play Developer API (androidpublisher) driven by curl plus a service-account JWT, mirroring the Chrome Web Store pipeline:

1. Play Console, Setup, API access: link a Google Cloud project, enable the Android Developer API.
2. Create a service account with the Release Manager role, download the JSON key.
3. Store the key in Bitwarden and at `~/.baluard/play-service-account.json` mode 600.
4. Then `scripts/upload-play-release.sh` plus a `just play-submit` recipe can carry the AAB to the tracks, gated on `BALUARD_PLAY_SERVICE_ACCOUNT_JSON` with skip mode without credentials, like `ext-submit`.

## Per-release flow

1. Bump the workspace version (all seven sources, one versionCode).
2. `just android-apk-release` builds the release APK and the Play AAB from the same source.
3. Console: upload the AAB to the internal testing release and, when the runway clock should run, the closed testing release; release name `X.Y.Z (NNNN)`; paste tester notes.
4. `just release-repositories` stages the same versionCode APK into the F-Droid repo and publishes it through the baluard-org republish.
5. Store submissions (Chrome, AMO) are governed by the unchanged-bundle gate in the release protocol, not by Play.
