# Baluard entitlement service

This Cloud Run service verifies Google Play purchase tokens with `purchases.subscriptionsv2.get`. It handles only subscription entitlement data. Vaults, master passwords, encryption keys, and Git credentials never reach it.

The service uses the Cloud Run attached service account through the metadata server. It has no npm runtime dependencies and needs no service-account JSON key.

## API

`POST /v1/entitlements/verify`

```json
{"purchaseToken":"<token from Play Billing>"}
```

An active, canceled-but-unexpired, or grace-period subscription with a future expiry returns:

```json
{"active":true,"willRenew":true}
```

`willRenew` is `false` after cancellation. Pending, paused, on-hold, expired, gone, and wrong-product purchases return:

```json
{"active":false}
```

Transient Google, authentication, argument or configuration, timeout, and malformed-upstream failures return HTTP 503 with `{"error":"verification_unavailable"}`. Google 404 also returns 503 because it can identify a package or service-account configuration error rather than a missing purchase. Only Google 410 is terminal. These failures never become an inactive entitlement. The Android client preserves its cached entitlement for these failures and for other non-200 responses.

Verification requests are limited to 10 per client IP and 60 per service instance per minute. Excess requests return HTTP 429 with `{"error":"rate_limited"}` and `Retry-After`; Android treats them as unavailable. Health checks are not limited.

`GET /healthz` returns `{"status":"ok"}` without calling Google Play. All responses carry `Cache-Control: no-store`.

## Local verification

Use Node.js 22 or later. There are no packages to install.

```bash
cd services/entitlements
npm test
```

The tests use synthetic tokens and mocked Google boundaries. The HTTP tests start real local servers. Production Google calls require the Cloud Run metadata server and are not available from a local `npm start`.

Run the cross-language contract check with the Node fixture in one terminal:

```bash
PORT=18080 node test-support/server.js
```

Then run the real Android verifier in another terminal:

```bash
cd mobile
BALUARD_TEST_ENTITLEMENT_URL="http://127.0.0.1:18080" ./gradlew :androidApp:testPlayDebugUnitTest \
  --tests "app.baluard.mobile.monetization.ServerEntitlementContractTest"
```

The fixture accepts only the synthetic contract token and returns a canceled-but-active entitlement.

## Google Cloud and Play Console setup

Run these commands from the repository root after replacing the project and region values. A Google Cloud billing account is required, although the expected low volume fits within the free allowances.

```bash
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"
export ENTITLEMENT_SERVICE_ACCOUNT="baluard-entitlements@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
```

Enable the required APIs and create the dedicated runtime identity:

```bash
gcloud services enable \
  androidpublisher.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  --project="$GCP_PROJECT_ID"

gcloud iam service-accounts create baluard-entitlements \
  --display-name="Baluard entitlement verification" \
  --project="$GCP_PROJECT_ID"
```

In Play Console, open Users and permissions and invite `baluard-entitlements@${GCP_PROJECT_ID}.iam.gserviceaccount.com`. Restrict access to the Baluard app. Grant both permissions required by Google's Play Billing API documentation:

- View financial data, orders, and cancellation survey responses.
- Manage orders and subscriptions.

The service only calls the read-only `subscriptionsv2.get` method. Do not create or download a service-account key.

## Deploy

```bash
gcloud run deploy baluard-entitlements \
  --source=services/entitlements \
  --project="$GCP_PROJECT_ID" \
  --region="$GCP_REGION" \
  --service-account="$ENTITLEMENT_SERVICE_ACCOUNT" \
  --allow-unauthenticated \
  --ingress=all \
  --cpu-throttling \
  --timeout=20 \
  --min-instances=0 \
  --max-instances=1 \
  --concurrency=80 \
  --set-env-vars="PLAY_PACKAGE_NAME=app.baluard.mobile,PLAY_PRODUCT_ID=baluard_supporter_yearly"
```

Public invocation is required because the Android app calls the service directly without a Baluard account. A purchase token is required to obtain an entitlement. Request bodies are bounded, package and product IDs are fixed server-side, and no route returns Google account or subscription details. Keep the one-instance ceiling so the per-instance rate limit applies to all requests. The limiter resets on restart and does not eliminate distributed denial of service. Configure Google Cloud budget alerts and Play Developer API quota alerts.

Purchase tokens are bearer credentials and are not bound to a Baluard account or device. Anyone who obtains one can query its entitlement. The service never logs or returns tokens, and Android refuses redirects and non-HTTPS production endpoints. Treat deployed tokens and logs as sensitive operational data.

Check the deployed health endpoint:

```bash
curl --fail "https://YOUR_SERVICE_URL/healthz"
```

Do not put a real purchase token in shell arguments, shell history, logs, tickets, or test fixtures. Verify a real purchase through the Play build and Play Billing Lab instead.

## Configure the Android Play build

Pass the deployed base URL with either a Gradle property or an environment variable:

```bash
cd mobile
./gradlew :androidApp:bundlePlayRelease \
  -Pbaluard.entitlementServiceUrl="https://YOUR_SERVICE_URL"
```

```bash
BALUARD_ENTITLEMENT_SERVICE_URL="https://YOUR_SERVICE_URL" ./gradlew :androidApp:bundlePlayRelease
```

An empty URL keeps the previous device-only behavior for debug development. `playRelease` fails when the URL is blank or is not a valid HTTPS origin without user info, query, or fragment. Loopback HTTP is available only to local JVM tests. The F-Droid flavor has no verifier or service configuration and remains ungated.

Before the production rollout, update the public privacy policy and network-egress inventory to disclose purchase-token verification, and review the Play Data safety declaration against that new transfer.

## Operational behavior

The Play app still uses `queryPurchasesAsync` to discover purchase tokens and acknowledge purchases. When configured, it grants or removes entitlement only from this service's response. It checks at app start and resume, after purchase, and on other existing entitlement refreshes.

A successful inactive response clears the unlocked entitlement. An unavailable service or transient Google failure preserves the cached state, so a temporary backend fault does not downgrade a paying user. This preserves the existing offline trade-off: a revocation takes effect after a successful verification, not while the app cannot reach the service.

Google dynamically extends `expiryTime` during grace periods, so the future-expiry check covers grace correctly. Before production, use Play Billing Lab to verify grace, renewal, cancellation, account hold, and expiration against the deployed service. Local mocks do not replace those checks.

Real-time developer notifications and a persisted entitlement ledger are not part of this service yet. Add that increment with an authenticated Pub/Sub push endpoint and a datastore before replacing start-and-resume checks as the primary freshness mechanism.
