# ADR 0103. Google Play Entitlement Verification Service

> Status: Accepted. A Cloud Run service verifies Play purchase tokens for configured Play builds. This refines the entitlement-check mechanism in ADR 0102 without changing the product, price, gated features, or F-Droid split.

## Context

ADR 0102 used `queryPurchasesAsync` as the authority for Play entitlement. That confirms what the local Billing service reports, but it is not server-side verification and does not inspect the subscription lifecycle exposed by `purchases.subscriptionsv2.get`.

Baluard has no user accounts and no vault backend. Adding account infrastructure only for monetization would increase privacy risk and complexity. The service therefore needs to verify a bearer purchase token without storing vault data, personal profiles, or a service-account private key.

## Decision

1. The main repository contains a small Node.js service in `services/entitlements`, deployed independently to Cloud Run. A separate repository is unnecessary because the client and server API contract evolves in the same review.
2. The service calls `purchases.subscriptionsv2.get` directly over authenticated HTTPS. Cloud Run's attached service account supplies OAuth access tokens through the metadata server. No service-account JSON key is created, stored, or shipped.
3. The Play app continues to use BillingClient to discover and acknowledge purchases. When `ENTITLEMENT_SERVICE_URL` is configured, the app sends each purchased token to the service and uses the server's answer instead of the local purchased assertion. An empty URL retains device-only behavior for debug builds. Play release builds fail without a valid HTTPS service URL.
4. Active, canceled-but-unexpired, and grace-period subscriptions unlock while the matching product has a future expiry. Pending, paused, on-hold, expired, gone, and wrong-product purchases do not unlock. Cancellation stops renewal but retains access until expiry. Google extends `expiryTime` during grace periods, so the same expiry check applies there.
5. Only HTTP 410 from Google is a terminal purchase outcome. HTTP 404 can also identify a package or service-account configuration error, so it remains unavailable. Authentication failures, argument or configuration errors, quotas, timeouts, Google 5xx responses, malformed responses, and service outages are unavailable outcomes. Unavailable outcomes preserve the cached entitlement; they never masquerade as an expired subscription.
6. The service is stateless and returns only `active` and `willRenew`. It does not return Google account data, order IDs, tokens, prices, or raw Play responses. Request size and token syntax are bounded, malformed request targets are controlled responses, per-client and per-instance verification rates are limited, and all responses are `no-store`.
7. The F-Droid flavor and desktop behavior do not change. The service processes only Play entitlement data and never receives vault contents, master passwords, encryption keys, or Git credentials.
8. Start-and-resume verification remains the freshness mechanism in this increment. Real-time developer notifications require an authenticated Pub/Sub endpoint and a persisted entitlement ledger in a later increment.

## Consequences

Google Cloud becomes a required production operator dependency for configured Play builds. The expected request volume fits within Cloud Run's free allowances, but deployment still needs a billing account, budget alerts, API quota monitoring, and a Play Console service-account grant.

A configured Play build now verifies entitlement with Google whenever it has connectivity. Temporary verification failures preserve offline access under the same cache policy as ADR 0102, so refunds and revocations still take effect only after a successful verification.

The public verification endpoint can be called without a Baluard account. A valid purchase token authorizes only an entitlement lookup, not account or vault access. Per-client limits, a per-instance ceiling, one-instance deployment, and Google API quotas bound operational exposure. They do not eliminate distributed denial of service; application attestation can be added later without changing the verification contract.

Purchase tokens are bearer credentials and are not bound to a Baluard account or device. Anyone who obtains a valid token can query its entitlement. The service never logs or returns tokens, Android sends them only to the configured HTTPS origin without following redirects, and the no-account design deliberately avoids a persisted token-to-user ledger.
