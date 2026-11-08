import assert from 'node:assert/strict';
import test from 'node:test';

import { createPlayVerifier } from '../src/verify.js';

const NOW = 1_800_000_000_000;
const PACKAGE_NAME = 'app.baluard.mobile';
const PRODUCT_ID = 'baluard_supporter_yearly';

function googleResponse(status, body) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function activePurchase() {
  return {
    kind: 'androidpublisher#subscriptionPurchaseV2',
    regionCode: 'US',
    startTime: new Date(NOW - 60_000).toISOString(),
    subscriptionState: 'SUBSCRIPTION_STATE_ACTIVE',
    linkedPurchaseToken: null,
    acknowledgementState: 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    externalAccountIdentifiers: {},
    lineItems: [{
      productId: PRODUCT_ID,
      expiryTime: new Date(NOW + 60_000).toISOString(),
      latestSuccessfulOrderId: 'GPA.0000-0000-0000-00000',
      autoRenewingPlan: {
        autoRenewEnabled: true,
        recurringPrice: { units: '4', nanos: 990_000_000, currencyCode: 'USD' },
      },
      offerDetails: { basePlanId: 'yearly', offerTags: [] },
      offerPhase: { basePrice: {} },
    }],
    etag: 'synthetic-etag',
  };
}

function verifierWith(fetchImpl) {
  return createPlayVerifier({
    getAccessToken: async () => 'synthetic-access-token',
    packageName: PACKAGE_NAME,
    productId: PRODUCT_ID,
    now: () => NOW,
    fetchImpl,
  });
}

test('verification uses the authenticated subscriptionsv2 endpoint', async () => {
  let request;
  const verify = verifierWith(async (url, options) => {
    request = { url, options };
    return googleResponse(200, activePurchase());
  });
  assert.deepEqual(await verify('token/with+synthetic characters'), { active: true, willRenew: true });
  assert.equal(
    request.url,
    'https://androidpublisher.googleapis.com/androidpublisher/v3/applications/app.baluard.mobile/purchases/subscriptionsv2/tokens/token%2Fwith%2Bsynthetic%20characters',
  );
  assert.equal(request.options.headers.authorization, 'Bearer synthetic-access-token');
  assert.equal(request.options.method, 'GET');
});

for (const status of [410]) {
  test(`Google ${status} is a terminal inactive entitlement`, async () => {
    const verify = verifierWith(async () => googleResponse(status, { error: { status } }));
    assert.deepEqual(await verify('synthetic-purchase-token'), { active: false });
  });
}

for (const status of [400, 401, 403, 404, 429, 500, 503]) {
  test(`Google ${status} remains a verification failure`, async () => {
    const verify = verifierWith(async () => googleResponse(status, { error: { status } }));
    await assert.rejects(() => verify('synthetic-purchase-token'));
  });
}

test('Google error logs include only a structured reason', async () => {
  const verify = verifierWith(async () => googleResponse(401, {
    error: {
      status: 'PERMISSION_DENIED',
      message: 'sensitive upstream message',
      details: [{
        '@type': 'type.googleapis.com/google.rpc.ErrorInfo',
        reason: 'ACCESS_TOKEN_SCOPE_INSUFFICIENT',
      }],
    },
  }));
  await assert.rejects(
    () => verify('synthetic-purchase-token'),
    (error) => {
      assert.equal(error.message, 'Google Play request failed with status 401 (ACCESS_TOKEN_SCOPE_INSUFFICIENT)');
      assert.equal(error.message.includes('sensitive upstream message'), false);
      return true;
    },
  );
});

test('a malformed Google success response remains a verification failure', async () => {
  const verify = verifierWith(async () => googleResponse(200, '{not-json'));
  await assert.rejects(() => verify('synthetic-purchase-token'));
});
