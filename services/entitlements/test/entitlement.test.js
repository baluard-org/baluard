import assert from 'node:assert/strict';
import test from 'node:test';

import { subscriptionEntitlement } from '../src/entitlement.js';

const NOW = 1_800_000_000_000;
const PRODUCT_ID = 'baluard_supporter_yearly';

function lineItem({ productId = PRODUCT_ID, expiryEpochMs = NOW + 60_000, autoRenew = true } = {}) {
  return {
    productId,
    expiryTime: new Date(expiryEpochMs).toISOString(),
    latestSuccessfulOrderId: 'GPA.0000-0000-0000-00000',
    autoRenewingPlan: {
      autoRenewEnabled: autoRenew,
      recurringPrice: { units: '4', nanos: 990_000_000, currencyCode: 'USD' },
    },
    offerDetails: { basePlanId: 'yearly', offerTags: [] },
    offerPhase: { basePrice: {} },
  };
}

function subscription(state, items = [lineItem()]) {
  return {
    kind: 'androidpublisher#subscriptionPurchaseV2',
    regionCode: 'US',
    startTime: new Date(NOW - 60_000).toISOString(),
    subscriptionState: state,
    linkedPurchaseToken: null,
    acknowledgementState: 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    externalAccountIdentifiers: {},
    lineItems: items,
    etag: 'synthetic-etag',
  };
}

const states = [
  ['SUBSCRIPTION_STATE_ACTIVE', true, true],
  ['SUBSCRIPTION_STATE_CANCELED', true, false],
  ['SUBSCRIPTION_STATE_IN_GRACE_PERIOD', true, true],
  ['SUBSCRIPTION_STATE_PENDING', false, false],
  ['SUBSCRIPTION_STATE_PAUSED', false, false],
  ['SUBSCRIPTION_STATE_ON_HOLD', false, false],
  ['SUBSCRIPTION_STATE_EXPIRED', false, false],
  ['SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED', false, false],
];

for (const [state, active, willRenew] of states) {
  test(`${state} maps to active=${active}`, () => {
    const items = state === 'SUBSCRIPTION_STATE_CANCELED'
      ? [lineItem({ autoRenew: false })]
      : state === 'SUBSCRIPTION_STATE_EXPIRED'
        ? [lineItem({ expiryEpochMs: NOW - 1, autoRenew: false })]
        : [lineItem()];
    assert.deepEqual(
      subscriptionEntitlement(subscription(state, items), { productId: PRODUCT_ID, nowEpochMs: NOW }),
      active ? { active: true, willRenew } : { active: false },
    );
  });
}

test('an active state with a past expiry does not unlock', () => {
  const purchase = subscription('SUBSCRIPTION_STATE_ACTIVE', [lineItem({ expiryEpochMs: NOW - 1 })]);
  assert.deepEqual(
    subscriptionEntitlement(purchase, { productId: PRODUCT_ID, nowEpochMs: NOW }),
    { active: false },
  );
});

test('another product never unlocks the Baluard entitlement', () => {
  const purchase = subscription('SUBSCRIPTION_STATE_ACTIVE', [lineItem({ productId: 'another_product' })]);
  assert.deepEqual(
    subscriptionEntitlement(purchase, { productId: PRODUCT_ID, nowEpochMs: NOW }),
    { active: false },
  );
});

test('the latest matching line item survives a deferred product change', () => {
  const purchase = subscription('SUBSCRIPTION_STATE_ACTIVE', [
    lineItem({ expiryEpochMs: NOW - 1, autoRenew: false }),
    lineItem({ expiryEpochMs: NOW + 120_000, autoRenew: true }),
  ]);
  assert.deepEqual(
    subscriptionEntitlement(purchase, { productId: PRODUCT_ID, nowEpochMs: NOW }),
    { active: true, willRenew: true },
  );
});

test('malformed active data is not converted into a terminal entitlement', () => {
  const purchase = subscription('SUBSCRIPTION_STATE_ACTIVE', [lineItem()]);
  delete purchase.lineItems[0].expiryTime;
  assert.throws(
    () => subscriptionEntitlement(purchase, { productId: PRODUCT_ID, nowEpochMs: NOW }),
    /expiryTime/,
  );
});
