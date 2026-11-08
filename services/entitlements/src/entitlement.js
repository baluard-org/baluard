const ACTIVE_STATES = new Set([
  'SUBSCRIPTION_STATE_ACTIVE',
  'SUBSCRIPTION_STATE_CANCELED',
  'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
]);

const INACTIVE_STATES = new Set([
  'SUBSCRIPTION_STATE_PENDING',
  'SUBSCRIPTION_STATE_PAUSED',
  'SUBSCRIPTION_STATE_ON_HOLD',
  'SUBSCRIPTION_STATE_EXPIRED',
  'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED',
]);

export function subscriptionEntitlement(purchase, { productId, nowEpochMs }) {
  if (!ACTIVE_STATES.has(purchase.subscriptionState) && !INACTIVE_STATES.has(purchase.subscriptionState)) {
    throw new Error('Unknown subscriptionState');
  }
  if (!Array.isArray(purchase.lineItems)) throw new Error('Missing lineItems');

  const items = purchase.lineItems.filter((item) => item.productId === productId);
  if (items.length === 0) return { active: false };

  const expiries = items.map((item) => {
    const expiry = Date.parse(item.expiryTime);
    if (!Number.isFinite(expiry)) throw new Error('Invalid expiryTime');
    return expiry;
  });
  const latestExpiry = Math.max(...expiries);
  const latest = items[expiries.indexOf(latestExpiry)];
  const active = ACTIVE_STATES.has(purchase.subscriptionState) && latestExpiry > nowEpochMs;
  if (!active) return { active: false };
  return { active: true, willRenew: latest.autoRenewingPlan?.autoRenewEnabled === true };
}
