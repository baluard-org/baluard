import { subscriptionEntitlement } from './entitlement.js';

const TERMINAL_GOOGLE_ERRORS = new Set([410]);
const PLAY_API_ROOT = 'https://androidpublisher.googleapis.com/androidpublisher/v3/applications';

class GooglePlayRequestError extends Error {
  constructor(status) {
    super(`Google Play request failed with status ${status}`);
    this.name = 'GooglePlayRequestError';
    this.status = status;
  }
}

export function createPlayVerifier({
  getAccessToken,
  packageName,
  productId,
  now = Date.now,
  fetchImpl = fetch,
}) {
  return async (purchaseToken) => {
    let response;
    try {
      const accessToken = await getAccessToken();
      const packageSegment = encodeURIComponent(packageName);
      const tokenSegment = encodeURIComponent(purchaseToken);
      response = await fetchImpl(
        `${PLAY_API_ROOT}/${packageSegment}/purchases/subscriptionsv2/tokens/${tokenSegment}`,
        {
          method: 'GET',
          headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
          signal: AbortSignal.timeout(10_000),
        },
      );
    } catch (error) {
      if (error instanceof GooglePlayRequestError) throw error;
      throw new Error('Google Play request unavailable', { cause: error });
    }

    if (!response.ok) {
      await response.body?.cancel();
      if (TERMINAL_GOOGLE_ERRORS.has(response.status)) return { active: false };
      throw new GooglePlayRequestError(response.status);
    }

    let purchase;
    try {
      purchase = await response.json();
    } catch (error) {
      throw new Error('Google Play returned malformed JSON', { cause: error });
    }
    return subscriptionEntitlement(purchase, { productId, nowEpochMs: now() });
  };
}
