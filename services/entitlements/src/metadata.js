const METADATA_TOKEN_URL = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fandroidpublisher';
const REFRESH_BEFORE_EXPIRY_MS = 60_000;

export function createMetadataTokenProvider({ now = Date.now, fetchImpl = fetch } = {}) {
  let cachedToken = null;
  let refreshAt = 0;
  let pending = null;

  return async () => {
    if (cachedToken !== null && now() < refreshAt) return cachedToken;
    if (pending !== null) return pending;

    pending = (async () => {
      let response;
      try {
        response = await fetchImpl(METADATA_TOKEN_URL, {
          headers: { 'Metadata-Flavor': 'Google' },
          signal: AbortSignal.timeout(5_000),
        });
      } catch (error) {
        throw new Error('Google metadata token request failed', { cause: error });
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error('Google metadata token request failed');
      }

      let data;
      try {
        data = await response.json();
      } catch (error) {
        throw new Error('Google metadata token response was malformed', { cause: error });
      }
      if (typeof data.access_token !== 'string' || data.access_token.length === 0 ||
          !Number.isFinite(data.expires_in) || data.expires_in <= 0) {
        throw new Error('Google metadata token response was invalid');
      }

      cachedToken = data.access_token;
      refreshAt = now() + data.expires_in * 1000 - REFRESH_BEFORE_EXPIRY_MS;
      return cachedToken;
    })();

    try {
      return await pending;
    } finally {
      pending = null;
    }
  };
}
