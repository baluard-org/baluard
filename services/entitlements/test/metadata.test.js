import assert from 'node:assert/strict';
import test from 'node:test';

import { createMetadataTokenProvider } from '../src/metadata.js';

test('metadata tokens are cached until their refresh window', async () => {
  let now = 1_000_000;
  let metadataCalls = 0;
  const getToken = createMetadataTokenProvider({
    now: () => now,
    fetchImpl: async (url, options) => {
      metadataCalls += 1;
      assert.equal(url, 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fandroidpublisher');
      assert.equal(options.headers['Metadata-Flavor'], 'Google');
      return Response.json({ access_token: `token-${metadataCalls}`, expires_in: 3600, token_type: 'Bearer' });
    },
  });
  assert.equal(await getToken(), 'token-1');
  assert.equal(await getToken(), 'token-1');
  now += 3_601_000;
  assert.equal(await getToken(), 'token-2');
  assert.equal(metadataCalls, 2);
});

test('metadata failures do not expose response data', async () => {
  const getToken = createMetadataTokenProvider({
    fetchImpl: async () => new Response('sensitive-upstream-body', { status: 503 }),
  });
  await assert.rejects(
    () => getToken(),
    (error) => !error.message.includes('sensitive-upstream-body'),
  );
});
