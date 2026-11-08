import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';

import { createRequestHandler } from '../src/http.js';

async function withServer(verifyPurchase, run, options = {}) {
  const server = createServer(createRequestHandler({ ...options, verifyPurchase }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test('health checks do not call Google Play', async () => {
  await withServer(async () => { throw new Error('must not run'); }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/health`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: 'ok' });
  });
});

test('the verify route returns the server entitlement without caching', async () => {
  await withServer(async (token) => {
    assert.equal(token, 'synthetic-purchase-token');
    return { active: true, willRenew: false };
  }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/entitlements/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ purchaseToken: 'synthetic-purchase-token' }),
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await response.json(), { active: true, willRenew: false });
  });
});

test('a transient verifier failure is never returned as an inactive subscription', async () => {
  await withServer(async () => { throw new Error('Google unavailable'); }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/entitlements/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ purchaseToken: 'synthetic-purchase-token' }),
    });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: 'verification_unavailable' });
  });
});

test('verification failure logs exclude tokens and upstream response bodies', async (t) => {
  const errors = [];
  t.mock.method(console, 'error', (entry) => errors.push(entry));
  await withServer(async () => {
    throw new Error('Google Play verification failed: HTTP 403');
  }, async (baseUrl) => {
    await fetch(`${baseUrl}/v1/entitlements/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ purchaseToken: 'synthetic-purchase-token' }),
    });
  });
  assert.equal(errors.length, 1);
  assert.deepEqual(JSON.parse(errors[0]), {
    event: 'play_verification_failed',
    message: 'Google Play verification failed: HTTP 403',
  });
  assert.equal(errors[0].includes('synthetic-purchase-token'), false);
});

const invalidRequests = [
  ['malformed JSON', '{', 'application/json', 400],
  ['missing token', '{}', 'application/json', 400],
  ['blank token', '{"purchaseToken":" "}', 'application/json', 400],
  ['current-directory token', '{"purchaseToken":"."}', 'application/json', 400],
  ['parent-directory token', '{"purchaseToken":".."}', 'application/json', 400],
  ['whitespace token', '{"purchaseToken":"token with space"}', 'application/json', 400],
  ['wrong media type', '{"purchaseToken":"token"}', 'text/plain', 415],
];

for (const [name, body, contentType, expectedStatus] of invalidRequests) {
  test(`the verify route rejects ${name}`, async () => {
    await withServer(async () => { throw new Error('must not run'); }, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/v1/entitlements/verify`, {
        method: 'POST',
        headers: { 'content-type': contentType },
        body,
      });
      assert.equal(response.status, expectedStatus);
      assert.deepEqual(await response.json(), { error: 'invalid_request' });
    });
  });
}

test('the verify route rejects oversized bodies before parsing them', async () => {
  await withServer(async () => { throw new Error('must not run'); }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/entitlements/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ purchaseToken: 'a'.repeat(9_000) }),
    });
    assert.equal(response.status, 413);
  });
});

test('other routes and methods cannot invoke verification', async () => {
  await withServer(async () => { throw new Error('must not run'); }, async (baseUrl) => {
    const wrongRoute = await fetch(`${baseUrl}/v1/entitlements`);
    assert.equal(wrongRoute.status, 404);
    const wrongMethod = await fetch(`${baseUrl}/v1/entitlements/verify`);
    assert.equal(wrongMethod.status, 405);
  });
});

test('a malformed request target is rejected without an unhandled rejection', async () => {
  const handler = createRequestHandler({ verifyPurchase: async () => { throw new Error('must not run'); } });
  let status = null;
  const response = {
    writeHead(code) { status = code; },
    end() {},
  };
  await handler({ url: '//', method: 'GET', headers: {} }, response);
  assert.equal(status, 400);
});

test('verification requests are limited per client IP', async () => {
  let calls = 0;
  await withServer(async () => {
    calls++;
    return { active: true, willRenew: true };
  }, async (baseUrl) => {
    const request = () => fetch(`${baseUrl}/v1/entitlements/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ purchaseToken: 'synthetic-purchase-token' }),
    });
    assert.equal((await request()).status, 200);
    assert.equal((await request()).status, 200);
    const limited = await request();
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '60');
    assert.deepEqual(await limited.json(), { error: 'rate_limited' });
    assert.equal(calls, 2);
  }, { rateLimit: { perIp: 2, global: 10, windowMs: 60_000 } });
});

test('a per-instance limit protects the Google API quota across client IPs', async () => {
  let calls = 0;
  await withServer(async () => {
    calls++;
    return { active: true, willRenew: true };
  }, async (baseUrl) => {
    const request = (ip) => fetch(`${baseUrl}/v1/entitlements/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
      body: JSON.stringify({ purchaseToken: 'synthetic-purchase-token' }),
    });
    assert.equal((await request('203.0.113.1')).status, 200);
    assert.equal((await request('203.0.113.2')).status, 200);
    assert.equal((await request('203.0.113.3')).status, 429);
    assert.equal(calls, 2);
  }, { rateLimit: { perIp: 10, global: 2, windowMs: 60_000 } });
});
