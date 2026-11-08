const MAX_BODY_BYTES = 8_192;
const MAX_TOKEN_LENGTH = 4_096;
const MAX_TRACKED_CLIENTS = 1_024;
function hasValidTokenCharacters(token) {
  return Array.from(token).every((character) => {
    const code = character.charCodeAt(0);
    return code >= 33 && code <= 126;
  });
}

class RequestError extends Error {
  constructor(status) {
    super('Invalid request');
    this.status = status;
  }
}

function sendJson(response, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  response.end(payload);
}

async function readPurchaseToken(request) {
  const mediaType = request.headers['content-type']?.split(';', 1)[0].trim().toLowerCase();
  if (mediaType !== 'application/json') throw new RequestError(415);

  const declaredLength = Number(request.headers['content-length'] ?? 0);
  if (declaredLength > MAX_BODY_BYTES) throw new RequestError(413);
  let size = 0;
  let tooLarge = false;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      tooLarge = true;
    } else {
      chunks.push(chunk);
    }
  }
  if (tooLarge) throw new RequestError(413);

  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new RequestError(400);
  }
  if (body === null || Array.isArray(body) || typeof body !== 'object') throw new RequestError(400);
  const token = body.purchaseToken;
  if (typeof token !== 'string' || token.trim().length === 0 || token.length > MAX_TOKEN_LENGTH ||
      token === '.' || token === '..' || !hasValidTokenCharacters(token)) {
    throw new RequestError(400);
  }
  return token;
}

function requestIp(request) {
  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    // The final address is appended by the Google Front End.
    return forwarded.split(',').at(-1).trim();
  }
  return request.socket?.remoteAddress ?? 'unknown';
}

function createRateLimiter({ perIp = 10, global = 60, windowMs = 60_000 } = {}, now) {
  const clients = new Map();
  let globalWindow = { startedAt: now(), count: 0 };

  return (request) => {
    const time = now();
    if (time - globalWindow.startedAt >= windowMs) globalWindow = { startedAt: time, count: 0 };
    const retryAfter = Math.max(1, Math.ceil((globalWindow.startedAt + windowMs - time) / 1_000));
    if (globalWindow.count >= global) return { allowed: false, retryAfter };

    for (const [ip, entry] of clients) {
      if (time - entry.startedAt >= windowMs) clients.delete(ip);
    }
    const ip = requestIp(request);
    if (!clients.has(ip) && clients.size >= MAX_TRACKED_CLIENTS) {
      clients.delete(clients.keys().next().value);
    }
    const entry = clients.get(ip) ?? { startedAt: time, count: 0 };
    if (entry.count >= perIp) {
      const ipRetryAfter = Math.max(1, Math.ceil((entry.startedAt + windowMs - time) / 1_000));
      return { allowed: false, retryAfter: ipRetryAfter };
    }

    entry.count++;
    globalWindow.count++;
    clients.set(ip, entry);
    return { allowed: true };
  };
}

async function handleRequest(request, response, verifyPurchase, checkRateLimit) {
  let path;
  try {
    path = new URL(request.url, 'http://localhost').pathname;
  } catch {
    sendJson(response, 400, { error: 'invalid_request' });
    return;
  }
  if (path === '/health' && request.method === 'GET') {
    sendJson(response, 200, { status: 'ok' });
    return;
  }
  if (path !== '/v1/entitlements/verify') {
    sendJson(response, 404, { error: 'not_found' });
    return;
  }
  if (request.method !== 'POST') {
    sendJson(response, 405, { error: 'invalid_request' }, { allow: 'POST' });
    return;
  }

  try {
    const rateLimit = checkRateLimit(request);
    if (!rateLimit.allowed) {
      sendJson(response, 429, { error: 'rate_limited' }, { 'retry-after': rateLimit.retryAfter });
      return;
    }
    const purchaseToken = await readPurchaseToken(request);
    const entitlement = await verifyPurchase(purchaseToken);
    sendJson(response, 200, entitlement);
  } catch (error) {
    if (error instanceof RequestError) {
      sendJson(response, error.status, { error: 'invalid_request' });
      return;
    }
    console.error(JSON.stringify({ event: 'play_verification_failed', message: error.message }));
    sendJson(response, 503, { error: 'verification_unavailable' });
  }
}

export function createRequestHandler({ verifyPurchase, rateLimit, now = Date.now }) {
  const checkRateLimit = createRateLimiter(rateLimit, now);
  return (request, response) => {
    handleRequest(request, response, verifyPurchase, checkRateLimit).catch(() => {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      sendJson(response, 503, { error: 'verification_unavailable' });
    });
  };
}
