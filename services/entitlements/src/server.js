import { createServer } from 'node:http';

import { createRequestHandler } from './http.js';
import { createMetadataTokenProvider } from './metadata.js';
import { createPlayVerifier } from './verify.js';

const packageName = process.env.PLAY_PACKAGE_NAME ?? 'app.baluard.mobile';
const productId = process.env.PLAY_PRODUCT_ID ?? 'baluard_supporter_yearly';
const port = Number(process.env.PORT ?? 8080);

if (!/^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(packageName)) throw new Error('Invalid PLAY_PACKAGE_NAME');
if (!/^[a-z0-9_.-]+$/.test(productId)) throw new Error('Invalid PLAY_PRODUCT_ID');
if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error('Invalid PORT');

const verifyPurchase = createPlayVerifier({
  getAccessToken: createMetadataTokenProvider(),
  packageName,
  productId,
});
const server = createServer(createRequestHandler({ verifyPurchase }));
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.listen(port, '0.0.0.0', () => {
  console.log(`Entitlement service listening on port ${port}`);
});

function shutdown() {
  const forceExit = setTimeout(() => process.exit(1), 5_000);
  forceExit.unref();
  server.close(() => {
    clearTimeout(forceExit);
    process.exit(0);
  });
  server.closeIdleConnections();
}

process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
