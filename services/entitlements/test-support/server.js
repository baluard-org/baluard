import { createServer } from 'node:http';

import { createRequestHandler } from '../src/http.js';

const verifyPurchase = async (token) => {
  if (token !== 'synthetic-contract-token') return { active: false };
  return { active: true, willRenew: false };
};
const server = createServer(createRequestHandler({ verifyPurchase }));
server.listen(Number(process.env.PORT ?? 0), '127.0.0.1', () => {
  console.log(`Contract server listening on port ${server.address().port}`);
});
