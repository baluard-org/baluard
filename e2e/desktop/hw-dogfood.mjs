import { gatewayRequest } from "../extension/gateway.mjs";
import { readFileSync } from "node:fs";

const [sock, slug, tokPath, ...actions] = process.argv.slice(2);
const token = readFileSync(tokPath, "utf8").trim();
const call = (action, payload) =>
  gatewayRequest(sock, { action, payload: JSON.stringify(payload ?? {}), token, slug }, 30000)
    .then((r) => JSON.parse(r))
    .catch((e) => ({ __err: String(e) }));

for (const a of actions) {
  if (a === "enable") console.log("enable:", JSON.stringify(await call("vault.hw_enable", { consent: false })));
  else if (a === "lock") console.log("lock:", JSON.stringify(await call("vault.lock", {})));
  else if (a === "status") console.log("status:", JSON.stringify(await call("vault.hw_status", {})));
  else if (a === "disable") console.log("disable:", JSON.stringify(await call("vault.hw_disable", {})));
}
