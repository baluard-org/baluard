// Desktop E2E flow 1: the unlock path (the E2E harness).
// Drives the REAL WebKitGTK webview through tauri-driver: type the
// seeded vault's password into the login form, unlock, assert the
// vault hub renders. The runner (run-e2e-desktop.sh) owns the
// display, vite, the seeded sandbox, and cleanup.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node unlock.mjs <path-to-baluard-desktop>");
const pw = process.env.BALUARD_E2E_PW;
assert(pw, "BALUARD_E2E_PW must be set by the runner");

const browser = await remote({
  hostname: "127.0.0.1",
  port: 4444,
  capabilities: {
    "tauri:options": { application: app },
  },
  logLevel: "warn",
  waitforTimeout: 20000,
});

try {
  // The login card: password field + unlock submit.
  const field = await browser.$('[data-testid="login-password"]');
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  const unlock = await browser.$('[data-testid="login-unlock"]');
  await unlock.click();

  // The unlocked hub marker (VaultView root) appears.
  const vault = await browser.$('[data-testid="vault-view"]');
  await vault.waitForDisplayed({
    timeout: 30000,
    timeoutMsg: "vault hub did not render after unlock",
  });
  console.log("E2E desktop unlock flow: PASS");
} finally {
  await browser.deleteSession().catch(() => {});
}
