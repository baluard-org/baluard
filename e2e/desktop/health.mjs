// Desktop E2E flow 2: the password health check (docs/e2e-testing.md
// Phase 3, G19's desktop half). Unlock the seeded vault (the runner
// adds one deliberately weak login), open Settings, run the check on
// the Data tab, and assert the findings dialog names the weak entry.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node health.mjs <path-to-baluard-desktop>");
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
  // Unlock.
  const field = await browser.$('[data-testid="login-password"]');
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  await (await browser.$('[data-testid="login-unlock"]')).click();
  const vault = await browser.$('[data-testid="vault-view"]');
  await vault.waitForDisplayed({ timeout: 30000 });

  // Settings -> Data tab -> Run check.
  await (await browser.$('[data-testid="settings-open"]')).click();
  const dataTab = await browser.$('[data-testid="settings-tab-data"]');
  await dataTab.waitForDisplayed({ timeout: 15000 });
  await dataTab.click();
  const run = await browser.$('button=Run check');
  await run.waitForDisplayed({ timeout: 15000 });
  await run.click();

  // The findings dialog groups the seeded weak login under weak, the
  // kind map localizes the reason, and Close returns to settings.
  const weak = await browser.$('div*=Weak passwords (1)');
  await weak.waitForDisplayed({ timeout: 30000 });
  await browser.$('[data-testid="health-finding"]');
  const finding = await browser.$('div=Weak Entry');
  await finding.waitForDisplayed({ timeout: 10000 });
  const reason = await browser.$('div=Too short (3 characters)');
  await reason.waitForDisplayed({ timeout: 10000 });
  const close = await browser.$('button=Close');
  await close.click();
  await weak.waitForDisplayed({ timeout: 10000, reverse: true });
  console.log("E2E desktop health flow: PASS");
} finally {
  await browser.deleteSession().catch(() => {});
}
