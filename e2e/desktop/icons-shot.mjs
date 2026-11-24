// Settings icon snapshot: screenshots the Agents and Browser connect
// tabs after an icon swap. Read-only against a sandboxed vault.
import { remote } from "webdriverio";
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";

const app = process.argv[2];
assert(app, "usage: node icons-shot.mjs <path-to-baluard-desktop>");
const pw = process.env.BALUARD_E2E_PW;
const out = process.env.SHOT_DIR;
assert(pw && out, "runner must set BALUARD_E2E_PW and SHOT_DIR");
mkdirSync(out, { recursive: true });

const browser = await remote({
  hostname: "127.0.0.1",
  port: 4444,
  capabilities: {
    "tauri:options": { application: app },
  },
  logLevel: "warn",
  waitforTimeout: 20000,
});

const q = (testid) => browser.$(`[data-testid="${testid}"]`);

// Clicking a tab starts transition-colors + the modal resize animation; a
// screenshot before they settle paints a stale sidebar pill. Wait for the
// aria flip, then let CSS finish.
async function openTabAndSettle(testid) {
  const tab = await q(testid);
  await tab.click();
  await browser.waitUntil(async () => (await tab.getAttribute("aria-current")) === "page", { timeout: 10000 });
  await browser.pause(400);
}

try {
  await browser.setWindowSize(1280, 800);

  const field = await q("login-password");
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  await (await q("login-unlock")).click();
  await (await q("vault-view")).waitForDisplayed({ timeout: 30000 });

  await (await q("settings-open")).click();
  await (await q("settings-tab-general")).waitForDisplayed({ timeout: 20000 });

  await openTabAndSettle("settings-tab-agents");
  await (await q("agent-settings")).waitForDisplayed({ timeout: 20000 });
  await browser.saveScreenshot(`${out}/settings-agents-icons.png`);
  console.log(`PASS agents tab shot: ${out}/settings-agents-icons.png`);

  await openTabAndSettle("settings-tab-bridge");
  await browser.saveScreenshot(`${out}/settings-bridge-icons.png`);
  console.log(`PASS bridge tab shot: ${out}/settings-bridge-icons.png`);

  await openTabAndSettle("settings-tab-legacy");
  await browser.saveScreenshot(`${out}/settings-legacy-icons.png`);
  console.log(`PASS legacy tab shot: ${out}/settings-legacy-icons.png`);
} finally {
  await browser.deleteSession();
}
