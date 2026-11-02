// Desktop E2E flow 4: the hardware security-chip guard (the E2E harness,
// hw-seal wave). Unlock the seeded vault, open Settings > Data, assert the
// chip card renders (the probe must report capable - run the harness under
// `sg tss` on machines whose TPM group is not in the session), toggle the
// guard on through the asymmetric-disclosure dialog, and verify the button
// flips to its disable label. Requires an hw-seal daemon sidecar.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node hw.mjs <path-to-baluard-desktop>");
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

  // Settings -> Data tab -> the chip card must render (probe said capable).
  await (await browser.$('[data-testid="settings-open"]')).click();
  const dataTab = await browser.$('[data-testid="settings-tab-data"]');
  await dataTab.waitForDisplayed({ timeout: 15000 });
  await dataTab.click();
  const card = await browser.$('[data-testid="hw-guard-card"]');
  await card.waitForDisplayed({ timeout: 15000 });

  // Toggle on: the confirm dialog carries the theft promise AND the
  // chip-death warning in one body (asymmetric disclosure), and the
  // language-independent confirm-accept testid drives it.
  const toggle = await browser.$('[data-testid="hw-toggle"]');
  const labelBefore = (await toggle.getText()).trim();
  await toggle.click();
  const accept = await browser.$('[data-testid="confirm-accept"]');
  await accept.waitForDisplayed({ timeout: 15000 });
  await accept.click();

  // The card reloads hw_status; the button now offers the off label
  // (rendered strings, not i18n keys - the runner pins English).
  await browser.waitUntil(
    async () => (await toggle.getText()).trim() === "Turn off",
    { timeout: 20000, timeoutMsg: "hw toggle label never flipped to Turn off" },
  );
  const labelAfter = (await toggle.getText()).trim();

  // Toggle back off through the same dialog (danger variant, same testid).
  await toggle.click();
  const accept2 = await browser.$('[data-testid="confirm-accept"]');
  await accept2.waitForDisplayed({ timeout: 15000 });
  await accept2.click();
  await browser.waitUntil(
    async () => {
      const label = (await toggle.getText()).trim();
      return label === labelBefore;
    },
    { timeout: 20000, timeoutMsg: "hw toggle label never restored after disable" },
  );

  console.log("E2E desktop hw flow: PASS");
} finally {
  await browser.deleteSession().catch(() => {});
}
