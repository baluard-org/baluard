// Windows desktop smoke flow: drives the REAL release-mode app in the guest
// VM over its WebView2 CDP port (baked into the smoke installer build by
// tauri.smoke.conf.json, never in the shipped artifact). Same data-testid
// selectors as the Linux desktop flows; pass/fail from DOM asserts,
// screenshots are artifacts. The runner owns SSH, the CDP tunnel, cleanup.
import { chromium } from "playwright";
import assert from "node:assert";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const CDP = process.env.BALUARD_SMOKE_CDP || "9222";
const ARTIFACTS = process.env.BALUARD_SMOKE_ARTIFACTS;
const pw = process.env.BALUARD_SMOKE_PW;
assert(ARTIFACTS, "BALUARD_SMOKE_ARTIFACTS must be set by the runner");
assert(pw, "BALUARD_SMOKE_PW must be set");
mkdirSync(ARTIFACTS, { recursive: true });

const shot = (page, name) =>
  page.screenshot({ path: join(ARTIFACTS, name) }).catch(() => {});

const browser = await chromium.connectOverCDP(`http://127.0.0.1:${CDP}`);

// The Tauri window is one page among the CDP targets (and may appear
// shortly after connect), so re-list targets until one carries the login UI.
let page;
for (let waited = 0; waited < 30000 && !page; waited += 1000) {
  for (const ctx of browser.contexts()) {
    for (const p of ctx.pages()) {
      const found = await p
        .locator('[data-testid="login-password"]')
        .waitFor({ state: "visible", timeout: 2000 })
        .then(() => true)
        .catch(() => false);
      if (found) { page = p; break; }
    }
    if (page) break;
  }
  if (!page) await new Promise((r) => setTimeout(r, 1000));
}
assert(page, "no CDP page exposed the Baluard login UI within 30s");
await shot(page, "01-login.png");

let browser_ref = browser;
const failShot = async () => {
  if (!page.isClosed?.()) await shot(page, "99-failed.png");
  console.error(`FAIL: page url = ${page.url()}`);
};
try {
  await runFlow(page);
} catch (err) {
  await failShot().catch(() => {});
  throw err;
} finally {
  await browser_ref.close().catch(() => {});
}

async function runFlow(page) {
// Unlock: fill + submit, then wait out the Argon2id KDF on the hub marker.
await page.locator('[data-testid="login-password"]').fill(pw);
await page.locator('[data-testid="login-unlock"]').click();
await page
  .locator('[data-testid="vault-view"]')
  .waitFor({ state: "visible", timeout: 30000, timeoutMsg: "vault hub did not render after unlock" });
await shot(page, "02-unlocked.png");
console.log("step: unlock PASS");

// After a save the UI either stays on the detail view or returns to the
// list; both paths end with detail-edit visible.
const openDetail = async () => {
  const detail = page.locator('[data-testid="detail-edit"]');
  if (await detail.isVisible().catch(() => false)) return;
  await page.locator('[data-testid="cipher-row"]').first().click();
  await detail.waitFor({ state: "visible", timeout: 20000, timeoutMsg: "entry detail did not open" });
};
const enterEdit = async () => {
  await openDetail();
  await page.locator('[data-testid="detail-edit"]').click();
  await page
    .locator('[data-testid="form-username"]')
    .waitFor({ state: "visible", timeout: 20000, timeoutMsg: "edit form did not open" });
};

await openDetail();
await shot(page, "03-detail.png");
await enterEdit();
const username = page.locator('[data-testid="form-username"]');
const original = await username.inputValue();

const editRound = async (value) => {
  await enterEdit();
  await username.fill(value);
  await page.locator('[data-testid="form-save"]').click();
  await username.waitFor({ state: "hidden", timeout: 20000, timeoutMsg: "edit form never closed after save" });
};

// Round 1 edits forward and verifies what persisted; round 2 restores the
// seed value, so reruns need no reset.
const edited = `smoke-${Date.now()}`;
await editRound(edited);
await enterEdit();
assert.strictEqual(await username.inputValue(), edited, "edited username did not persist after save");
await shot(page, "04-edited-verified.png");
console.log(`step: edit+save PASS (username -> ${edited})`);

await editRound(original);
await enterEdit();
assert.strictEqual(await username.inputValue(), original, "username restore did not persist");
await shot(page, "05-restored.png");
console.log("step: restore PASS");

console.log("WINDOWS SMOKE PASS");
}

// browser.close() moved to the finally block above
