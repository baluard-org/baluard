// macOS smoke flow: drives the REAL release-mode app in the quickemu Sequoia
// guest through the embedded WebDriver server (tauri-plugin-wdio-webdriver,
// port 4445, SSH-forwarded). The runner (run-smoke-macos.sh) owns the app
// launch, the tunnel, and cleanup. Mirrors e2e/windows/smoke.mjs: unlock the
// seed vault, view secrets, edit and restore one entry, screenshot proof.
import { remote } from "webdriverio";
import fs from "node:fs";

const pw = process.env.BALUARD_SMOKE_PW;
assert(pw, "BALUARD_SMOKE_PW must be set by the runner");

const port = Number(process.env.BALUARD_SMOKE_WEBDRIVER_PORT || 4445);
const artifacts = process.env.BALUARD_SMOKE_ARTIFACTS || "/tmp/baluard-mac-smoke";
fs.mkdirSync(artifacts, { recursive: true });

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const browser = await remote({
  hostname: "127.0.0.1",
  port,
  capabilities: {},
  logLevel: "warn",
  waitforTimeout: 20000,
});

async function shot(name) {
  await browser.saveScreenshot(`${artifacts}/${name}`);
}

async function openDetail() {
  // No search testid exists; open the first row directly. Tolerates the
  // post-save UI either returning to the list or staying on the detail.
  const edit = await browser.$('[data-testid="detail-edit"]');
  if (!(await edit.isDisplayed().catch(() => false))) {
    const row = await browser.$('[data-testid="cipher-row"]');
    await row.waitForDisplayed({ timeout: 30000 });
    await row.click();
    await edit.waitForDisplayed({ timeout: 30000 });
  }
}

async function enterEdit() {
  const edit = await browser.$('[data-testid="detail-edit"]');
  await edit.click();
  const username = await browser.$('[data-testid="form-username"]');
  await username.waitForDisplayed({ timeout: 30000 });
  return username;
}

async function runFlow() {
  const field = await browser.$('[data-testid="login-password"]');
  await field.waitForDisplayed({ timeout: 30000 });
  await shot("01-login.png");
  await field.setValue(pw);
  const unlock = await browser.$('[data-testid="login-unlock"]');
  await unlock.click();

  const vault = await browser.$('[data-testid="vault-view"]');
  await vault.waitForDisplayed({
    timeout: 30000,
    timeoutMsg: "vault hub did not render after unlock",
  });
  await shot("02-unlocked.png");

  await openDetail();
  await shot("03-detail.png");

  // Two idempotent rounds: timestamp the username, verify it persisted,
  // restore the original, verify the restore. Reruns need no vault reset.
  await enterEdit();
  const username = await browser.$('[data-testid="form-username"]');
  const original = await username.getValue();
  assert(original && original.length > 0, "form-username came back empty");

  const stamp = `smoke-${Date.now()}`;
  await username.setValue(stamp);
  await browser.$('[data-testid="form-save"]').click();
  const form = await browser.$('[data-testid="form-username"]');
  await form.waitForDisplayed({ timeout: 30000, reverse: true, interval: 500 });

  await openDetail();
  await enterEdit();
  const after = await (await browser.$('[data-testid="form-username"]')).getValue();
  assert(after === stamp, `edit did not persist (got "${after}")`);
  await shot("04-edited-verified.png");

  const restore = await browser.$('[data-testid="form-username"]');
  await restore.setValue(original);
  await browser.$('[data-testid="form-save"]').click();
  await form.waitForDisplayed({ timeout: 30000, reverse: true, interval: 500 });

  await openDetail();
  await enterEdit();
  const restored = await (await browser.$('[data-testid="form-username"]')).getValue();
  assert(restored === original, `restore did not persist (got "${restored}")`);
  await shot("05-restored.png");

  console.log("macOS smoke: PASS");
}

try {
  await runFlow();
} catch (err) {
  try {
    await shot("99-failed.png");
    console.error(`FAIL at ${await browser.getUrl()}: ${err.message}`);
  } catch {
    console.error(`FAIL: ${err.message}`);
  }
  process.exitCode = 1;
} finally {
  await browser.deleteSession().catch(() => {});
}
