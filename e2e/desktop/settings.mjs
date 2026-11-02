// Desktop E2E flow 5: settings modals (the E2E harness flow coverage
// beyond CRUD). Drives the encrypted-backup master-password reprompt gate
// and the contacts tab's own verification code.
//
// Boundary: the encrypted-backup passphrase dialog behind the gate is not
// drivable under this harness — its in-dialog daemon call never resolves
// when automation drives the reprompt (verified: the same route resolves
// fine from a bare page probe), so the flow asserts the gate and the
// FocusTrap Escape close. The dialog itself carries manual coverage.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node settings.mjs <path-to-baluard-desktop>");
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

const q = (testid) => browser.$(`[data-testid="${testid}"]`);

try {
  // Unlock.
  const field = await q("login-password");
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  await (await q("login-unlock")).click();
  await (await q("vault-view")).waitForDisplayed({ timeout: 30000 });

  await (await q("settings-open")).click();
  await (await q("settings-tab-data")).click();
  await (await q("backup-encrypted")).waitForDisplayed({ timeout: 20000 });

  // ---- Encrypted backup: the master-password reprompt gate comes first
  // (vault.reprompt_verify really checks the password server-side).
  await (await q("backup-encrypted")).click();
  await (await q("reprompt-input")).waitForDisplayed({ timeout: 20000 });
  console.log("PASS backup reprompt gate");

  // Escape closes through the ConsolePanel FocusTrap.
  await browser.keys(["Escape"]);
  for (let i = 0; i < 30; i++) {
    if (!(await q("reprompt-input").isDisplayed().catch(() => false))) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  assert(
    !(await q("reprompt-input").isDisplayed().catch(() => false)),
    "reprompt modal never closed on Escape",
  );
  console.log("PASS reprompt escape");

  // ---- Contacts tab: the vault's own verification code renders.
  await (await q("settings-tab-contacts")).click();
  const code = await q("contacts-my-code");
  await code.waitForDisplayed({ timeout: 20000 });
  const codeText = await browser.execute(() => {
    const el = document.querySelector('[data-testid="contacts-my-code"]');
    return el ? el.innerText : "";
  });
  assert(/^[0-9a-f]{16}$/.test(codeText.trim()), `verification code malformed: '${codeText}'`);
  console.log("PASS contacts code");

  console.log("PASS settings");
} finally {
  await browser.deleteSession();
}

function fail(m) {
  console.error(`FAIL: ${m}`);
  process.exitCode = 1;
  throw new Error(m);
}
