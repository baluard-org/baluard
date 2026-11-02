// Desktop E2E flow 9: the password generator modal (the E2E harness
// Phase 3 flow coverage). Generate, switch to the passphrase tab,
// regenerate, copy (label flip), and confirm the history row lands.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node generator.mjs <path-to-baluard-desktop>");
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

const resultText = async () =>
  browser.execute(
    () => document.querySelector('[data-testid="generator-result"]')?.innerText.trim() ?? "",
  );
const buttonText = async (testid) =>
  browser.execute(
    (id) => document.querySelector(`[data-testid="${id}"]`)?.innerText.trim() ?? "",
    testid,
  );

try {
  // Unlock.
  const field = await browser.$('[data-testid="login-password"]');
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  await (await browser.$('[data-testid="login-unlock"]')).click();
  await (await browser.$('[data-testid="vault-view"]')).waitForDisplayed({ timeout: 30000 });

  // ---- Open the generator; the password result renders immediately.
  await (await browser.$('[data-testid="generator-open"]')).click();
  const result = await browser.$('[data-testid="generator-result"]');
  await result.waitForDisplayed({ timeout: 20000 });
  const v1 = await resultText();
  assert(v1.length >= 8, `generated password too short: '${v1}'`);
  console.log("PASS open");

  // ---- Passphrase tab: words joined by the default '-' separator.
  await (await browser.$('[data-testid="generator-tab-passphrase"]')).click();
  await new Promise((r) => setTimeout(r, 300));
  const v2 = await resultText();
  assert(v2.includes("-"), `passphrase lacks word separators: '${v2}'`);
  console.log("PASS passphrase");

  // ---- Regenerate produces a fresh value.
  await (await browser.$('[data-testid="generator-regenerate"]')).click();
  await new Promise((r) => setTimeout(r, 300));
  const v3 = await resultText();
  assert(v3 !== v2, "regenerate returned the same passphrase");
  assert(v3.includes("-"), `regenerated passphrase malformed: '${v3}'`);
  console.log("PASS regenerate");

  // ---- Copy flips the button label to its copied state.
  const before = await buttonText("generator-copy");
  await (await browser.$('[data-testid="generator-copy"]')).click();
  await new Promise((r) => setTimeout(r, 300));
  const after = await buttonText("generator-copy");
  assert(after !== before, `copy label did not flip ('${before}' -> '${after}')`);
  console.log("PASS copy");

  // ---- The generated value lands in the history list. The panel is a
  // drawer behind a toggle link.
  await (await browser.$('[data-testid="generator-history-toggle"]')).click();
  let history = false;
  for (let i = 0; i < 30; i++) {
    const n = await browser.execute(
      () => document.querySelectorAll('[data-testid="generator-history-row"]').length,
    );
    if (n >= 1) {
      history = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  assert(history, "no generator history row appeared");
  console.log("PASS history");
  console.log("PASS generator");
} finally {
  await browser.deleteSession();
}

function fail(m) {
  console.error(`FAIL: ${m}`);
  process.exitCode = 1;
  throw new Error(m);
}
