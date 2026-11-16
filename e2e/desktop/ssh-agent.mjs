// Desktop E2E: SSH agent enable through the reprompt modal — the regression
// flow for the ConsolePanel portal delegation fix. Drives only real user
// events (setValue/keys/click); the DEV submit hook is gone from the source.
//   PASS unlock
//   PASS unlock
//   PASS reprompt: Enter submits and the SSH agent toggle flips to Enabled
//   PASS ssh agent disable does not reopen the reprompt
//   PASS reprompt: cancel closes the dialog and the toggle stays disabled
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node ssh-agent.mjs <path-to-baluard-desktop>");
const pw = process.env.BALUARD_E2E_PW;
assert(pw, "BALUARD_E2E_PW must be set by the runner");

const browser = await remote({
  hostname: "127.0.0.1",
  port: 4444,
  capabilities: { "tauri:options": { application: app } },
  logLevel: "warn",
  waitforTimeout: 20000,
});

const q = (testid) => browser.$(`[data-testid="${testid}"]`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shown = async (testid) => q(testid).isDisplayed().catch(() => false);

// Info toasts (bottom-right, pointer-events-auto) can cover the toggle right
// after the settings pane mounts; retry the click while the toast dies.
async function clickWithRetry(el, attempts = 5) {
  for (let a = 1; a <= attempts; a++) {
    try {
      await el.click();
      return;
    } catch (e) {
      if (!/intercept|not interactable/i.test(String(e.message))) throw e;
      await sleep(1500);
    }
  }
  throw new Error("click kept getting intercepted");
}

try {
  await (await q("login-password")).setValue(pw);
  await (await q("login-unlock")).click();
  await (await q("vault-view")).waitForDisplayed({ timeout: 30000 });
  console.log("PASS unlock");

  await (await q("settings-open")).click();
  await (await q("settings-tab-general")).click();
  const toggle = await q("ssh-agent-toggle");
  await toggle.waitForDisplayed({ timeout: 10000 });
  // WebKit WebDriver intermittently returns "" for getText on this button,
  // so state is read from the enabled class, not the label.
  const enabled = async () => (await toggle.getAttribute("class")).includes("btn-active-green");
  console.log("toggle initially enabled:", await enabled());

  // ── Enable path: reprompt opens, Enter submits, toggle flips.
  await clickWithRetry(toggle);
  const input = await q("reprompt-input");
  await input.waitForDisplayed({ timeout: 10000 });
  await input.setValue(pw);
  await browser.keys(["Return"]);
  await input.waitForDisplayed({ timeout: 15000, reverse: true });
  await browser.waitUntil(async () => enabled(), {
    timeout: 15000, interval: 500, timeoutMsg: "toggle never flipped to Enabled",
  });
  console.log("PASS reprompt: Enter submits and the SSH agent toggle flips to Enabled");

  // ── Disable path: no reprompt on the way down.
  await clickWithRetry(toggle);
  await browser.waitUntil(async () => !(await enabled()), {
    timeout: 15000, interval: 500, timeoutMsg: "toggle never flipped back to Disabled",
  });
  assert(!(await shown("reprompt-input")), "reprompt must not open on disable");
  console.log("PASS ssh agent disable does not reopen the reprompt");

  // ── Cancel path: reopen, type, cancel closes and the toggle stays disabled.
  await clickWithRetry(toggle);
  const cancelInput = await q("reprompt-input");
  await cancelInput.waitForDisplayed({ timeout: 10000 });
  await cancelInput.setValue(pw);
  await (await q("reprompt-cancel")).click();
  await cancelInput.waitForDisplayed({ timeout: 10000, reverse: true });
  if (await enabled()) throw new Error("ssh agent enabled after cancel — cancel leaked a policy write");
  console.log("PASS reprompt: cancel closes the dialog and the toggle stays disabled");

  console.log("SSH-AGENT FLOW DONE");
} catch (e) {
  console.log("SSH-AGENT FLOW FAILED:", String(e.message || e).split("\n")[0]);
  process.exitCode = 1;
} finally {
  await browser.deleteSession();
}
