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
  if (!(await (async () => {
    try { await waitVisible(edit, { timeout: 1000 }); return true; } catch { return false; }
  })())) {
    const row = await browser.$('[data-testid="cipher-row"]');
    await waitVisible(row, { timeout: 30000 });
    await row.click();
    await waitVisible(edit, { timeout: 30000 });
  }
}

async function enterEdit() {
  const edit = await browser.$('[data-testid="detail-edit"]');
  await edit.click();
  const username = await browser.$('[data-testid="form-username"]');
  await waitVisible(username, { timeout: 30000 });
  return username;
}

// tauri-plugin-wdio's isDisplayed gates on el.offsetParent !== null, which
// WKWebView reports as null for visible elements in this layout; judge
// visibility from geometry + computed style instead.
const waitVisible = (el, { timeout = 30000, reverse = false, timeoutMsg, interval = 500 } = {}) => {
  const sel = typeof el === "string" ? el : el.selector;
  return browser.waitUntil(
    () => browser.execute((q, rev) => {
      const n = document.querySelector(q);
      if (!n) return rev; // removed from DOM: success for reverse waits only
      const r = n.getBoundingClientRect();
      const cs = getComputedStyle(n);
      const shown = r.width > 0 && r.height > 0 && cs.display !== "none" && cs.visibility !== "hidden" && Number(cs.opacity) > 0;
      return rev ? !shown : shown;
    }, sel, reverse),
    { timeout, interval, timeoutMsg: timeoutMsg || `${sel} did not ${reverse ? "disappear" : "appear"} within ${timeout}ms` }
  );
};

async function runFlow() {
  const field = await browser.$('[data-testid="login-password"]');
  await waitVisible(field, { timeout: 30000 });
  await shot("01-login.png");
  await field.setValue(pw);
  const unlock = await browser.$('[data-testid="login-unlock"]');
  await unlock.click();

  const vault = await browser.$('[data-testid="vault-view"]');
  await waitVisible(vault, {
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
  await waitVisible(form, { timeout: 30000, reverse: true, interval: 500 });

  await openDetail();
  await enterEdit();
  const after = await (await browser.$('[data-testid="form-username"]')).getValue();
  assert(after === stamp, `edit did not persist (got "${after}")`);
  await shot("04-edited-verified.png");

  const restore = await browser.$('[data-testid="form-username"]');
  await restore.setValue(original);
  await browser.$('[data-testid="form-save"]').click();
  await waitVisible(form, { timeout: 30000, reverse: true, interval: 500 });

  await openDetail();
  await enterEdit();
  const restored = await (await browser.$('[data-testid="form-username"]')).getValue();
  assert(restored === original, `restore did not persist (got "${restored}")`);
  await shot("05-restored.png");

  // Bug-2 regression: the close-to-tray toggle must actually invoke the
  // set_close_to_tray command (it used to hit a shadowed signal setter),
  // proven after the flow by the runner checking desktop-prefs.json on disk.
  await (await browser.$('[data-testid="settings-open"]')).click();
  const generalTab = await browser.$('[data-testid="settings-tab-general"]');
  await waitVisible(generalTab, { timeout: 10000 });
  await generalTab.click();
  const cttToggle = await browser.$('[data-testid="close-to-tray-toggle"]');
  await waitVisible(cttToggle, { timeout: 10000, timeoutMsg: "close-to-tray toggle did not render (mac-only section)" });
  const enabled = async () => {
    const c = await cttToggle.getAttribute("class");
    return (c || "").includes("btn-active-green");
  };
  if (await enabled()) {
    await cttToggle.click();
    await browser.waitUntil(async () => !(await enabled()), { timeout: 10000, timeoutMsg: "close-to-tray toggle never flipped to disabled" });
  }
  await shot("06-settings-general.png");
  await cttToggle.click();
  await browser.waitUntil(async () => enabled(), { timeout: 10000, timeoutMsg: "close-to-tray toggle never flipped to enabled" });
  await shot("07-close-to-tray-enabled.png");
  console.log("step: close-to-tray toggle PASS");

  // Bug-1 regression: ssh agent enable through the reprompt modal — real
  // typing, Enter to submit (the portal event-delivery fix).
  const sshToggle = await browser.$('[data-testid="ssh-agent-toggle"]');
  await waitVisible(sshToggle, { timeout: 10000 });
  const sshEnabled = async () => ((await sshToggle.getAttribute("class")) || "").includes("btn-active-green");
  if (await sshEnabled()) {
    await sshToggle.click();
    await browser.waitUntil(async () => !(await sshEnabled()), { timeout: 10000, timeoutMsg: "ssh agent toggle never flipped to disabled" });
  }
  await sshToggle.click();
  const repromptInput = await browser.$('[data-testid="reprompt-input"]');
  await waitVisible(repromptInput, { timeout: 10000, timeoutMsg: "reprompt modal did not open after ssh agent enable click" });
  await shot("08-reprompt.png");
  await repromptInput.setValue(pw);
  await browser.keys(["Return"]);
  await waitVisible(repromptInput, { timeout: 20000, reverse: true, timeoutMsg: "reprompt modal never closed after Enter" });
  await browser.waitUntil(async () => sshEnabled(), { timeout: 20000, timeoutMsg: "ssh agent toggle did not flip to enabled after reprompt" });
  await shot("09-ssh-agent-enabled.png");
  console.log("step: ssh agent enable via reprompt PASS");

  // Cancel path: the reprompt closes and no policy write lands.
  await sshToggle.click();
  await browser.waitUntil(async () => !(await sshEnabled()), { timeout: 10000, timeoutMsg: "ssh agent toggle never flipped to disabled" });
  await sshToggle.click();
  const cancelInput = await browser.$('[data-testid="reprompt-input"]');
  await waitVisible(cancelInput, { timeout: 10000, timeoutMsg: "reprompt modal did not reopen for the cancel step" });
  await cancelInput.setValue(pw);
  await (await browser.$('[data-testid="reprompt-cancel"]')).click();
  await waitVisible(cancelInput, { timeout: 10000, reverse: true, timeoutMsg: "reprompt modal never closed after cancel" });
  assert(!(await sshEnabled()), "ssh agent enabled after cancel — cancel leaked a policy write");
  await shot("10-ssh-agent-cancelled.png");
  console.log("step: reprompt cancel PASS");

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
