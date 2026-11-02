// Desktop E2E flow 3: entry CRUD through the real UI (the E2E harness
// Phase 3 flow coverage). Unlock the seeded vault, add a login through the
// New-entry menu, edit its name, then delete it through the confirm modal.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node crud.mjs <path-to-baluard-desktop>");
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

const NAME = "CRUD Entry";
const NAME2 = "CRUD Entry Renamed";

// Rows carry the entry name in their text; return the matching element.
// Page-side innerText: the driver's getText() returns empty for these rows
// on WebKitGTK.
const rowByName = async (name) => {
  // Tag the match in-page, then select by the tag: an index resolved across
  // two driver round-trips can point at a different row after a re-render.
  const hit = await browser.execute((n) => {
    const rows = Array.from(document.querySelectorAll('[data-testid="cipher-row"]'));
    rows.forEach((r) => r.removeAttribute("data-crud-match"));
    const row = rows.find((r) => r.innerText.includes(n));
    if (!row) return false;
    row.setAttribute("data-crud-match", "1");
    return true;
  }, name);
  if (!hit) return null;
  return browser.$('[data-testid="cipher-row"][data-crud-match="1"]');
};
const waitRow = async (name, timeoutMs = 20000) => {
  for (let i = 0; i < timeoutMs / 300; i++) {
    const row = await rowByName(name);
    if (row) return row;
    await new Promise((r) => setTimeout(r, 300));
  }
  return null;
};

try {
  // Unlock.
  const field = await browser.$('[data-testid="login-password"]');
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  await (await browser.$('[data-testid="login-unlock"]')).click();
  const vault = await browser.$('[data-testid="vault-view"]');
  await vault.waitForDisplayed({ timeout: 30000 });

  // ---- Create: New -> Logins -> fill -> Save. Form inputs bind Solid's
  // delegated onInput; WebKitWebDriver's setValue does not deliver events
  // Solid sees, so fill via JS set + bubbling input (the cdp-popup pattern).
  await (await browser.$('[data-testid="new-entry"]')).click();
  await (await browser.$('[data-testid="new-login"]')).click();
  await (await browser.$('[data-testid="form-name"]')).waitForDisplayed({ timeout: 20000 });
  const fill = (testid, value) =>
    browser.execute(
      (id, v) => {
        const i = document.querySelector(`[data-testid="${id}"]`);
        i.value = v;
        i.dispatchEvent(new Event("input", { bubbles: true }));
        // Solid's delegated onInput lives in an expando the bundler emits
        // ($$input); a synthetic event can miss the delegation root, so
        // invoke the handler directly as a fallback.
        const key = Object.keys(i).find((k) => k.startsWith("$$") && k.endsWith("input"));
        if (key && typeof i[key] === "function") i[key]({ target: i, currentTarget: i, type: "input" });
        return i.value;
      },
      testid,
      value,
    );
  await fill("form-name", NAME);
  await fill("form-username", "crud@e2e.test");
  await fill("form-password", "crud-pw-1");
  const readback = await browser.execute(() => ({
    name: document.querySelector('[data-testid="form-name"]')?.value,
    user: document.querySelector('[data-testid="form-username"]')?.value,
    pw: document.querySelector('[data-testid="form-password"]')?.value,
    counts: {
      name: document.querySelectorAll('[data-testid="form-name"]').length,
      rows: document.querySelectorAll('[data-testid="cipher-row"]').length,
      visibleName: Array.from(document.querySelectorAll('[data-testid="form-name"]')).filter(
        (i) => i.offsetParent !== null,
      ).length,
    },
  }));
  console.log(`form readback: ${JSON.stringify(readback)}`);
  await (await browser.$('[data-testid="form-save"]')).click();
  const row = await waitRow(NAME);
  if (!row) {
    const wire = await browser.execute(async () => {
      try {
        const m = await import("/src/lib/daemon.js");
        const resp = await m.daemon("vault.list");
        const j = JSON.parse(resp);
        return (j.ciphers || []).map((c) => `${c.name}<${c.id}>`).join(" ; ");
      } catch (e) {
        return `wire probe unavailable: ${e.message}`;
      }
    });
    fail(`created entry '${NAME}' never appeared. wire=[${wire}]`);
  }
  console.log("PASS create");

  // ---- Read: open the detail view.
  await row.click();
  const detail = await browser.$('[data-testid="detail-edit"]');
  await detail.waitForDisplayed({ timeout: 20000 });
  console.log("PASS open");

  // ---- Update: edit the name, save, assert the renamed row.
  await detail.click();
  const nameField = await browser.$('[data-testid="form-name"]');
  await nameField.waitForDisplayed({ timeout: 20000 });
  await fill("form-name", NAME2);
  await (await browser.$('[data-testid="form-save"]')).click();
  const renamed = await waitRow(NAME2);
  if (!renamed) {
    const body = await browser.$("body");
    fail(`renamed entry '${NAME2}' never appeared. Body: ${(await body.getText()).slice(0, 400)}`);
  }
  console.log("PASS update");

  // ---- Delete: open the detail, delete, confirm in the modal.
  await renamed.click();
  await (await browser.$('[data-testid="detail-edit"]')).waitForDisplayed({ timeout: 20000 });
  await (await browser.$('[data-testid="detail-delete"]')).click();
  // The confirm modal's accept button carries the Delete label; poll for the
  // modal rather than racing its render.
  let confirmed = false;
  for (let i = 0; i < 30 && !confirmed; i++) {
    await new Promise((r) => setTimeout(r, 300));
    const accept = await browser.$('[role="dialog"] [data-testid="confirm-accept"]');
    if (await accept.isDisplayed().catch(() => false)) {
      await accept.click();
      confirmed = true;
    }
  }
  if (!confirmed) {
    const diag = await browser.execute(() => {
      const d = document.querySelector('[role="dialog"]');
      return d
        ? `dialog-ok buttons=[${Array.from(d.querySelectorAll("button")).map((b) => `${b.textContent.trim()}${b.dataset.testid ? "#" + b.dataset.testid : ""}`).join(", ")}]`
        : `no-dialog body=${document.body.innerText.slice(0, 150)}`;
    });
    fail(`confirm modal's accept button never appeared. ${diag}`);
  }
  for (let i = 0; i < 40; i++) {
    if (!(await rowByName(NAME2))) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  assert(!(await rowByName(NAME2)), `deleted entry '${NAME2}' still listed`);
  console.log("PASS delete");
  console.log("PASS crud");
} finally {
  await browser.deleteSession();
}

function fail(m) {
  console.error(`FAIL: ${m}`);
  process.exitCode = 1;
  throw new Error(m);
}
