// Desktop E2E flow 7: trash round-trip (the E2E harness flow
// coverage). Delete an entry to trash, restore it from the Trash category,
// delete again, then Empty Trash through its confirm modal.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node trash.mjs <path-to-baluard-desktop>");
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

const NAME = "Trash Entry";

// Page-side innerText matching: the driver's getText() returns empty for
// these rows on WebKitGTK. Tag the match in-page, then select by the tag.
const rowByName = async (name) => {
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
const fill = (testid, value) =>
  browser.execute(
    (id, v) => {
      const i = document.querySelector(`[data-testid="${id}"]`);
      i.value = v;
      i.dispatchEvent(new Event("input", { bubbles: true }));
      const key = Object.keys(i).find((k) => k.startsWith("$$") && k.endsWith("input"));
      if (key && typeof i[key] === "function") i[key]({ target: i, currentTarget: i, type: "input" });
      return i.value;
    },
    testid,
    value,
  );
const confirmAccept = async () => {
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 300));
    const accept = await browser.$('[role="dialog"] [data-testid="confirm-accept"]');
    if (await accept.isDisplayed().catch(() => false)) {
      await accept.click();
      return true;
    }
  }
  return false;
};
const pickCategory = async (id) => {
  const c = await browser.$(`[data-testid="category-${id}"]`);
  await c.click();
  await new Promise((r) => setTimeout(r, 400));
};

try {
  // Unlock.
  const field = await browser.$('[data-testid="login-password"]');
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  await (await browser.$('[data-testid="login-unlock"]')).click();
  await (await browser.$('[data-testid="vault-view"]')).waitForDisplayed({ timeout: 30000 });

  // Create the victim entry.
  await (await browser.$('[data-testid="new-entry"]')).click();
  await (await browser.$('[data-testid="new-login"]')).click();
  await (await browser.$('[data-testid="form-name"]')).waitForDisplayed({ timeout: 20000 });
  await fill("form-name", NAME);
  await fill("form-username", "trash@e2e.test");
  await fill("form-password", "trash-pw-1");
  await (await browser.$('[data-testid="form-save"]')).click();
  let row = await waitRow(NAME);
  if (!row) fail(`created entry '${NAME}' never appeared`);

  // Delete to trash through the detail view.
  await row.click();
  await (await browser.$('[data-testid="detail-delete"]')).waitForDisplayed({ timeout: 20000 });
  await (await browser.$('[data-testid="detail-delete"]')).click();
  if (!(await confirmAccept())) fail("delete confirm never appeared");
  for (let i = 0; i < 40; i++) {
    if (!(await rowByName(NAME))) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  assert(!(await rowByName(NAME)), "deleted entry still listed outside trash");
  console.log("PASS delete-to-trash");

  // The Trash category lists it; restore from the detail view.
  await pickCategory("trash");
  row = await waitRow(NAME);
  if (!row) fail(`trashed entry '${NAME}' not listed in the Trash category`);
  await row.click();
  const restore = await browser.$('[data-testid="detail-restore"]');
  await restore.waitForDisplayed({ timeout: 20000 });
  await restore.click();
  await pickCategory("allItems");
  row = await waitRow(NAME);
  if (!row) fail(`restored entry '${NAME}' missing after restore`);
  console.log("PASS restore");

  // Delete again, then Empty Trash.
  await row.click();
  await (await browser.$('[data-testid="detail-delete"]')).waitForDisplayed({ timeout: 20000 });
  await (await browser.$('[data-testid="detail-delete"]')).click();
  if (!(await confirmAccept())) fail("second delete confirm never appeared");
  await pickCategory("trash");
  row = await waitRow(NAME);
  if (!row) fail(`entry '${NAME}' missing in trash before Empty Trash`);
  const emptyBtn = await browser.$('[data-testid="empty-trash"]');
  await emptyBtn.waitForDisplayed({ timeout: 20000 });
  await emptyBtn.click();
  if (!(await confirmAccept())) fail("empty-trash confirm never appeared");
  for (let i = 0; i < 40; i++) {
    if (!(await waitRow(NAME, 300))) break;
  }
  assert(!(await rowByName(NAME)), "trash still lists the entry after Empty Trash");
  console.log("PASS empty-trash");
  console.log("PASS trash");
} finally {
  await browser.deleteSession();
}

function fail(m) {
  console.error(`FAIL: ${m}`);
  process.exitCode = 1;
  throw new Error(m);
}
