// Desktop E2E flow 8: folders and tags (docs/e2e-testing.md Phase 3 flow
// coverage). Create a sidebar folder, file a new entry into it, then tag
// the entry from the edit form and exercise tag filtering and deletion.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node organize.mjs <path-to-baluard-desktop>");
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

const NAME = "Org Entry";
const FOLDER = "Work";
const TAG = "team";

const byTestidText = async (testid, text) => {
  const hit = await browser.execute(
    (id, n) => {
      const els = Array.from(document.querySelectorAll(`[data-testid="${id}"]`));
      els.forEach((r) => r.removeAttribute("data-crud-match"));
      const el = els.find((r) => r.innerText.includes(n));
      if (!el) return false;
      el.setAttribute("data-crud-match", "1");
      return true;
    },
    testid,
    text,
  );
  if (!hit) return null;
  return browser.$(`[data-testid="${testid}"][data-crud-match="1"]`);
};
const waitTestidText = async (testid, text, timeoutMs = 20000) => {
  for (let i = 0; i < timeoutMs / 300; i++) {
    const el = await byTestidText(testid, text);
    if (el) return el;
    await new Promise((r) => setTimeout(r, 300));
  }
  return null;
};
const rowByName = (name) => waitTestidText("cipher-row", name);
const waitRow = (name, timeoutMs = 20000) => waitTestidText("cipher-row", name, timeoutMs);
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
// Solid delegates keydown, so a synthetic event can miss the delegation
// root: dispatch it AND invoke the emitted $$keydown expando directly.
const pressEnter = (testid) =>
  browser.execute((id) => {
    const i = document.querySelector(`[data-testid="${id}"]`);
    const ev = { key: "Enter", target: i, currentTarget: i, preventDefault() {} };
    i.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    const key = Object.keys(i).find((k) => k.startsWith("$$") && k.endsWith("keydown"));
    if (key && typeof i[key] === "function") i[key](ev);
    return i.value;
  }, testid);
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

try {
  // Unlock.
  const field = await browser.$('[data-testid="login-password"]');
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  await (await browser.$('[data-testid="login-unlock"]')).click();
  await (await browser.$('[data-testid="vault-view"]')).waitForDisplayed({ timeout: 30000 });

  // ---- Folder: create via the sidebar, then file a new entry into it.
  await (await browser.$('[data-testid="new-folder"]')).click();
  const folderInput = await browser.$('[data-testid="new-folder-input"]');
  await folderInput.waitForDisplayed({ timeout: 20000 });
  await fill("new-folder-input", FOLDER);
  await pressEnter("new-folder-input");
  const folderRow = await waitTestidText("folder-row", FOLDER);
  if (!folderRow) {
    const body = await browser.execute(
      () => document.body.innerText.slice(0, 300),
    );
    fail(`folder '${FOLDER}' never appeared. body=${body}`);
  }
  console.log("PASS folder-create");

  // File the new entry into the selected folder.
  await folderRow.click();
  await new Promise((r) => setTimeout(r, 300));
  await (await browser.$('[data-testid="new-entry"]')).click();
  await (await browser.$('[data-testid="new-login"]')).click();
  await (await browser.$('[data-testid="form-name"]')).waitForDisplayed({ timeout: 20000 });
  await fill("form-name", NAME);
  await fill("form-username", "org@e2e.test");
  await (await browser.$('[data-testid="form-save"]')).click();
  let row = await rowByName(NAME);
  if (!row) fail(`entry '${NAME}' created in folder '${FOLDER}' never appeared`);
  console.log("PASS folder-file");

  // ---- Tag: add from the edit form, filter by the pill, then delete it.
  await (await browser.$('[data-testid="category-allItems"]')).click();
  await new Promise((r) => setTimeout(r, 300));
  row = await rowByName(NAME);
  await row.click();
  await (await browser.$('[data-testid="detail-edit"]')).waitForDisplayed({ timeout: 20000 });
  await (await browser.$('[data-testid="detail-edit"]')).click();
  const tags = await browser.$('[data-testid="form-tags"]');
  await tags.waitForDisplayed({ timeout: 20000 });
  await fill("form-tags", TAG);
  const cleared = await pressEnter("form-tags");
  if (cleared !== "") {
    // The Enter path did not commit; the blur handler commits non-empty input.
    await browser.execute((id) => {
      const i = document.querySelector(`[data-testid="${id}"]`);
      i.dispatchEvent(new Event("blur"));
      const key = Object.keys(i).find((k) => k.startsWith("$$") && k.endsWith("blur"));
      if (key && typeof i[key] === "function") i[key]({ target: i, currentTarget: i, type: "blur" });
    }, "form-tags");
  }
  await (await browser.$('[data-testid="form-save"]')).click();
  if (!(await waitRow(NAME))) fail(`entry '${NAME}' missing after save with tag`);
  const pill = await waitTestidText("tag-pill", TAG);
  if (!pill) {
    const pills = await browser.execute(
      () => Array.from(document.querySelectorAll('[data-testid="tag-pill"]')).map((p) => p.innerText.trim()).join(","),
    );
    fail(`tag pill '${TAG}' never appeared. pills=[${pills}]`);
  }
  console.log("PASS tag-add");

  await pill.click();
  await new Promise((r) => setTimeout(r, 400));
  row = await rowByName(NAME);
  if (!row) fail(`entry '${NAME}' not listed under tag filter '${TAG}'`);
  console.log("PASS tag-filter");

  const del = await browser.$('[data-testid="tag-delete"]');
  await del.waitForDisplayed({ timeout: 20000 });
  await del.click();
  if (!(await confirmAccept())) fail("delete-tag confirm never appeared");
  let pillGone = false;
  for (let i = 0; i < 40; i++) {
    if (!(await byTestidText("tag-pill", TAG))) {
      pillGone = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  assert(pillGone, "tag pill survived its deletion");
  console.log("PASS tag-delete");
  console.log("PASS organize");
} finally {
  await browser.deleteSession();
}

function fail(m) {
  console.error(`FAIL: ${m}`);
  process.exitCode = 1;
  throw new Error(m);
}
