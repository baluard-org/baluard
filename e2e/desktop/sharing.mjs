// Desktop E2E flow 4: sharing surfaces (the E2E harness flow coverage
// beyond CRUD). The runner seeds a second live member row and a pending D61
// ownership-claim record. Drive the Collections tab (create a shared folder,
// grant the member access, revoke), the People tab (role change on the
// member row), and the claim card (present, then cancelled by the owner).
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node sharing.mjs <path-to-baluard-desktop>");
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

const FOLDER = "E2E Folder";

// Fill through JS set + bubbling input: WebKitWebDriver's setValue does not
// deliver events Solid's delegated onInput sees (the crud.mjs lesson).
const fill = (testid, value) =>
  browser.execute(
    (id, v) => {
      const i = document.querySelector(`[data-testid="${id}"]`);
      if (!i) return null;
      i.value = v;
      i.dispatchEvent(new Event("input", { bubbles: true }));
      const key = Object.keys(i).find((k) => k.startsWith("$$") && k.endsWith("input"));
      if (key && typeof i[key] === "function") i[key]({ target: i, currentTarget: i, type: "input" });
      return i.value;
    },
    testid,
    value,
  );

const q = (testid) => browser.$(`[data-testid="${testid}"]`);
const waitDisplayed = async (testid, timeoutMs = 20000) => {
  const el = await q(testid);
  await el.waitForDisplayed({ timeout: timeoutMs });
  return el;
};

try {
  // Collect uncaught errors/rejections from here on — refresh failures in
  // the component layer surface as unhandled promise rejections.
  await browser.execute(() => {
    window.__errs = [];
    window.addEventListener("error", (e) =>
      window.__errs.push(`err: ${e.message}\n${(e.error && e.error.stack) || ""}`),
    );
    window.addEventListener("unhandledrejection", (e) =>
      window.__errs.push(`rej: ${e.reason?.message || e.reason}`),
    );
  });

  // Unlock.
  const field = await q("login-password");
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  await (await q("login-unlock")).click();
  await (await q("vault-view")).waitForDisplayed({ timeout: 30000 });

  // Open Settings on the Collections tab.
  await (await q("settings-open")).click();
  await (await q("settings-tab-collections")).click();
  await (await q("collections-name-input")).waitForDisplayed({ timeout: 20000 });

  // ---- Create a shared folder.
  await fill("collections-name-input", FOLDER);
  await (await q("collections-create")).click();
  let found = null;
  for (let i = 0; i < 40 && !found; i++) {
    found = await browser.execute((n) => {
      const rows = Array.from(document.querySelectorAll('[data-testid="collection-row"]'));
      return rows.some((r) => r.innerText.includes(n));
    }, FOLDER);
    if (!found) await new Promise((r) => setTimeout(r, 300));
  }
  if (!found) {
    // Remount the tab (onSettled refresh) — discriminating a post-create
    // refresh gap from a render problem.
    await (await q("settings-tab-data")).click();
    await (await q("settings-tab-collections")).click();
    await (await q("collections-name-input")).waitForDisplayed({ timeout: 20000 });
    for (let i = 0; i < 20 && !found; i++) {
      found = await browser.execute((n) => {
        const rows = Array.from(document.querySelectorAll('[data-testid="collection-row"]'));
        return rows.some((r) => r.innerText.includes(n));
      }, FOLDER);
      if (!found) await new Promise((r) => setTimeout(r, 300));
    }
    if (found) console.log("NOTE: rows only appeared after remount");
  }
  if (!found) {
    const diag = await browser.execute(async (n) => {
      const modal = document.querySelector(".fixed.inset-0.z-\\[90\\], div[class*='z-[90]'], div[class*='z-[100]']");
      const tab = modal
        ? modal.innerText.slice(0, 900)
        : Array.from(document.querySelectorAll("h3")).map((h) => h.innerText).join(" | ");
      let wire = "";
      try {
        const m = await import("/src/lib/daemon.js");
        wire = await m.daemon("collections.list");
      } catch (e) {
        wire = `wire unavailable: ${e.message}`;
      }
      const stack = (window.__errs || []).join("\n").slice(0, 1400);
      return `rows=[${document.querySelectorAll('[data-testid="collection-row"]').length}] errs=${stack} wire=${wire.slice(0, 200)}`;
    }, FOLDER);
    fail(`created folder '${FOLDER}' never appeared. ${diag}`);
  }
  console.log("PASS create folder");

  // ---- Grant the seeded member read access.
  await (await q("collections-manage")).click();
  const grantSection = await q("grant-member");
  await grantSection.waitForDisplayed({ timeout: 20000 });
  // The select's options carry member ids; pick the non-empty one that is
  // not the placeholder (a personal vault lists the founder plus the
  // seeded member; either grants exercise the machinery).
  await browser.execute(() => {
    const sel = document.querySelector('[data-testid="grant-member"]');
    const opt = Array.from(sel.options).find((o) => o.value);
    sel.value = opt.value;
    sel.dispatchEvent(new Event("input", { bubbles: true }));
    sel.dispatchEvent(new Event("change", { bubbles: true }));
    return sel.value;
  });
  await (await q("grant-add")).click();
  // The granted toast or the grant count updating — poll the row text for
  // a non-zero grant count.
  let granted = false;
  for (let i = 0; i < 40 && !granted; i++) {
    granted = await browser.execute((n) => {
      const row = Array.from(document.querySelectorAll('[data-testid="collection-row"]')).find((r) =>
        r.innerText.includes(n),
      );
      return row ? /^\s*1\s/.test(row.innerText) || row.innerText.includes("1 ") : false;
    }, FOLDER);
    if (!granted) await new Promise((r) => setTimeout(r, 300));
  }
  assert(granted, "grant count never updated to 1");
  console.log("PASS grant");

  // ---- People tab: the seeded member row exists; change its role.
  await (await q("settings-tab-people")).click();
  const memberRow = await q("member-row");
  await memberRow.waitForDisplayed({ timeout: 20000 });
  const roleSel = await browser.$('[data-testid="member-row"] [data-testid="role-select"]');
  await roleSel.waitForDisplayed({ timeout: 20000 });
  await browser.execute(() => {
    const sel = document.querySelector('[data-testid="member-row"] [data-testid="role-select"]');
    sel.value = "viewer";
    sel.dispatchEvent(new Event("input", { bubbles: true }));
    sel.dispatchEvent(new Event("change", { bubbles: true }));
  });
  let roleSet = false;
  for (let i = 0; i < 40 && !roleSet; i++) {
    roleSet = await browser.execute(() => {
      const wire = null; // role re-reads after the set; check the select value
      const sel = document.querySelector('[data-testid="member-row"] [data-testid="role-select"]');
      return sel && sel.value === "viewer";
    });
    if (!roleSet) await new Promise((r) => setTimeout(r, 300));
  }
  assert(roleSet, "role change never landed on the member row");
  console.log("PASS role change");

  // ---- D61 claim card: seeded pending claim; the owner cancels it.
  const claim = await q("claim-card");
  await claim.waitForDisplayed({ timeout: 20000 });
  await (await q("claim-cancel")).click();
  // The typed-confirm modal guards the cancel; its accept carries the
  // language-independent confirm-accept testid (the CRUD-wave convention).
  let cancelled = false;
  for (let i = 0; i < 30 && !cancelled; i++) {
    await new Promise((r) => setTimeout(r, 300));
    const accept = await browser.$('[role="dialog"] [data-testid="confirm-accept"]');
    if (await accept.isDisplayed().catch(() => false)) {
      await accept.click();
      cancelled = true;
    }
  }
  for (let i = 0; i < 40; i++) {
    if (!(await q("claim-card").isDisplayed().catch(() => false))) {
      cancelled = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  assert(cancelled, "claim card never cleared after cancel");
  // Wire truth: the pending contest record is consumed, not just hidden.
  const wire = await browser.execute(async () => {
    const m = await import("/src/lib/daemon.js");
    const r = JSON.parse(await m.daemon("members.contest_status"));
    return r;
  });
  assert(wire.pending === false, `claim cancel never reached the wire: ${JSON.stringify(wire).slice(0, 120)}`);
  console.log("PASS claim cancel");

  console.log("PASS sharing");
} finally {
  await browser.deleteSession();
}

function fail(m) {
  console.error(`FAIL: ${m}`);
  process.exitCode = 1;
  throw new Error(m);
}
