// Desktop E2E flow: search bar alignment probe.
// Unlocks the seeded vault, types a query so the clear button mounts,
// then measures the search icon, input, and clear button relative to
// the search bar container. Asserts the classic absolute-overlay
// geometry: icon pinned left, clear button pinned right, all three
// vertically inside the input row. Exits non-zero on any misalignment.
import { remote } from "webdriverio";
import assert from "node:assert";

const app = process.argv[2];
assert(app, "usage: node search-align.mjs <path-to-baluard-desktop>");
const pw = process.env.BALUARD_E2E_PW;
assert(pw, "BALUARD_E2E_PW must be set by the runner");

const app2 = await remote({
  hostname: "127.0.0.1",
  port: 4444,
  capabilities: {
    "tauri:options": { application: app },
  },
  logLevel: "warn",
  waitforTimeout: 20000,
});

try {
  const field = await app2.$('[data-testid="login-password"]');
  await field.waitForDisplayed({ timeout: 30000 });
  await field.setValue(pw);
  const unlock = await app2.$('[data-testid="login-unlock"]');
  await unlock.click();

  const vault = await app2.$('[data-testid="vault-view"]');
  await vault.waitForDisplayed({ timeout: 30000 });

  const input = await app2.$('input[placeholder="Search vault..."]');
  await input.waitForDisplayed({ timeout: 15000 });
  await input.setValue("svalbard");

  // The clear button mounts reactively once a query exists.
  const clear = await app2.$('[data-testid="vault-search"] button');
  await clear.waitForDisplayed({ timeout: 15000 });
  await app2.pause(500);

  const m = await app2.execute(() => {
    const cont = document.querySelector('[data-testid="vault-search"]');
    const icon = cont.querySelector("span > svg");
    const input = cont.querySelector("input");
    const btn = cont.querySelector("button");
    const r = (el) => {
      const b = el.getBoundingClientRect();
      return { x: b.x, y: b.y, w: b.width, h: b.height };
    };
    const cs = getComputedStyle(btn);
    const ics = getComputedStyle(icon);
    return {
      container: r(cont), icon: r(icon), input: r(input), button: r(btn),
      btnPosition: cs.position, btnInsetBlock: cs.getPropertyValue("inset-block"),
      iconPosition: ics.position,
      ua: navigator.userAgent,
    };
  });

  const c = m.container, i = m.icon, n = m.input, b = m.button;
  const yc = (el) => el.y + el.h / 2;
  const report = JSON.stringify(m, null, 2);
  console.log(report);

  // The bug this flow guards: the icon/button must not depend on abspos
  // overlay math (WebKitGTK mis-lays it on some Linux stacks).
  assert.strictEqual(m.btnPosition, "static", `clear button must be static flex child, got ${m.btnPosition}`);
  assert.strictEqual(m.iconPosition, "static", `icon must be static flex child, got ${m.iconPosition}`);
  // Icon: after the 14px lead padding, vertically centered on the row.
  assert.ok(Math.abs(i.x - c.x - 14) < 4, `icon x ${i.x} not at container left padding (container x ${c.x})`);
  assert.ok(Math.abs(yc(i) - yc(n)) < 6, `icon center ${yc(i)} not aligned with input center ${yc(n)}`);
  // Clear button: right-most child, vertically centered.
  assert.ok(Math.abs(b.x + b.w - (c.x + c.w)) < 8, `clear button right edge ${b.x + b.w} not at container right ${c.x + c.w}`);
  assert.ok(Math.abs(yc(b) - yc(n)) < 6, `clear button center ${yc(b)} not aligned with input center ${yc(n)}`);
  // Overlay invariant: button box sits INSIDE the container (not flowed below).
  assert.ok(b.y >= c.y - 1 && b.y + b.h <= c.y + c.h + 1, `clear button ${b.y}..${b.y + b.h} escaped container ${c.y}..${c.y + c.h}`);

  const shot = process.env.BALUARD_E2E_SHOT;
  if (shot) {
    await app2.saveScreenshot(shot);
    console.log(`screenshot: ${shot}`);
  }
  console.log("E2E desktop search-align flow: PASS");
} finally {
  await app2.deleteSession().catch(() => {});
}
