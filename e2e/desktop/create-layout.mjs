// Desktop create-vault layout: every control must remain reachable when the
// card is taller than the window, without clipping the card header at scrollTop 0.
import { remote } from "webdriverio";
import assert from "node:assert/strict";

const app = process.argv[2];
assert(app, "usage: node create-layout.mjs <path-to-baluard-desktop>");

const browser = await remote({
  hostname: "127.0.0.1",
  port: 4444,
  capabilities: {
    "tauri:options": { application: app },
  },
  logLevel: "warn",
  waitforTimeout: 20000,
});

try {
  await browser.setWindowSize(1200, 700);

  const differentVault = await browser.$("button*=Create new or use a different vault");
  await differentVault.waitForDisplayed({ timeout: 30000 });
  await differentVault.click();
  const newVault = await browser.$(".welcome-screen__btn-new");
  await newVault.waitForDisplayed();
  await newVault.click();
  const screen = await browser.$(".create-vault-screen");
  await screen.waitForDisplayed();

  const before = await browser.execute(() => {
    const container = document.querySelector(".create-vault-screen");
    const card = document.querySelector(".create-vault-screen__card");
    const back = document.querySelector(".create-vault-screen__back-btn");
    return {
      viewportHeight: innerHeight,
      cardTop: card.getBoundingClientRect().top,
      backBottom: back.getBoundingClientRect().bottom,
      overflowY: getComputedStyle(container).overflowY,
      clientHeight: container.clientHeight,
      scrollHeight: container.scrollHeight,
    };
  });

  const failures = [];
  if (before.cardTop < 0) failures.push(`card header starts at ${before.cardTop}px`);
  if (before.backBottom > before.viewportHeight && !["auto", "scroll"].includes(before.overflowY)) {
    failures.push(`back button ends at ${before.backBottom}px in a ${before.viewportHeight}px viewport with overflow-y: ${before.overflowY}`);
  }
  assert.deepEqual(failures, [], `Create-vault controls are unreachable: ${failures.join("; ")}`);

  await browser.execute(() => {
    const container = document.querySelector(".create-vault-screen");
    container.scrollTop = container.scrollHeight;
  });
  await browser.waitUntil(async () => browser.execute(() => {
    const rect = document.querySelector(".create-vault-screen__back-btn").getBoundingClientRect();
    return rect.top >= 0 && rect.bottom <= innerHeight;
  }), { timeoutMsg: "back button did not become visible after scrolling to the bottom" });

  await browser.execute(() => {
    document.querySelector(".create-vault-screen").scrollTop = 0;
  });
  const topAfterScroll = await browser.execute(() => (
    document.querySelector(".create-vault-screen__card").getBoundingClientRect().top
  ));
  assert(topAfterScroll >= 0, `card header is clipped after returning to the top: ${topAfterScroll}px`);

  console.log("E2E desktop create-vault layout: PASS");
} finally {
  await browser.deleteSession().catch(() => {});
}
