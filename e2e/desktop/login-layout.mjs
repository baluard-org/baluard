// Desktop auth/onboarding layout: on short (non-maximized) windows every
// card must scroll inside its screen instead of clipping top and bottom —
// the join form, the welcome hub, and the clone wizard all grow past 700px.
import { remote } from "webdriverio";
import assert from "node:assert/strict";

const app = process.argv[2];
assert(app, "usage: login-layout.mjs <path-to-baluard-desktop>");

const browser = await remote({
  hostname: "127.0.0.1",
  port: 4444,
  capabilities: {
    "tauri:options": { application: app },
  },
  logLevel: "warn",
  waitforTimeout: 20000,
});

// Metrics for one screen: the card must not clip at scrollTop 0, the
// container must scroll when the card outgrows the viewport, and the
// card's bottom edge must be reachable.
async function measureScreen(containerSel, cardSel) {
  return browser.execute(
    (cSel, kSel) => {
      const container = document.querySelector(cSel);
      const card = document.querySelector(kSel);
      if (!container || !card) return null;
      const c = card.getBoundingClientRect();
      return {
        overflowY: getComputedStyle(container).overflowY,
        viewportHeight: innerHeight,
        cardTop: c.top,
        cardBottom: c.bottom,
        clientHeight: container.clientHeight,
        scrollHeight: container.scrollHeight,
      };
    },
    containerSel,
    cardSel,
  );
}

async function assertScreen(label, containerSel, cardSel) {
  await browser.$(cardSel).waitForDisplayed();
  const m = await measureScreen(containerSel, cardSel);
  assert(m, `${label}: ${cardSel} not found`);
  const failures = [];
  if (m.cardTop < 0) failures.push(`card top is clipped at ${m.cardTop}px`);
  if (
    m.cardBottom > m.viewportHeight &&
    !["auto", "scroll"].includes(m.overflowY)
  ) {
    failures.push(
      `card ends at ${m.cardBottom}px in a ${m.viewportHeight}px viewport with overflow-y: ${m.overflowY}`,
    );
  }
  await browser.execute(
    (cSel) => {
      document.querySelector(cSel).scrollTop = document.querySelector(cSel).scrollHeight;
    },
    containerSel,
  );
  await browser.waitUntil(
    async () => {
      const s = await measureScreen(containerSel, cardSel);
      return s && s.cardBottom <= s.viewportHeight + 1;
    },
    { timeoutMsg: `${label}: card bottom is unreachable by scrolling` },
  );
  await browser.execute(
    (cSel) => {
      document.querySelector(cSel).scrollTop = 0;
    },
    containerSel,
  );
  const top = await measureScreen(containerSel, cardSel);
  if (top.cardTop < 0) {
    failures.push(`card top is clipped after returning to the top: ${top.cardTop}px`);
  }
  assert.deepEqual(failures, [], `${label}: ${failures.join("; ")}`);
}

try {
  await browser.setWindowSize(1200, 700);

  // Join form (the reported bug): the unlock card's footer link toggles it.
  const joinLink = await browser.$("button*=Joining a shared vault");
  await joinLink.waitForDisplayed({ timeout: 30000 });
  await joinLink.click();
  await assertScreen("login join", ".login-screen", ".login-screen__card");

  // Back to unlock, then on to the welcome hub.
  const back = await browser.$("button*=Back to unlock");
  await back.waitForDisplayed();
  await back.click();
  const different = await browser.$("button*=Create new or use a different vault");
  await different.waitForDisplayed();
  await different.click();
  await assertScreen("welcome", ".welcome-screen", ".welcome-screen__card");

  // Clone wizard from the welcome hub.
  const download = await browser.$(".welcome-screen__btn-download");
  await download.waitForDisplayed();
  await download.click();
  await assertScreen("clone", ".clone-screen", ".clone-screen__card");

  console.log("E2E desktop auth layout: PASS");
} finally {
  await browser.deleteSession().catch(() => {});
}
