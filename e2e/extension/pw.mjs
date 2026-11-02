// Browser-extension e2e: real Chromium + real NMH + real daemon.
//
// Ring 1 of the E2E harness. The orchestrator (run-e2e-extension.sh)
// builds the dist with an injected fixed key (deterministic extension id),
// registers the NMH manifest inside the profile (and the HOME brand paths),
// starts a scratch daemon, seeds and unlocks a vault, and passes the desktop
// session token here — this script then plays the desktop side of the bridge
// pairing ceremony over the daemon socket (pair_start / pair_approve), the
// exact flows the desktop UI drives.
//
// The ceremony rides the REAL browser-action popup: a tab-borne popup.html is
// dropped by the service worker's content-script guard (sender.tab present),
// and Chromium surfaces the action popup only as a raw CDP target, which
// cdp-popup.mjs drives directly.

import { createServer } from "node:http";
import { chromium } from "playwright";
import { gatewayRequest } from "./gateway.mjs";
import { PopupCdp } from "./cdp-popup.mjs";

const EXT_ID = process.env.EXT_ID;
const TOKEN = process.env.DESKTOP_TOKEN;
const SOCKET = process.env.DAEMON_SOCKET;
const SITE_URL = process.env.SITE_URL;
const EXT_DIR = process.env.EXT_DIR;
const PROFILE_DIR = process.env.PROFILE_DIR || "";
const CDP_PORT = process.env.CDP_PORT;

const fail = (m) => {
  console.error(`FAIL: ${m}`);
  process.exit(1);
};
const missing = Object.entries({ EXT_ID, TOKEN, SOCKET, SITE_URL, EXT_DIR, CDP_PORT })
  .filter(([, v]) => !v)
  .map(([k]) => k);
if (missing.length) fail(`env missing: ${missing.join(",")}`);

const desktop = (action, payload) => gatewayRequest(SOCKET, { action, payload, token: TOKEN });

// Local "site": an http origin the seeded login's URI matches.
const site = createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  res.end("<html><body><h1>Ext E2E Site</h1></body></html>");
});
await new Promise((r) => site.listen(new URL(SITE_URL).port, "127.0.0.1", r));

const swLogs = [];
const ctx = await chromium.launchPersistentContext(PROFILE_DIR, {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT_DIR}`,
    `--load-extension=${EXT_DIR}`,
    `--remote-debugging-port=${CDP_PORT}`,
  ],
});
try {
  // The service worker must be alive; it opens the NMH port on startup, so a
  // dead NMH would surface as no-daemon in the popup instead of matches.
  const sw =
    ctx.serviceWorkers().find((w) => w.url().includes(EXT_ID)) ||
    (await ctx.waitForEvent("serviceworker", { timeout: 15000 }));
  if (!sw.url().includes(EXT_ID)) fail(`unexpected worker ${sw.url()}`);
  sw.on("console", (m) => swLogs.push(m.text()));

  const version = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`)).json();
  const cdp = await PopupCdp.connect(version.webSocketDebuggerUrl);

  const openPopup = async () => {
    await sw.evaluate(() => chrome.action.openPopup());
    await new Promise((r) => setTimeout(r, 800));
    await cdp.attachPopup();
    return cdp;
  };

  // ---- Pairing ceremony: welcome -> code -> held pair_complete -> approve.
  const popup = await openPopup();
  await popup.waitForText("Welcome to Baluard");
  await popup.clickButton("I have Baluard installed");
  await popup.waitForText("Link this browser to the Baluard app");

  const started = await desktop("bridge.pair_start", JSON.stringify({ browser: "chromium" }));
  const code = JSON.parse(started).pair_code;
  if (!code || code.length !== 8) fail(`bad pair code: ${started}`);

  await popup.fillInput(".pair-code-input", code);
  await popup.clickButton("Connect to Baluard");
  await popup.waitForText("Waiting for approval");
  await desktop("bridge.pair_approve", "{}");
  // Approval resolves the held pair_complete; the popup re-probes into ready
  // (its active tab here is not a matched site, so ready shows no matches).
  await popup.waitForText("No logins for this site");
  console.log("PASS pairing");

  // ---- Matched-entries surface: reopen the popup over the site tab; the
  // popup boots against the ACTIVE tab and renders the match card.
  const sitePage = await ctx.newPage();
  await sitePage.goto(SITE_URL);
  const popup2 = await openPopup();
  await popup2.waitForText("Ext Bank");
  await popup2.waitForText("u@ext.test");

  // A real user lands on the site tab by switching to it; switching also
  // drives the badge's onActivated path.
  await sw.evaluate(
    (site) =>
      new Promise((r) =>
        chrome.tabs.query({}, (tabs) => {
          const tab = tabs.find((t) => t.url && t.url.startsWith(site));
          if (tab) chrome.tabs.update(tab.id, { active: true }, () => void chrome.runtime.lastError);
          r();
        }),
      ),
    SITE_URL,
  );
  await new Promise((r) => setTimeout(r, 1000));

  let badge = "";
  for (let i = 0; i < 20 && badge !== "1"; i++) {
    await new Promise((r) => setTimeout(r, 300));
    badge = await sw.evaluate(
      (site) =>
        new Promise((r) =>
          chrome.tabs.query({}, (tabs) => {
            const tab = tabs.find((t) => t.url && t.url.startsWith(site));
            if (!tab) return r("no-site-tab");
            chrome.action.getBadgeText({ tabId: tab.id }, r);
          }),
        ),
      SITE_URL,
    );
  }
  if (badge !== "1") fail(`badge expected 1, got ${JSON.stringify(badge)} / sw=${JSON.stringify(swLogs)}`);
  console.log("PASS matches");

  cdp.close();
  console.log("EXT=0");
} catch (e) {
  console.error("FAIL:", e.message.split("\n")[0]);
  console.error("sw console:", JSON.stringify(swLogs.slice(-8)));
  process.exitCode = 1;
} finally {
  await ctx.close();
  site.close();
}
