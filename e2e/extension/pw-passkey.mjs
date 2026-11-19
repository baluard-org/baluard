// Ring 3 of the E2E harness: the WebAuthn passkey ceremonies (Leg C).
//
// Drives a REAL relying party (rp.mjs on http://localhost — a secure
// context that verifies signatures) through every Baluard path:
//   1. Register: page-script wrap -> popout confirm (new entry) ->
//      daemon provider ceremony -> RP verifies the attestation.
//   2. Assert: single credential, no UV -> silent sign -> RP verifies the
//      ECDSA signature over authData || clientDataHash.
//   3. Conditional: mediation:"conditional" pending -> inline dropdown
//      passkey row -> pick resumes the ceremony -> RP verifies.
//   4. Fallback: an allowCredentials list with transports ["usb"] only must
//      be handed BACK to the browser (page script restores natives); with
//      a CDP virtual authenticator holding no matching credential the
//      native call rejects NotAllowedError — proving the proxy stepped
//      aside and Baluard's UI never appeared.
//
// Closed-shadow UI is located through CDP DOM piercing and clicked with
// trusted mouse events (same technique as inline.mjs, Ring 2).

import { chromium } from "playwright";
import { gatewayRequest } from "./gateway.mjs";

const EXT_ID = process.env.EXT_ID;
const EXT_DIR = process.env.EXT_DIR;
const PROFILE_DIR = process.env.PROFILE_DIR || "";
const CDP_PORT = process.env.CDP_PORT;
const RP_PORT = process.env.RP_PORT;
const SOCKET = process.env.DAEMON_SOCKET;
const TOKEN = process.env.DESKTOP_TOKEN;
if (!EXT_ID || !EXT_DIR || !RP_PORT) fail("EXT_ID / EXT_DIR / RP_PORT missing");
const RP_URL = `http://localhost:${RP_PORT}/`;
const HOST_ATTR = "data-baluard-inline";

// Every assertion lands on the picker popout now (Bitwarden parity): wait
// for it, confirm the first row, and return it for extra assertions.
async function pickInPopout(ctx) {
  let popout = null;
  for (let i = 0; i < 40; i++) {
    popout = ctx.pages().find((p) => p.url().includes("popup.html#/passkey/"));
    if (popout) break;
    await sleep(300);
  }
  if (!popout) return null;
  await popout.waitForSelector(".match-card", { timeout: 10000 });
  await popout.locator(".match-card").first().click();
  return popout;
}

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

// Debug dump for ceremony failures: the RP page's own status line and the
// fresh page URL, printed before the driver exits.
async function dumpPage(page) {
  if (!page || page.isClosed()) return;
  try {
    console.error(
      "PAGE-STATUS " + (await page.evaluate(() => document.getElementById("status")?.textContent || ""))
    );
    console.error("PAGE-URL " + page.url());
  } catch {}
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(page, fn, desc, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await page.evaluate(fn).catch(() => null);
    if (last) return last;
    await sleep(250);
  }
  // Throw (not fail) so the catch block dumps diagnostics first.
  throw new Error(`timeout waiting for ${desc} (last=${JSON.stringify(last)})`);
}

async function shadowNodes(client, hostAttr, cls) {
  const treeContainsAttr = (node, attr) => {
    if ((node.attributes || []).includes(attr)) return true;
    return (
      (node.children || []).some((c) => treeContainsAttr(c, attr)) ||
      (node.shadowRoots || []).some((c) => treeContainsAttr(c, attr))
    );
  };
  let root;
  for (let i = 0; i < 5; i++) {
    try {
      ({ root } = await client.send("DOM.getDocument", { depth: -1, pierce: true }));
    } catch (e) {
      throw new Error(`DOM.getDocument failed (${e.message})`);
    }
    if (treeContainsAttr(root, hostAttr)) break;
    await sleep(300);
  }
  const out = [];
  const collectText = (n) =>
    (n.nodeType === 3 ? n.nodeValue || n.textContent || "" : "") +
    (n.children || []).map(collectText).join("");
  const walk = (node, inside) => {
    const attrs = node.attributes || [];
    const isInside = inside || attrs.includes(hostAttr);
    const ci = attrs.indexOf("class");
    if (isInside && ci >= 0 && attrs[ci + 1]?.split(/\s+/).includes(cls)) {
      const text = (node.children || []).map(collectText).join(" ").trim();
      out.push({ nodeId: node.nodeId, text });
    }
    for (const child of node.children || []) walk(child, isInside);
    for (const sr of node.shadowRoots || []) walk(sr, true);
  };
  walk(root, false);
  return out;
}

async function waitShadowNodes(client, hostAttr, cls, timeoutMs = 12000, accept) {
  const deadline = Date.now() + timeoutMs;
  let nodes = [];
  while (Date.now() < deadline) {
    nodes = await shadowNodes(client, hostAttr, cls);
    if (nodes.length > 0 && (!accept || nodes.some((n) => accept(n.text)))) return nodes;
    await sleep(300);
  }
  return nodes;
}

async function clickShadowNode(page, client, hostAttr, cls, wantText, keyboard) {
  let nodes = [];
  for (let i = 0; i < 40; i++) {
    nodes = await shadowNodes(client, hostAttr, cls);
    if (nodes.length > 0 && (!wantText || nodes.some((n) => n.text.includes(wantText)))) break;
    await sleep(300);
  }
  const pick = wantText
    ? nodes.find((n) => n.text.includes(wantText)) ||
      (nodes.length === 1 ? nodes[0] : undefined)
    : nodes[0];
  if (!pick) throw new Error(`shadow node not found: .${cls}${wantText ? ` (${wantText})` : ""}`);
  const { model } = await client.send("DOM.getBoxModel", { nodeId: pick.nodeId });
  const q = model.border;
  const center = { x: (q[0] + q[4]) / 2, y: (q[1] + q[5]) / 2 };
  if (keyboard) {
    // Accessibility path: focus the row via CDP and press Enter (the row's
    // keydown handler). Used where the mouse route proved flaky.
    await client.send("DOM.focus", { nodeId: pick.nodeId });
    await keyboard.press("Enter");
  } else {
    await page.mouse.click(center.x, center.y);
  }
  return { ...pick, center };
}

const ctx = await chromium.launchPersistentContext(PROFILE_DIR, {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT_DIR}`,
    `--load-extension=${EXT_DIR}`,
    `--remote-debugging-port=${CDP_PORT}`,
  ],
});
// Popout windows surface here late relative to chrome.windows.create, and
// their URL may still be blank at event time — polling pages() below is
// the reliable detector.
const swLogs = [];
const pageLogs = [];
let page = null;
let swPoll = null;
try {
  const sw =
    ctx.serviceWorkers().find((w) => w.url().includes(EXT_ID)) ||
    (await ctx.waitForEvent("serviceworker", { timeout: 15000 }));
  if (!sw.url().includes(EXT_ID)) fail(`unexpected worker ${sw.url()}`);
  // The browser restarts the SW on idle; hook EVERY instance so console
  // breadcrumbs survive a restart mid-leg.
  const hookSw = (w) => {
    if (w.__hooked) return;
    w.__hooked = true;
    w.on("console", (m) => swLogs.push(m.text()));
  };
  ctx.serviceWorkers().forEach(hookSw);
  ctx.on("serviceworker", hookSw);
  swPoll = setInterval(() => ctx.serviceWorkers().forEach(hookSw), 1000);

  // ── pairing (when this leg runs without Rings 1/2 before it) ──
  const desktop = (action, payload) => gatewayRequest(SOCKET, { action, payload, token: TOKEN });
  const popupPage = await ctx.newPage();
  await popupPage.goto(`chrome-extension://${EXT_ID}/popup.html`);
  await popupPage.waitForSelector(".baluard-popup");
  const bodyText = await popupPage.evaluate(() => document.body.innerText);
  if (bodyText.includes("Welcome to Baluard")) {
    await popupPage.getByRole("button", { name: "I have Baluard installed" }).click();
    await popupPage.waitForSelector(".pair-code-input");
    const started = await desktop("bridge.pair_start", JSON.stringify({ browser: "chromium" }));
    const code = JSON.parse(started).pair_code;
    if (!code || code.length !== 8) fail(`bad pair code: ${started}`);
    await popupPage.fill(".pair-code-input", code);
    await popupPage.getByRole("button", { name: "Connect to Baluard" }).click();
    await desktop("bridge.pair_approve", "{}");
    await popupPage
      .waitForFunction(() => !document.body.innerText.includes("Waiting for approval"), null, {
        timeout: 15000,
      })
      .catch(() => {});
    console.log("PASS pairing");
  } else if (bodyText.includes("Waiting for approval")) {
    fail("popup left in a stale pairing state");
  }

  // ── enable passkeys through the real settings UI ──
  await popupPage.evaluate(() => location.reload());
  await popupPage.waitForSelector(".header-actions button");
  // Locale-independent selectors: the header gear and the third toggle row
  // (inline autofill, copy code, passkeys) by position, not by string.
  await popupPage.locator(".header-actions button").first().click();
  const passkeyToggle = popupPage.locator(".setting-row input[type=checkbox]").nth(2);
  // Default ON: cycle off and back on through the real UI so the settings
  // write, the SW re-registration dance, and the stayed-on guard all still
  // run (a failed MAIN-world registration flips it back off).
  await passkeyToggle.click();
  await sleep(300);
  await passkeyToggle.click();
  // The SW registers both content scripts and injects into open tabs; give
  // that dance a beat, then confirm the toggle stayed on.
  await sleep(1200);
  if (!(await passkeyToggle.isChecked())) {
    fail("passkeys toggle did not stay on (world MAIN unsupported?)");
  }
  await popupPage.close();

  // Fresh page AFTER the setting exists so document_start registration
  // picks it up (registered scripts apply to new loads).
  page = await ctx.newPage();
  page.on("console", (m) => pageLogs.push(m.text()));
  const cdp = await ctx.newCDPSession(page);
  const statusText = () => document.getElementById("status").textContent;

  await page.goto(RP_URL);

  // ── 1. Registration through the popout ──
  await page.click("#register");
  let popout = null;
  for (let i = 0; i < 40; i++) {
    popout = ctx.pages().find((p) => p.url().includes("popup.html#/passkey/"));
    if (popout) break;
    await sleep(300);
  }
  if (!popout) {
    await dumpPage(page);
    fail("registration popout never opened");
  }
  await popout.waitForSelector(".state-title", { timeout: 10000 });
  // The confirm view has exactly one .btn-secondary: "create a new entry"
  // (locale-independent; the site-row cards are .match-card elements).
  await popout.locator("button.btn-secondary").last().click();
  await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.includes("REGISTER") && s.includes('"verified":true') ? s : null;
    },
    "RP attestation verification"
  );
  console.log("PASS register (RP verified attestation)");

  // ── 2. Single-credential assertion rides the picker (Bitwarden parity) ──
  // One matching credential used to sign silently; every assertion now
  // opens the picker and waits for the explicit confirm.
  await page.click("#signin");
  if (!(await pickInPopout(ctx))) {
    await dumpPage(page);
    fail("single-credential picker never opened");
  }
  await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.includes("ASSERT") && s.includes('"verified":true') ? s : null;
    },
    "RP assertion signature verification"
  );
  console.log("PASS assert (picker confirmed, RP verified ECDSA signature)");

  // ── 3. Conditional mediation via the inline dropdown ──
  await page.click("#conditional"); // pending conditional get
  // Focus a qualifying field so the icon mounts, then open the menu.
  await page.click("#user");
  await clickShadowNode(page, cdp, HOST_ATTR, "icon");
  // Accept only real credential rows (entry name or username), never any
  // stray text in the menu.
  const rows = await waitShadowNodes(cdp, HOST_ATTR, "entry", 12000, (t) =>
    t.includes("Local Passkey RP") || t.includes("demo")
  );
  if (rows.length === 0) fail("conditional passkey row not rendered");
  // Drive the pick from the content script's OWN isolated world: the closed
  // shadow root is reachable there (host.shadowRoot is null everywhere
  // else), and element.click() fires the row's real handler. The mouse and
  // keyboard routes both proved unreliable against this closed-root menu
  // from outside the world.
  const cdp2 = await ctx.newCDPSession(page);
  const contexts = [];
  cdp2.on("Runtime.executionContextCreated", (e) => contexts.push(e.context));
  await cdp2.send("Runtime.enable");
  await sleep(500);
  const isolated = contexts.find((c) => c.auxData && c.auxData.isDefault === false);
  if (!isolated) fail("isolated world context not found");
  const pickResult = await cdp2.send("Runtime.evaluate", {
    contextId: isolated.id,
    expression: `(() => {
      if (typeof window.__baluardPasskeyPickFirst !== "function") return "no-hook";
      return JSON.stringify(window.__baluardPasskeyPickFirst());
    })()`,
    returnByValue: true,
  });
  console.error("PICK-VIA-ISOLATED " + JSON.stringify(pickResult.result && pickResult.result.value));
  // Ground truth: the page's own conditional promise settles and the RP
  // verifies the resumed assertion (the pick diagnostics live in the SW
  // trail now — the host element is page-readable and carries nothing).
  await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.includes("CONDITIONAL") && s.includes('"verified":true') ? s : null;
    },
    "RP conditional verification"
  );
  console.log("PASS conditional (inline dropdown resumed the ceremony)");

  // ── 4. Fallback: usb-only allowCredentials go back to the browser ──
  // A CDP virtual authenticator is attached so the NATIVE path can settle:
  // it holds no matching credential, so the native call must reject fast.
  await cdp.send("WebAuthn.enable", {});
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "usb", hasResidentKey: true, isUserVerified: true },
  });
  const popoutsBeforeFallback = ctx.pages().filter((p) => p.url().includes("#/passkey/")).length;
  await page.click("#usb");
  await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.startsWith("USB ") ? s : null;
    },
    "native fallback outcome"
  );
  const usbOutcome = await page.evaluate(statusText);
  if (!usbOutcome.includes("NotAllowedError")) {
    fail(`fallback expected native NotAllowedError, got: ${usbOutcome}`);
  }
  if (ctx.pages().filter((p) => p.url().includes("#/passkey/")).length !== popoutsBeforeFallback) {
    fail("fallback must not open any Baluard UI");
  }
  console.log("PASS fallback (native ceremony rejected; Baluard UI stayed out)");

  // ── 5. UV-required assertion rides the popout picker ──
  await page.click("#signin-uv");
  let uvPopout = null;
  for (let i = 0; i < 40; i++) {
    uvPopout = ctx.pages().find((p) => p.url().includes("popup.html#/passkey/"));
    if (uvPopout) break;
    await sleep(300);
  }
  if (!uvPopout) {
    await dumpPage(page);
    fail("UV assertion picker never opened");
  }
  await uvPopout.waitForSelector(".match-card", { timeout: 10000 });
  await uvPopout.locator(".match-card").first().click();
  const uvStatus = await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.includes("UV ") && s.includes('"verified":true') ? s : null;
    },
    "RP UV assertion verification"
  );
  if (!uvStatus.includes('"uv":true')) fail("UV flag missing in RP verification");
  console.log("PASS uv-picker (popout picker granted user verification)");

  // ── 6. RP negatives: flipped signature byte + replayed challenge ──
  const tamper = await page.evaluate(async () =>
    (await (await fetch("/tamper-verify", { method: "POST" })).json())
  );
  if (tamper.ok !== false) fail(`tampered signature verified (bug): ${JSON.stringify(tamper)}`);
  const replay = await page.evaluate(async () =>
    (await (await fetch("/replay-verify", { method: "POST" })).json())
  );
  if (replay.ok !== false || !/challenge/i.test(String(replay.error))) {
    fail(`replayed challenge accepted (bug): ${JSON.stringify(replay)}`);
  }
  console.log("PASS rp-negatives (tamper rejected, replay rejected)");

  // ── 7. SPA pushState must NOT strand the bridge port ──
  await page.evaluate(() => history.pushState({}, "", "/spa-navigated"));
  await sleep(400);
  await page.click("#signin");
  if (!(await pickInPopout(ctx))) fail("post-pushState picker never opened");
  await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.includes("ASSERT") && s.includes('"verified":true') ? s : null;
    },
    "post-pushState assertion"
  );
  console.log("PASS spa-pushState (bridge port survived the history change)");

  // ── 8. Toggle off restores natives; back on re-wraps live ──
  const settings = await ctx.newPage();
  await settings.goto(`chrome-extension://${EXT_ID}/popup.html`);
  await settings.waitForSelector(".header-actions button");
  await settings.locator(".header-actions button").first().click();
  const pkToggle = settings.locator(".setting-row input[type=checkbox]").nth(2);
  if (!(await pkToggle.isChecked())) fail("passkeys toggle unexpectedly off before the toggle leg");
  await pkToggle.click();
  await sleep(1500);
  const offState = await page.evaluate(() => window.__baluardPasskey);
  if (offState !== false) fail(`natives not restored after toggle off (__baluardPasskey=${offState})`);
  await pkToggle.click();
  await sleep(1500);
  if (!(await pkToggle.isChecked())) fail("passkeys toggle did not come back on");
  const onState = await page.evaluate(() => window.__baluardPasskey);
  if (onState !== true) fail(`interception not re-armed after toggle on (__baluardPasskey=${onState})`);
  await settings.close();
  // The re-armed wrap must still serve a full ceremony.
  await page.click("#signin");
  if (!(await pickInPopout(ctx))) fail("post-re-enable picker never opened");
  await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.includes("ASSERT") && s.includes('"verified":true') ? s : null;
    },
    "post-re-enable assertion"
  );
  console.log("PASS toggle-cycle (off restores natives, on re-arms the wrap)");

  // ── 9. Service-worker kill: wrap survives, pipeline re-arms ──
  // MV3 idles the service worker ~30s after its last event; the bridge
  // content script must reconnect (not destroy) when that disconnect
  // lands, and the whole ceremony pipeline must still work afterwards.
  // DevTools-attached workers do not idle-terminate, so the harness stops
  // all workers deterministically over CDP instead of sleeping 36s.
  console.log("leg 9: stopping all service workers over CDP");
  // Clear the status line so the post-kill assertion cannot pass on leg
  // 8's stale text (rp.mjs never clears it between clicks).
  await page.evaluate(() => {
    document.getElementById("status").textContent = "";
  });
  const idleCdp = await ctx.newCDPSession(page);
  await idleCdp.send("ServiceWorker.stopAllWorkers");
  await sleep(1500);
  const idleWrap = await page.evaluate(() => window.__baluardPasskey);
  if (idleWrap !== true)
    fail(`wrap did not survive the service-worker stop (__baluardPasskey=${idleWrap})`);
  await page.click("#signin");
  if (!(await pickInPopout(ctx))) fail("post-idle picker never opened");
  await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.includes("ASSERT") && s.includes('"verified":true') ? s : null;
    },
    "post-idle assertion"
  );
  console.log("PASS idle-survival (wrap + ceremony intact after SW stop)");

  // ── 10. Stale-registration repair ──
  // Simulate what an extension UPDATE actually leaves behind: the page
  // script pinned with STALE PARAMS (no world MAIN — an older release's
  // shape). The id-present check of the old sync considered this healthy;
  // the spec-compare sync must repair it. The wrap stays dark (the
  // ISOLATED-world copy never touches the page's MAIN-world flag), then a
  // settings write with a REAL value change fires storage.onChanged →
  // syncPasskeyScripts, which re-registers with the current spec.
  const repair = await ctx.newPage();
  await repair.goto(`chrome-extension://${EXT_ID}/popup.html`);
  await repair.waitForSelector(".baluard-popup");
  await repair.evaluate(async () => {
    await chrome.scripting.unregisterContentScripts({ ids: ["baluard-passkey-page"] });
    await chrome.scripting.registerContentScripts([
      {
        id: "baluard-passkey-page",
        js: ["passkey-page.js"],
        matches: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
        runAt: "document_start",
        allFrames: false,
        persistAcrossSessions: true,
      },
    ]);
  });
  await sleep(500);
  await repair.close();
  await page.reload();
  await waitFor(page, () => document.getElementById("status") !== null, "RP reload");
  const staleWrap = await page.evaluate(() => window.__baluardPasskey);
  if (staleWrap === true)
    fail(`page script still wraps the MAIN world after stale registration (__baluardPasskey=${staleWrap})`);
  // Trigger the sync deterministically: an identical write would not fire
  // storage.onChanged, so flip a throwaway key and restore it.
  const swWake = await ctx.newPage();
  await swWake.goto(`chrome-extension://${EXT_ID}/popup.html`);
  await swWake.waitForSelector(".baluard-popup");
  await swWake.evaluate(async () => {
    const cur = await chrome.storage.local.get("settings");
    const base = cur.settings || {};
    await chrome.storage.local.set({ settings: { ...base, _syncNudge: Date.now() } });
    await chrome.storage.local.set({ settings: base });
  });
  await sleep(2000);
  const repaired = await swWake.evaluate(async () => {
    const all = await chrome.scripting.getRegisteredContentScripts();
    return all.find((r) => r.id === "baluard-passkey-page");
  });
  if (!repaired || (repaired.world ?? "ISOLATED") !== "MAIN")
    fail(`registration repair did not restore world MAIN (${JSON.stringify(repaired || null)})`);
  await swWake.close();
  await page.reload();
  await waitFor(page, () => document.getElementById("status") !== null, "RP reload 2");
  const repairedWrap = await page.evaluate(() => window.__baluardPasskey);
  if (repairedWrap !== true)
    fail(`registration repair did not re-arm the wrap (__baluardPasskey=${repairedWrap})`);
  await page.evaluate(() => {
    document.getElementById("status").textContent = "";
  });
  await page.click("#signin");
  if (!(await pickInPopout(ctx))) fail("post-repair picker never opened");
  await waitFor(
    page,
    () => {
      const s = document.getElementById("status").textContent;
      return s.includes("ASSERT") && s.includes('"verified":true') ? s : null;
    },
    "post-repair assertion"
  );
  console.log("PASS registration-repair (stale unregister healed, pipeline re-armed)");

  console.log("RING3=1");
  // Close hard: a wedged popout or service worker must never hold the
  // runner's pipes open (process.exit also mirrors the fail() path).
  await ctx.close().catch(() => {});
  process.exit(0);
} catch (e) {
  if (swPoll) clearInterval(swPoll);
  for (const line of swLogs.slice(-12)) console.error("SW-LOG " + line);
  for (const line of pageLogs.slice(-14)) console.error("PAGE-LOG " + line);
  // SW breadcrumbs from storage.session (readable from extension pages).
  try {
    const reader = await ctx.newPage();
    await reader.goto(`chrome-extension://${EXT_ID}/popup.html`);
    await sleep(600);
    const trail = await reader.evaluate(async () => {
      const r = await chrome.storage.session.get("pkTrail");
      return r.pkTrail || [];
    });
    for (const line of trail) console.error("PK-TRAIL " + line);
    await reader.close();
  } catch (e2) {
    console.error("PK-TRAIL-ERR " + e2.message);
  }
  await dumpPage(page);
  fail(e.message);
} finally {
  await ctx.close();
}
