// Ring 2 of the E2E harness: the inline autofill dropdown driven
// on REAL public sites (same harness shape as pw.mjs, Ring 1).
//
// The dropdown UI lives inside a CLOSED shadow root (page JS cannot reach it
// by design), so the icon and the menu entries are located through the CDP
// DOM domain with pierce:true and clicked with trusted input events
// (Playwright's mouse) - the only user-realistic way in.
//
// Leg A: practicetestautomation.com - icon on the username field, entry click
// fills username+password, submit, the real login succeeds.
// Leg B: 2fa.scheb.de - login form filled the same way, then the TOTP
// challenge: the icon on the one-time-code field fills the code computed by
// the daemon from the demo's published fixture secret, submit, 2FA passes.

import { createServer } from "node:http";
import crypto from "node:crypto";
import { chromium } from "playwright";
import { gatewayRequest } from "./gateway.mjs";
import { PopupCdp } from "./cdp-popup.mjs";

const EXT_ID = process.env.EXT_ID;
const TOKEN = process.env.DESKTOP_TOKEN;
const SOCKET = process.env.DAEMON_SOCKET;
const EXT_DIR = process.env.EXT_DIR;
const PROFILE_DIR = process.env.PROFILE_DIR || "";
const CDP_PORT = process.env.CDP_PORT;

const PRACTICE_URL = "https://practicetestautomation.com/practice-test-login/";
const DEMO_URL = process.env.DEMO_URL;
if (!DEMO_URL) fail("DEMO_URL missing");

// ── Local 2FA demo: a real server-side TOTP verifier over our own fixture
// secret. The live 2fa.scheb.de was tried first and rejected hand-computed
// codes for its own published fixture (deployment drift), so per Esteban the
// 2FA leg runs against this local verifier instead — same mechanics (login
// form, one-time-code challenge, ±1 TOTP window), zero drift.
const DEMO_SECRET_B32 = "JBSWY3DPEHPK3PXP";
const DEMO_USER = "user1";
const DEMO_PASS = "test";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const b32decode = (s) => {
  const clean = s.toUpperCase().replace(/=+$/, "");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) out.push((value >>> (bits - 8)) & 0xff), (bits -= 8);
  }
  return Buffer.from(out);
};
const DEMO_SECRET = b32decode(DEMO_SECRET_B32);
const totpAt = (counter) => {
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(counter, 4); // STREAM counter, big-endian
  const mac = crypto.createHmac("sha1", DEMO_SECRET).update(msg).digest();
  const o = mac[mac.length - 1] & 0x0f;
  return String((mac.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0");
};
const sessions = new Map();
const demoServer = createServer((req, res) => {
  const sid = (req.headers.cookie || "").match(/sid=(\w+)/)?.[1];
  const sess = sid && sessions.get(sid);
  const redirect = (loc) => { res.writeHead(302, { location: loc }); res.end(); };
  const page = (body) => { res.writeHead(200, { "content-type": "text/html" }); res.end(body); };
  if (req.url === "/login" && req.method === "POST") {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const form = new URLSearchParams(raw);
      if (form.get("username") !== DEMO_USER || form.get("password") !== DEMO_PASS) return redirect("/?error=1");
      const id = crypto.randomBytes(8).toString("hex");
      sessions.set(id, { stage: "2fa" });
      res.writeHead(302, { location: "/2fa", "set-cookie": `sid=${id}; HttpOnly` });
      res.end();
    });
    return;
  }
  if (req.url === "/2fa" && req.method === "POST") {
    if (!sess) return redirect("/");
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const code = new URLSearchParams(raw).get("_auth_code") || "";
      const counter = Math.floor(Date.now() / 1000 / 30);
      if ([1, 0, -1].some((d) => code === totpAt(counter + d))) sess.stage = "done";
      redirect(sess.stage === "done" ? "/" : "/2fa?error=1");
    });
    return;
  }
  if (req.url.startsWith("/2fa")) {
    if (!sess) return redirect("/");
    return page(`<h1>Two-Factor Authentication</h1>
      ${req.url.includes("error") ? "<p>The verification code is not valid.</p>" : ""}
      <form method="post" action="/2fa">
        <input id="_auth_code" name="_auth_code" autocomplete="one-time-code" autofocus />
        <button type="submit">Login</button>
      </form>`);
  }
  if (sess?.stage === "done") return page(`<h1>Local 2FA OK</h1><p>Hello ${DEMO_USER}, welcome to the secured area.</p>`);
  page(`<h1>Login</h1>
    ${req.url.includes("error") ? "<p>Invalid credentials.</p>" : ""}
    <form method="post" action="/login">
      <input id="username" name="username" type="text" />
      <input id="password" name="password" type="password" />
      <button type="submit">Login</button>
    </form>`);
});
await new Promise((r) => demoServer.listen(new URL(DEMO_URL).port, "127.0.0.2", r));

const fail = (m) => {
  console.error(`FAIL: ${m}`);
  process.exit(1);
};
if (!EXT_ID || !TOKEN || !SOCKET || !EXT_DIR || !CDP_PORT) fail("env missing");

const desktop = (action, payload) => gatewayRequest(SOCKET, { action, payload, token: TOKEN });

// ── Closed-shadow navigation via the CDP DOM domain ──
// Returns [{nodeId, text}] for every node whose class attribute carries `cls`
// inside any shadow root under the host carrying `hostAttr`.
async function shadowNodes(client, hostAttr, cls) {
  const treeContainsAttr = (node, attr) => {
    if ((node.attributes || []).includes(attr)) return true;
    return (
      (node.children || []).some((c) => treeContainsAttr(c, attr)) ||
      (node.shadowRoots || []).some((c) => treeContainsAttr(c, attr))
    );
  };
  // The pierced snapshot can come back short while the renderer is busy;
  // retry until the inline host itself is visible in the tree.
  let root;
  for (let i = 0; i < 5; i++) {
    try {
      ({ root } = await client.send("DOM.getDocument", { depth: -1, pierce: true }));
    } catch (e) {
      throw new Error(`DOM.getDocument failed (${e.message})`);
    }
    if (treeContainsAttr(root, hostAttr)) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  const out = [];
  const walk = (node, inside) => {
    const attrs = node.attributes || [];
    const isInside = inside || attrs.includes(hostAttr);
    const ci = attrs.indexOf("class");
    if (isInside && ci >= 0 && attrs[ci + 1]?.split(/\s+/).includes(cls)) {
      const text = (node.children || [])
        .map((c) => collectText(c))
        .join(" ")
        .trim();
      out.push({ nodeId: node.nodeId, text });
    }
    for (const child of node.children || []) walk(child, isInside);
    for (const sr of node.shadowRoots || []) walk(sr, true);
  };
  const collectText = (n) =>
    (n.nodeType === 3 ? n.textContent || "" : "") +
    (n.children || []).map(collectText).join("");
  walk(root, false);
  return out;
}

async function clickShadowNode(page, client, hostAttr, cls, wantText) {
  // The dropdown loads matches over IPC (and the icon needs a focus race on
  // ad-heavy pages); poll up to ~12s for the requested node.
  let nodes = [];
  for (let i = 0; i < 40; i++) {
    nodes = await shadowNodes(client, hostAttr, cls);
    if (nodes.length > 0 && (!wantText || nodes.some((n) => n.text.includes(wantText)))) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  // Prefer the text match; the pierced tree can truncate entry children on
  // ad-heavy pages, so a single-entry menu is also accepted as-is (both test
  // sites match exactly one seeded login).
  const pick = wantText
    ? nodes.find((n) => n.text.includes(wantText)) ||
      (nodes.length === 1 ? nodes[0] : undefined)
    : nodes[0];
  if (!pick) throw new Error(`shadow node not found: .${cls}${wantText ? ` (${wantText})` : ""}`);
  const { model } = await client.send("DOM.getBoxModel", { nodeId: pick.nodeId });
  const q = model.border; // [x1,y1, x2,y2, x3,y3, x4,y4]
  await page.mouse.click((q[0] + q[4]) / 2, (q[1] + q[5]) / 2);
  return pick;
}

// Inline dropdown mount: the host div the content script appends.
const HOST_ATTR = "data-baluard-inline";

// The content script registers at document_idle, which ad-heavy pages can
// delay for many seconds; wait for the mount, with one reload retry.
async function waitHostMounted(page, label) {
  const mounted = () => document.querySelectorAll("[data-baluard-inline]").length > 0;
  for (const attempt of [1, 2]) {
    try {
      await page.waitForFunction(mounted, undefined, { timeout: 20000, polling: 300 });
      return;
    } catch {
      if (attempt === 2) break;
      await page.reload({ waitUntil: "domcontentloaded", timeout: 60000 });
      await page.focus("input").catch(() => {});
    }
  }
  throw new Error(`inline content script never mounted (${label})`);
}

// Wait until the page predicate holds; the error carries the live page text
// so a failure is diagnosable from the log alone.
async function pageWait(page, fn, timeoutMs, label) {
  try {
    await page.waitForFunction(fn, undefined, { timeout: timeoutMs, polling: 200 });
  } catch {
    let text = "";
    try { text = (await page.textContent("body"))?.slice(0, 300) || ""; } catch {}
    throw new Error(`timeout waiting for: ${label}; url=${page.url()}; text=${JSON.stringify(text)}`);
  }
}

const ctx = await chromium.launchPersistentContext(PROFILE_DIR, {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT_DIR}`,
    `--load-extension=${EXT_DIR}`,
    `--remote-debugging-port=${CDP_PORT}`,
  ],
});
try {
  const sw =
    ctx.serviceWorkers().find((w) => w.url().includes(EXT_ID)) ||
    (await ctx.waitForEvent("serviceworker", { timeout: 15000 }));
  if (!sw.url().includes(EXT_ID)) fail(`unexpected worker ${sw.url()}`);
  const swLogs = [];
  sw.on("console", (m) => swLogs.push(m.text()));

  const version = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`)).json();
  const cdp = await PopupCdp.connect(version.webSocketDebuggerUrl);

  const openPopup = async () => {
    await sw.evaluate(() => chrome.action.openPopup());
    await new Promise((r) => setTimeout(r, 800));
    await cdp.attachPopup();
    return cdp;
  };

  // ---- Pairing ceremony (identical to Ring 1's pw.mjs) — skipped when the
  // profile is already paired (pw.mjs runs first against the same profile).
  const popup = await openPopup();
  await popup.waitForText("Baluard");
  const body = await popup.eval("document.body.innerText");
  if (body.includes("Welcome to Baluard")) {
    await popup.clickButton("I have Baluard installed");
    await popup.waitForText("Link this browser to the Baluard app");
    const started = await desktop("bridge.pair_start", JSON.stringify({ browser: "chromium" }));
    const code = JSON.parse(started).pair_code;
    if (!code || code.length !== 8) fail(`bad pair code: ${started}`);
    await popup.fillInput(".pair-code-input", code);
    await popup.clickButton("Connect to Baluard");
    await popup.waitForText("Waiting for approval");
    await desktop("bridge.pair_approve", "{}");
    await popup.waitForText("No logins for this site");
    console.log("PASS pairing");
  } else if (body.includes("No logins for this site")) {
    console.log("PASS pairing (already paired)");
  } else {
    fail(`unexpected popup state: ${JSON.stringify(body.slice(0, 120))}`);
  }

  // ---- Leg A: practice-site login via the inline dropdown.
  const pageA = await ctx.newPage();
  await pageA.goto(PRACTICE_URL, { waitUntil: "domcontentloaded", timeout: 60000 });
  // focus() rather than a click: ad iframes can cover the field and make a
  // click race; the icon only needs the focusin event.
  await pageA.focus("#username");
  const clientA = await pageA.context().newCDPSession(pageA);
  await waitHostMounted(pageA, "practice login");
  await clickShadowNode(pageA, clientA, HOST_ATTR, "icon");
  await clickShadowNode(pageA, clientA, HOST_ATTR, "entry", "Practice Portal");
  await pageWait(
    pageA,
    () =>
      document.querySelector("#username")?.value === "student" &&
      document.querySelector("#password")?.value === "Password123",
    8000,
    "inline fill of the practice login form"
  );
  await pageA.click("#submit");
  await pageWait(
    pageA,
    () => document.body.innerText.includes("Logged In Successfully"),
    25000,
    "practice-site successful login"
  );
  console.log("PASS practice login fill");
  await pageA.close();

  // ---- Leg B: 2FA demo - password leg, then the TOTP challenge.
  const pageB = await ctx.newPage();
  await pageB.goto(DEMO_URL, { waitUntil: "domcontentloaded", timeout: 60000 });
  await pageB.focus("#username");
  const clientB = await pageB.context().newCDPSession(pageB);
  await waitHostMounted(pageB, "demo login");
  await clickShadowNode(pageB, clientB, HOST_ATTR, "icon");
  await clickShadowNode(pageB, clientB, HOST_ATTR, "entry", "2FA Demo");
  await pageWait(
    pageB,
    () =>
      document.querySelector("#username")?.value === "user1" &&
      document.querySelector("input[type=password]")?.value === "test",
    8000,
    "inline fill of the demo login form"
  );
  await pageB.click("button:has-text('Login')");
  await pageWait(
    pageB,
    () => document.body.innerText.includes("Two-Factor Authentication"),
    15000,
    "demo 2FA challenge page"
  );
  await pageB.focus("#_auth_code");
  await waitHostMounted(pageB, "demo 2fa");
  await clickShadowNode(pageB, clientB, HOST_ATTR, "icon");
  await clickShadowNode(pageB, clientB, HOST_ATTR, "entry", "2FA Demo");
  await pageWait(
    pageB,
    () => /^\d{6}$/.test(document.querySelector("#_auth_code")?.value || ""),
    8000,
    "daemon-computed TOTP code filled into the one-time-code field"
  );
  await pageB.locator("#_auth_code").press("Enter");
  await pageWait(
    pageB,
    () => document.body.innerText.includes("Local 2FA OK"),
    15000,
    "2FA accepted by the local verifier"
  );
  console.log("PASS 2fa totp fill");
  await pageB.close();
  demoServer.close();

  console.log("RING2=0");
} catch (e) {
  console.error(`FAIL: ${e.message}`);
  process.exitCode = 1;
} finally {
  await ctx.close().catch(() => {});
}
