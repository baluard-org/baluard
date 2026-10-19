// Firefox-extension e2e: real Firefox + real NMH + real daemon.
//
// Ring 1 of docs/e2e-testing.md Phase 4 on Firefox. geckodriver installs the
// unpacked Firefox dist as a temporary add-on; the popup page then runs as a
// TAB (moz-extension://<uuid>/popup.html). Firefox marks extension pages in
// tabs with sender.tab set, so background.js's B4 split classifies senders
// by ORIGIN (sender.id + extension-origin url), not by surface — our own
// popup page routes fully while web-page content scripts stay inline-only.
// Driving is plain WebDriver content-context script.
//
// Boundary vs the Chromium ring (documented, not a bug): the popup tab sees
// itself as the active tab, so its boot-time match pass is empty by design —
// matches are asserted with an explicit-url bridge.match probe through the
// same popup->SW->NMH->daemon chain. The toolbar badge is a toolbar-surface
// feature and is not asserted in tab mode; Chromium's ring covers it.

import { gatewayRequest } from "./gateway.mjs";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const TOKEN = process.env.DESKTOP_TOKEN;
const SOCKET = process.env.DAEMON_SOCKET;
const SITE_URL = process.env.SITE_URL;
const FF_DIST = process.env.FF_DIST;
const EXT_ID = "baluard@actitud.xyz";

const fail = (m) => {
  // Throw, never process.exit: exit() would skip the finally block that
  // tears the WebDriver session down. The top-level catch turns this into
  // the exit code.
  console.error(`FAIL: ${m}`);
  process.exitCode = 1;
  throw new Error(m);
};
const missing = Object.entries({ TOKEN, SOCKET, SITE_URL, FF_DIST })
  .filter(([, v]) => !v)
  .map(([k]) => k);
if (missing.length) fail(`env missing: ${missing.join(",")}`);
if (!fs.existsSync(FF_DIST)) fail(`firefox dist not found at ${FF_DIST}`);

const desktop = (action, payload) => gatewayRequest(SOCKET, { action, payload, token: TOKEN });

// Local "site": an http origin the seeded login's URI matches (same shape
// as the Chromium ring's pw.mjs server).
const site = createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  res.end("<html><body><h1>Ext E2E Site</h1></body></html>");
});
await new Promise((r) => site.listen(new URL(SITE_URL).port, "127.0.0.1", r));
// Never hold the process open: a green flow must exit promptly even though
// the server is never explicitly closed.
site.unref();

// ---- geckodriver lifecycle (headless session).
let port = 30000 + Math.floor(Math.random() * 20000);
const driverBin = process.env.GECKODRIVER || path.resolve(".tools/geckodriver");
if (!fs.existsSync(driverBin)) fail(`geckodriver not found at ${driverBin}`);
const driver = spawn(driverBin, ["--port", String(port)], { stdio: ["ignore", "ignore", "ignore"] });
process.on("exit", () => driver.kill("SIGTERM"));
for (let i = 0; i < 50; i++) {
  try {
    if ((await fetch(`http://127.0.0.1:${port}/status`)).ok) break;
  } catch {}
  await new Promise((r) => setTimeout(r, 200));
}

let sid = null;
async function req(method, cmd, body) {
  const r = await fetch(`http://127.0.0.1:${port}${cmd}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body ?? {}),
  });
  const j = await r.json().catch(() => ({}));
  if (j && j.value && j.value.error) throw new Error(`${j.value.error}: ${j.value.message}`);
  return j.value;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

sid = (
  await req("POST", "/session", {
    capabilities: {
      alwaysMatch: {
        browserName: "firefox",
        "moz:firefoxOptions": {
          // -remote-allow-system-access gates moz/context (chrome script),
          // used only to resolve the extension uuid below.
          args: [
            "-headless",
            "-remote-allow-system-access",
            ...(process.env.FF_PROFILE ? ["-profile", process.env.FF_PROFILE] : []),
          ],
          prefs: {
            "xpinstall.signatures.required": false,
            "extensions.autoDisableScopes": 0,
            "browser.shell.checkDefaultBrowser": false,
            "datareporting.policy.dataSubmissionEnabled": false,
            "toolkit.telemetry.enabled": false,
            "app.update.enabled": false,
          },
        },
      },
    },
  })
).sessionId;
const cleanupSession = async () => {
  // Best-effort teardown: a session delete can hang on a wedged Firefox
  // shutdown, and the harness must not outlive a green flow because of it —
  // cap the polite delete, then always kill the driver.
  try {
    await Promise.race([
      req("DELETE", `/session/${sid}`),
      new Promise((r) => setTimeout(r, 5000)),
    ]);
  } catch {}
  driver.kill("SIGTERM");
};
process.on("SIGTERM", cleanupSession);

try {
  // ---- Install the temporary add-on and resolve its moz-extension uuid.
  await req("POST", `/session/${sid}/moz/addon/install`, { path: FF_DIST, temporary: true });
  await req("POST", `/session/${sid}/url`, { url: "about:blank" });
  await req("POST", `/session/${sid}/moz/context`, { context: "chrome" });
  // Add-on registration is asynchronous: poll instead of a fixed sleep so a
  // slow runner cannot null the lookup.
  let uuid = null;
  for (let i = 0; i < 30 && !uuid; i++) {
    await sleep(300);
    uuid = await req("POST", `/session/${sid}/execute/sync`, {
      script: `
        const { ExtensionParent } = ChromeUtils.importESModule("resource://gre/modules/ExtensionParent.sys.mjs");
        const ext = ExtensionParent.GlobalManager.getExtension(${JSON.stringify(EXT_ID)});
        return ext ? ext.uuid : null;
      `,
      args: [],
    });
  }
  if (!uuid) fail("extension uuid not found");
  await req("POST", `/session/${sid}/moz/context`, { context: "content" });

  // ---- Open the popup page as a tab.
  await req("POST", `/session/${sid}/url`, { url: `moz-extension://${uuid}/popup.html` });

  const exec = (script, args = []) =>
    req("POST", `/session/${sid}/execute/sync`, { script, args });

  const waitText = async (needle, timeoutMs = 15000) => {
    for (let i = 0; i < timeoutMs / 300; i++) {
      const hit = await exec(
        `return document.body && document.body.innerText.includes(${JSON.stringify(needle)});`,
      );
      if (hit) return;
      await sleep(300);
    }
    const body = await exec("return document.body ? document.body.innerText.slice(0, 300) : 'no-body';");
    fail(`'${needle}' never appeared. Body: ${JSON.stringify(body)}`);
  };
  const clickButton = async (label) => {
    const ok = await exec(
      `const b = Array.from(document.querySelectorAll("button")).find((b) => b.textContent.trim() === ${JSON.stringify(label)});
       if (!b) return false; b.click(); return true;`,
    );
    if (!ok) fail(`button not found: ${label}`);
  };
  const fillInput = async (selector, value) => {
    const ok = await exec(
      `const i = document.querySelector(${JSON.stringify(selector)});
       if (!i) return false;
       i.value = ${JSON.stringify(value)};
       i.dispatchEvent(new Event("input", { bubbles: true }));
       return i.value === ${JSON.stringify(value)};`,
    );
    if (!ok) fail(`fill did not land: ${selector}`);
  };

  // ---- Pairing ceremony: welcome -> code -> held pair_complete -> approve.
  await waitText("Welcome to Baluard");
  await clickButton("I have Baluard installed");
  await waitText("Link this browser to the Baluard app");

  const started = await desktop("bridge.pair_start", JSON.stringify({ browser: "firefox" }));
  const code = JSON.parse(started).pair_code;
  if (!code || code.length !== 8) fail(`bad pair code: ${started}`);

  await fillInput(".pair-code-input", code);
  await clickButton("Connect to Baluard");
  await waitText("Waiting for approval");
  await desktop("bridge.pair_approve", "{}");
  // The popup tab sees itself as the active (non-web) tab: ready shows the
  // empty state.
  await waitText("No logins for this site");
  console.log("PASS pairing");

  // ---- Matched entries: explicit-url bridge.match from the popup page rides
  // the same popup->SW->NMH->daemon chain the real popup uses.
  const matchesJson = await exec(
    `return new Promise((resolve) => {
       chrome.runtime.sendMessage(
         { action: "bridge.match", payload: { url: ${JSON.stringify(SITE_URL)} } },
         (resp) => resolve(resp && resp.ok ? resp.payload : "ERR:" + JSON.stringify(resp)),
       );
     });`,
  );
  if (String(matchesJson).startsWith("ERR:")) fail(`bridge.match failed: ${matchesJson}`);
  const data = JSON.parse(matchesJson || "{}");
  const names = (data.matches || []).map((m) => m.name);
  if (!names.includes("Ext Bank")) fail(`matches missing 'Ext Bank': ${JSON.stringify(data.matches)}`);
  const user = (data.matches || []).find((m) => m.name === "Ext Bank")?.username;
  if (user !== "u@ext.test") fail(`username mismatch: ${JSON.stringify(user)}`);
  console.log("PASS matches");
  console.log("PASS firefox ring");
} catch (e) {
  console.error(`FAIL: ${e.message}`);
  process.exitCode = 1;
} finally {
  await cleanupSession();
}
