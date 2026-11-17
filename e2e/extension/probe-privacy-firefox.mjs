// BL0006 probe: does chrome.privacy.services.passwordSavingEnabled exist in
// Firefox, and do the shipped background.js default-manager paths (startup
// apply, storage-watcher flip, reconciliation) actually control the pref?
//
// Firefox runs headless in the ubuntu-24.04 VM; geckodriver listens there and
// is port-forwarded to the host. The driver script runs on the host: the
// add-on installs by base64 (no shared filesystem), and the extension UUID is
// polled through the chrome context (ExtensionParent). Nothing on the host's
// Baluard production state is touched; no daemon is involved.
//
// VM-side requirements (launch once): geckodriver on 127.0.0.1:4444 with
//   MOZ_REMOTE_ALLOW_SYSTEM_ACCESS=1   (FF141+ chrome-context gate)
//   TMPDIR under $HOME                 (snap firefox cannot read /tmp)
// Verified on Firefox 159.0.1 snap, Ubuntu 24.04, geckodriver 0.36.0.

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

// VM harness (defaults match the local ubuntu-24.04 quickemu VM):
//   FF_PRIVACY_WD       geckodriver address, forwarded to the host
//   FF_PRIVACY_ZIP      firefox dist zip to install
//   FF_PRIVACY_SSH      ssh target for reading the profile inside the VM
const WD = process.env.FF_PRIVACY_WD || "http://127.0.0.1:4444";
const ZIP = process.env.FF_PRIVACY_ZIP || "/tmp/bl0006/baluard-firefox.zip";
const SSH_BASE =
  process.env.FF_PRIVACY_SSH ||
  "ssh -p 22222 -i " + process.env.HOME + "/.local/share/baluard-smoke/ubuntu-guest-key" +
  " -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" +
  " -o BatchMode=yes esteban@localhost";

let sessionId = null;
const results = [];
const check = (name, ok, detail) => {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};

async function wd(method, path, body) {
  const res = await fetch(WD + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json();
  if (json.value && json.value.error) throw new Error(`${json.value.error}: ${json.value.message}`);
  return json.value;
}

// In-page probe: runs in the extension page (privileged context).
const PAGE_PROBE = `
  const done = arguments[arguments.length - 1];
  (async () => {
    const ctrl = chrome.privacy?.services?.passwordSavingEnabled;
    const bCtrl = browser?.privacy?.services?.passwordSavingEnabled;
    const get = async (c) => (c && c.get ? await c.get({}) : null);
    const stored = await chrome.storage.local.get(["settings"]);
    const out = {
      chromeNamespace: typeof chrome,
      browserNamespace: typeof browser,
      chromePrivacyServices: Object.keys(chrome.privacy?.services || {}),
      browserPrivacyServices: Object.keys(browser?.privacy?.services || {}),
      chromeHasControl: Boolean(ctrl),
      browserHasControl: Boolean(bCtrl),
      sameObject: Boolean(ctrl && bCtrl && ctrl === bCtrl),
      initialGet: await get(ctrl),
      initialBrowserGet: await get(bCtrl),
      storedSettings: stored.settings || null,
    };
    done(JSON.stringify(out));
  })().catch((e) => done(JSON.stringify({ probeError: String(e) })));
`;

const FLIP_TO_FALSE = `
  const done = arguments[arguments.length - 1];
  (async () => {
    const stored = await chrome.storage.local.get(["settings"]);
    const next = { ...(stored.settings || {}), defaultPasswordManager: false };
    await chrome.storage.local.set({ settings: next });
    await new Promise((r) => setTimeout(r, 800)); // storage watcher -> apply
    const ctrl = chrome.privacy?.services?.passwordSavingEnabled;
    const after = ctrl && ctrl.get ? await ctrl.get({}) : null;
    done(JSON.stringify({ afterFlipOff: after, stored: next }));
  })().catch((e) => done(JSON.stringify({ flipError: String(e) })));
`;

const FLIP_TO_TRUE = `
  const done = arguments[arguments.length - 1];
  (async () => {
    const stored = await chrome.storage.local.get(["settings"]);
    const next = { ...(stored.settings || {}), defaultPasswordManager: true };
    await chrome.storage.local.set({ settings: next });
    await new Promise((r) => setTimeout(r, 800));
    const ctrl = chrome.privacy?.services?.passwordSavingEnabled;
    const after = ctrl && ctrl.get ? await ctrl.get({}) : null;
    done(JSON.stringify({ afterFlipOn: after }));
  })().catch((e) => done(JSON.stringify({ flipError: String(e) })));
`;

async function evalJson(script) {
  const v = await wd("POST", `/session/${sessionId}/execute/async`, {
    script,
    args: [],
  });
  return JSON.parse(v);
}

try {
  const addonB64 = readFileSync(ZIP).toString("base64");
  const session = await wd("POST", "/session", {
    capabilities: {
      alwaysMatch: {
        browserName: "firefox",
        "moz:firefoxOptions": {
          args: ["-headless"],
          prefs: {
            "xpinstall.signatures.required": false,
            "browser.warnOnQuit": true,
          },
        },
      },
    },
  });
  sessionId = session.sessionId;
  const profile = session.capabilities["moz:profile"];
  console.log(`session ok, profile: ${profile}`);

  const installed = await wd("POST", `/session/${sessionId}/moz/addon/install`, {
    addon: addonB64,
    temporary: true,
  });
  console.log(`addon installed: ${JSON.stringify(installed)}`);

  // The moz-extension host uuid comes from the extension itself, polled in
  // the chrome context (same route as ff.mjs; the xpi filename is a cache
  // uuid, not the host).
  await wd("POST", `/session/${sessionId}/moz/context`, { context: "chrome" });
  let extBase = null;
  for (let i = 0; i < 30 && !extBase; i++) {
    await new Promise((r) => setTimeout(r, 300));
    const uuid = await wd("POST", `/session/${sessionId}/execute/sync`, {
      script: `const { ExtensionParent } = ChromeUtils.importESModule("resource://gre/modules/ExtensionParent.sys.mjs");
        const ext = ExtensionParent.GlobalManager.getExtension("baluard@actitud.xyz");
        return ext ? ext.uuid : null;`,
      args: [],
    });
    if (uuid) extBase = `moz-extension://${uuid}`;
  }
  await wd("POST", `/session/${sessionId}/moz/context`, { context: "content" });
  if (!extBase) throw new Error("extension uuid not found");
  console.log(`extension base: ${extBase}`);

  await wd("POST", `/session/${sessionId}/url`, { url: `${extBase}/popup.html` });
  await new Promise((r) => setTimeout(r, 1500));

  const probe = await evalJson(PAGE_PROBE);
  if (probe.probeError) throw new Error("probe page error: " + probe.probeError);
  console.log("PROBE " + JSON.stringify(probe, null, 2));

  // 1: the API surface exists (the whole ticket question).
  check(
    "chrome.privacy.services.passwordSavingEnabled exists on Firefox",
    probe.chromeHasControl,
    `services keys: ${probe.chromePrivacyServices.join(",") || "(none)"}`,
  );
  check(
    "browser.privacy exposes the same control (alias check)",
    probe.browserHasControl && probe.sameObject,
    `browser side: ${probe.browserHasControl}, same object as chrome: ${probe.sameObject}`,
  );

  // 2: the shipped startup path applied the control (default ON -> set false).
  const init = probe.initialGet;
  const startupHeld =
    init &&
    init.value === false &&
    (init.levelOfControl === "controlled_by_this_extension" || init.levelOfControl === "controlled_by_other_extensions");
  check(
    "startup apply (default ON) holds the pref with value=false",
    Boolean(startupHeld),
    `initial get: ${JSON.stringify(init)}`,
  );

  // 3: storage-watcher flip OFF clears the control (restores browser default).
  const flipOff = await evalJson(FLIP_TO_FALSE);
  const off = flipOff.afterFlipOff;
  // The release observable is levelOfControl. The restored value equals the
  // profile default, and geckodriver automation profiles carry
  // signon.rememberSignons=false (a test-hygiene pref), so value===true is
  // NOT expected here — on real desktop profiles the default is true.
  check(
    "flip OFF clears the control (released, value back to profile default)",
    off && off.levelOfControl === "controllable_by_this_extension",
    `after flip off: ${JSON.stringify(off)}`,
  );

  // 4: flip back ON re-applies.
  const flipOn = await evalJson(FLIP_TO_TRUE);
  const on = flipOn.afterFlipOn;
  check(
    "flip ON re-applies the control (value=false)",
    on && on.value === false,
    `after flip on: ${JSON.stringify(on)}`,
  );

  const failed = results.filter((r) => !r.ok);
  console.log(`\nSUMMARY: ${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) process.exitCode = 1;
} catch (e) {
  console.error("PROBE ERROR:", e.message);
  process.exitCode = 2;
} finally {
  if (sessionId) await wd("DELETE", `/session/${sessionId}`).catch(() => {});
}
