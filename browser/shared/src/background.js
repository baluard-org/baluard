// Background service worker (MV3).
//
// Owns the single long-lived native-messaging port to `baluard-nmh`,
// multiplexes {id}-tagged requests, runs the version handshake on connect,
// and routes popup/content-script messages.
//
// Per Decision 2: holds NO secrets in chrome.storage beyond transient request
// IDs. The bridge token lives in the NMH's memory, never here.

import { normalizeClearSeconds } from "./settings.js";
import { originOf } from "./url.js";

const NMH_HOST = "xyz.actitud.baluard"; // matches the host manifest `name`
const MIN_NMH_VERSION = "0.1.0";

let port = null;
let pending = new Map(); // id -> {resolve, reject}
let nextId = 1;
let versionInfo = null;
// B7: fail closed until the connect-time ping handshake proves the NMH is
// current. Cleared ONLY in the ping-success branch; a missing, slow, or
// stale host leaves it true and every non-ping send refuses.
let versionSkew = true;
// Settles once per connection when the handshake ping resolves, fails, or
// times out. Non-ping sends queue on it (see send()).
let handshake = null;
const HANDSHAKE_TIMEOUT_MS = 5000;

// Last native-messaging disconnect reason (from chrome.runtime.lastError).
// Surfaced to the popup so the user isn't staring at a generic failure.
// Chromium sets lastError on disconnect with the real cause, e.g.
// "Specified native messaging host not found" or
// "Access to the specified native messaging host is forbidden".
let lastDisconnectReason = null;

function connect() {
  try {
    port = chrome.runtime.connectNative(NMH_HOST);
  } catch (e) {
    port = null;
    return;
  }
  port.onMessage.addListener(onMessage);
  port.onDisconnect.addListener(() => {
    // Chrome populates lastError with the *reason* the host failed to start.
    const reason = chrome.runtime.lastError?.message || "disconnected";
    lastDisconnectReason = reason;
    console.error("[baluard] NMH disconnected:", reason);
    port = null;
    // Reject all in-flight; the popup will see failures + reconnect on next action.
    for (const { reject } of pending.values()) {
      try {
        const e = new Error(reason);
        e.code = classifyDisconnect(reason);
        reject(e);
      } catch (_) {}
    }
    pending.clear();
  });
  // Version handshake immediately on connect. Hard-fail closed on
  // skew: a password manager must never silently run a
  // partially-understood protocol.
  // B7: the handshake promise gates every non-ping send. Until it settles,
  // actions queue instead of racing an unverified host; if the ping fails
  // or times out, queued actions reject with the cannot-reach error.
  handshake = withTimeout(
    send("ping", {}).then((r) => {
      versionInfo = r;
      // ping's payload is a JSON string like {"nmh_version":"0.1.0",...}.
      let nmh = "0.0.0";
      try {
        const raw = typeof r === "string" ? r : (r && r.payload);
        const parsed = JSON.parse(raw);
        nmh = parsed.nmh_version || "0.0.0";
      } catch (_) {}
      if (compareVersions(nmh, MIN_NMH_VERSION) < 0) {
        versionSkew = true;
        console.error(
          `[baluard] NMH version ${nmh} < required ${MIN_NMH_VERSION}. Extension disabled until the Baluard desktop app is updated.`
        );
      } else {
        versionSkew = false;
      }
    }),
    HANDSHAKE_TIMEOUT_MS
  );
}

function onMessage(msg) {
  if (!msg || msg.id == null) return;
  const entry = pending.get(msg.id);
  if (!entry) {
    return;
  }
  pending.delete(msg.id);
  if (msg.ok) entry.resolve(msg);
  else entry.reject(buildError(msg));
}

function buildError(msg) {
  const e = new Error(msg.error || "unknown");
  e.code = msg.code || "proto";
  return e;
}

// Exported for unit tests; not used outside the SW module otherwise.
export { buildError, send };

function send(action, payload) {
  return new Promise((resolve, reject) => {
    if (!port) {
      // Try (re)connect once.
      connect();
    }
    if (!port) {
      reject(err("Cannot reach the Baluard app. Is it running?", "no-daemon"));
      return;
    }
    // B7: single choke point for the version gate — covers direct send()
    // callers (badge, inline handlers), not just the onMessage route.
    const dispatch = () => {
      if (action !== "ping" && versionSkew) {
        reject(
          err("Baluard desktop app is out of date. Update it to use the extension.", "version-skew")
        );
        return;
      }
      const id = nextId++;
      pending.set(String(id), { resolve, reject });
      port.postMessage({
        id: String(id),
        action,
        payload: typeof payload === "string" ? payload : JSON.stringify(payload),
      });
    };
    // B7: queue non-ping traffic until the handshake settles.
    if (action !== "ping" && handshake) {
      handshake.then(dispatch, reject);
    } else {
      dispatch();
    }
  });
}

// Map a Chromium native-messaging disconnect reason to a friendly code.
// "not found" / "forbidden" => no-daemon (manifest missing or NMH not installed).
// Anything else stays generic but the raw reason travels in the message.
export function classifyDisconnect(reason) {
  const r = (reason || "").toLowerCase();
  if (r.includes("not found") || r.includes("forbidden")) return "no-daemon";
  return "nmh-error";
}

function err(message, code) {
  const e = new Error(message);
  e.code = code;
  return e;
}

// B7: reject with the cannot-reach error after `ms` unless `promise`
// settles first. Covers the handshake ping stalling forever against a
// half-started or hung NMH.
function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(err("Cannot reach the Baluard app. Is it running?", "no-daemon")),
      ms
    );
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ── Inline autofill: sender-gated routes ──
// The inline content script runs IN the page's principal. Everything it asks
// for must be gated on the SENDER (privileged tab metadata Chrome attaches),
// never on anything the message payload claims. A hostile page cannot forge
// these messages (no externally_connectable), but our own injected script is
// reachable from page-influenced events — so the rules are:
//   inline.matches -> match against sender.tab.url ONLY.
//   inline.fill    -> fetch the credential, then PUSH it to the requesting
//                     tab as baluard-inline-fill with expectedOrigin derived
//                     from sender.tab.url. It is NEVER returned as the
//                     message response (a page-compromised handler must not
//                     be able to read the credential out of a response).

// Extract the trustworthy URL for a content-script sender. Returns "" when
// the sender is not a tab or the URL is not a normal web page (fail closed).
export function senderUrl(sender) {
  const url = sender && sender.tab && sender.tab.url;
  if (!url) return "";
  if (!url.startsWith("http://") && !url.startsWith("https://")) return "";
  return url;
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

// B1: fill-time origin is scheme+host+port (originOf, shared in url.js).
// A credential saved on https://example.com must NOT fill on
// http://example.com — a network attacker can serve the plain-HTTP page
// and read the typed password. Content scripts compare location.origin.

async function handleInlineMatches(sender) {
  const url = senderUrl(sender);
  if (!url) throw err("no matching tab", "no-match");
  const r = await send("bridge.match", { url });
  let data = {};
  try {
    data = JSON.parse(r.payload || "{}");
  } catch {
    data = {};
  }
  // B4 projection, G24: the merged match response carries a vaults
  // array and display names for popup chips; the PAGE principal gets
  // match fields only. Vault names never cross to inline; it learns
  // at most that more than one vault contributed.
  const matches = (data.matches || []).map((m) => ({
    id: m.id,
    name: m.name,
    username: m.username,
    favorite: m.favorite,
    vault_slug: m.vault_slug,
  }));
  return JSON.stringify({
    matches,
    multiVault: new Set(matches.map((m) => m.vault_slug).filter(Boolean)).size > 1,
  });
}

async function handleInlineFill(sender, id, mode, hasTotpField, vaultSlug) {
  const url = senderUrl(sender);
  if (!url) throw err("no matching tab", "no-match");
  if (typeof id !== "string" || id.length === 0) throw err("missing id", "proto");
  // Code-only mode (2FA page): the push carries NO login secrets. Payload
  // minimization happens HERE, in the SW — never trusted to the content
  // script's discretion (B4: gate on what crosses the boundary).
  const totpOnly = mode === "totp";
  let cred = {};
  if (!totpOnly) {
    // Fetch the single credential (Decision 7 allowlist: one at a time).
    // B3: the page URL rides along so the DAEMON enforces the URI match
    // server-side with the same matcher bridge.match uses — a compromised
    // extension page cannot fetch a credential for an unrelated site.
    const r = await send("vault.get", { id, url, vault_slug: vaultSlug || "" });
    try {
      cred = JSON.parse(r.payload || "{}");
    } catch {
      cred = {};
    }
  }
  // Produce a TOTP code when the page can consume it, when the user asked
  // for code-only fill, or when copyTotp is on AND the entry actually has
  // TOTP (Bitwarden-style: the code rides the clipboard to step 2 of a
  // two-step login). Entries without TOTP are never probed.
  const copyTotp = await settingEnabled("copyTotp");
  const wantsTotp =
    totpOnly || hasTotpField === true || (copyTotp && Boolean(cred.totp));
  let totpCode = "";
  let copied = false;
  let clipboardFallback = false;
  if (wantsTotp) {
    try {
      const t = await send("cipher.totp_code", { id, url, vault_slug: vaultSlug || "" });
      totpCode = JSON.parse(t.payload || "{}").code || "";
    } catch {
      totpCode = "";
    }
    // The SW owns the clipboard write: the code never round-trips through a
    // content-script message to get copied (B1-B8 pattern). Firefox has no
    // offscreen doc, so signal the fallback and let inline.js write directly.
    if (totpCode && copyTotp) {
      try {
        const res = await clipboardCopy(totpCode);
        if (res === "fallback") clipboardFallback = true;
        else copied = true;
      } catch {
        copied = false;
      }
    }
  }
  const expectedOrigin = originOf(url);
  const payload = totpOnly
    ? { kind: "totp", expectedOrigin, totpCode, copied, clipboardFallback }
    : {
        kind: "login",
        expectedOrigin,
        credential: {
          username: cred.username || "",
          password: cred.password || "",
          totpCode,
        },
        copied,
        clipboardFallback,
      };
  // Push the fill to the requesting tab only (B5: pinned to the exact
  // frame the request came from). Content script re-checks the ORIGIN at
  // fill time (fill-time origin re-check, Decision 9).
  chrome.tabs.sendMessage(
    sender.tab.id,
    { type: "baluard-inline-fill", ...payload },
    { frameId: sender.frameId ?? 0 }
  );
  return JSON.stringify({ filled: true });
}

// semver-ish compare (only needs major.minor.patch). Returns <0, 0, >0.
export function compareVersions(a, b) {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x - y;
  }
  return 0;
}

// ── Popup / content-script message routing ──
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.action !== "string") return;

  // B4 privilege split, enforced BEFORE anything else:
  //   sender.tab present           => content script inside a page
  //                                  principal. ONLY the two inline routes
  //                                  are allowed; everything else is dropped
  //                                  (a page-compromised path must not reach
  //                                  vault.get/vault.add from a tab).
  //   sender.id === extension id   => extension-owned page (popup/offscreen).
  //                                  Full routing.
  //   anything else                => dropped.
  const fromContentScript = !!(sender && sender.tab);
  const fromExtensionPage =
    !fromContentScript && sender && sender.id === chrome.runtime.id;
  if (!fromContentScript && !fromExtensionPage) {
    console.warn("[baluard-sw] dropped message from unknown sender");
    return false;
  }
  if (
    fromContentScript &&
    msg.action !== "inline.matches" &&
    msg.action !== "inline.fill"
  ) {
    console.warn(
      "[baluard-sw] dropped non-inline action from content script:",
      msg.action
    );
    return false;
  }

  // B7: the version-skew gate now lives inside send() (single choke point
  // covering direct callers too). Non-ping actions route through it and
  // surface code "version-skew" from there.
  // Local action: clipboard copy via offscreen document (service worker has
  // no DOM). Auto-clears after 20s (review M2). Extension pages only — the
  // B4 split above already dropped any content-script clipboard-copy.
  if (msg.action === "clipboard-copy") {
    clipboardCopy(msg.text)
      .then((r) =>
        sendResponse(r === "fallback" ? { ok: true, fallback: true } : { ok: true })
      )
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  // Inline autofill routes (sender-gated; see handleInline* above).
  // B2: `sender` is now actually bound — the parameter used to be named
  // `_sender`, so these routes threw ReferenceError and never ran.
  if (msg.action === "inline.matches" && sender && sender.tab) {
    handleInlineMatches(sender)
      .then((payload) => sendResponse({ ok: true, payload }))
      .catch((e) => sendResponse({ ok: false, error: e.message, code: e.code }));
    return true;
  }
  if (msg.action === "inline.fill" && sender && sender.tab) {
    handleInlineFill(sender, msg.id, msg.mode, msg.hasTotpField, msg.vault_slug)
      .then((payload) => sendResponse({ ok: true, payload }))
      .catch((e) => sendResponse({ ok: false, error: e.message, code: e.code }));
    return true;
  }
  send(msg.action, msg.payload || {})
    .then((r) => sendResponse({ ok: true, payload: r.payload }))
    .catch((e) => sendResponse({ ok: false, error: e.message, code: e.code }));
  return true; // async
});

// ── Clipboard via offscreen document (review M2) ──
// The service worker has no DOM, so navigator.clipboard is unavailable. We
// create a hidden offscreen document that writes to the clipboard; the
// offscreen doc owns the auto-clear timer (configurable, see
// clipboardClearSeconds) and survives SW restarts.

async function clipboardCopy(text) {
  // B8: Firefox has no chrome.offscreen. The copy must run in the popup
  // context (user gesture + document focus satisfy navigator.clipboard);
  // signal the fallback to the caller instead of throwing.
  if (!chrome.offscreen || !chrome.offscreen.createDocument) {
    return "fallback";
  }
  const clearSeconds = await getClipboardClearSeconds();
  await ensureOffscreen();
  await chrome.runtime.sendMessage({
    action: "offscreen-copy",
    target: "offscreen",
    text,
    clearSeconds,
  });
}

async function ensureOffscreen() {
  const existing = await chrome.offscreen?.hasDocument?.();
  if (existing) return;
  await chrome.offscreen.createDocument({
    url: "offscreen.html",
    reasons: ["CLIPBOARD"],
    justification: "Copy passwords/TOTP from the popup; service worker has no DOM.",
  });
}

// ── Toolbar badge: match count for the active tab ──
// Pure browser-native badge API; zero DOM injection, zero attack surface.
// Updates on tab activation + navigation. Queries bridge.match for the URL.
// Debounced: a burst of tab updates (slow-loading page firing many progress
// events) collapses to one lookup.
let badgeTimer = null;
function updateBadgeForTab(tabId, url) {
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  if (badgeTimer) clearTimeout(badgeTimer);
  badgeTimer = setTimeout(() => {
    send("bridge.match", { url })
      .then((payload) => {
        const data = JSON.parse(payload || "{}");
        const n = (data.matches || []).length;
        chrome.action.setBadgeText({ tabId, text: n > 0 ? String(n) : "" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#0a7" });
      })
      .catch(() => {
        chrome.action.setBadgeText({ tabId, text: "" });
      });
  }, 250);
}

chrome.tabs?.onActivated?.addListener((info) => {
  chrome.tabs.get(info.tabId, (tab) => {
    if (chrome.runtime.lastError) return;
    updateBadgeForTab(info.tabId, tab.url);
  });
});

chrome.tabs?.onUpdated?.addListener((tabId, change, tab) => {
  if (change.url && tab.active) {
    updateBadgeForTab(tabId, change.url);
  }
});

// ── Inline autofill: dynamic content-script registration ──
// The inline dropdown script is registered ONLY while the inlineAutofill
// setting is on, and persists across sessions (no re-registration dance on
// every SW wake). Zero page surface when the setting is off.
// Top-frame only (allFrames: false — Decision 9 C3/D1).
const INLINE_SCRIPT_ID = "baluard-inline";
const SETTINGS_KEY = "settings";

// Read a boolean setting, default ON (mirrors DEFAULT_SETTINGS in
// settings.js: absent key means enabled).
async function readSettings() {
  try {
    return await chrome.storage.local
      .get([SETTINGS_KEY])
      .then((r) => r[SETTINGS_KEY] || {});
  } catch {
    return {};
  }
}

async function settingEnabled(name) {
  const settings = await readSettings();
  return settings[name] !== false;
}

// Clipboard auto-clear seconds, validated by settings.js
// normalizeClearSeconds. background.js is esbuild-bundled (see
// vite.config.js), so importing the shared helper is safe.
async function getClipboardClearSeconds() {
  try {
    return normalizeClearSeconds((await readSettings()).clipboardClearSeconds);
  } catch {
    return 60;
  }
}

async function syncInlineScript() {
  if (!chrome.scripting?.registerContentScripts) return; // API unavailable
  const settings = await readSettings();
  // Default ON (settings.js DEFAULT_SETTINGS mirrors this).
  const enabled = settings.inlineAutofill !== false;
  try {
    const registered = await chrome.scripting.getRegisteredContentScripts();
    const exists = registered.some((s) => s.id === INLINE_SCRIPT_ID);
    if (enabled && !exists) {
      await chrome.scripting.registerContentScripts([
        {
          id: INLINE_SCRIPT_ID,
          js: ["inline.js"],
          matches: ["http://*/*", "https://*/*"],
          runAt: "document_idle",
          allFrames: false,
          persistAcrossSessions: true,
        },
      ]);
    } else if (!enabled && exists) {
      await chrome.scripting.unregisterContentScripts({ ids: [INLINE_SCRIPT_ID] });
    }
  } catch (e) {
    console.error("[baluard] inline script sync failed:", e);
  }
}

chrome.storage?.onChanged?.addListener((changes, area) => {
  if (area === "local" && changes[SETTINGS_KEY]) syncInlineScript();
});

// Connect on worker start.
connect();
syncInlineScript();
