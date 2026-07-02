// Background service worker (MV3).
//
// Owns the single long-lived native-messaging port to `baluard-nmh`,
// multiplexes {id}-tagged requests, runs the version handshake on connect,
// and routes popup/content-script messages.
//
// Per Decision 2: holds NO secrets in chrome.storage beyond transient request
// IDs. The bridge token lives in the NMH's memory, never here.

const NMH_HOST = "xyz.actitud.baluard"; // matches the host manifest `name`
const MIN_NMH_VERSION = "0.1.0";

let port = null;
let pending = new Map(); // id -> {resolve, reject}
let nextId = 1;
let versionInfo = null;
let versionSkew = false; // review agy I6: hard-fail closed on NMH version skew

function connect() {
  try {
    port = chrome.runtime.connectNative(NMH_HOST);
  } catch (e) {
    port = null;
    return;
  }
  port.onMessage.addListener(onMessage);
  port.onDisconnect.addListener(() => {
    port = null;
    // Reject all in-flight; the popup will see failures + reconnect on next action.
    for (const { reject } of pending.values()) {
      try {
        reject(new Error("nmh-disconnected"));
      } catch (_) {}
    }
    pending.clear();
  });
  // Version handshake immediately on connect (review X5). Hard-fail closed on
  // skew (review agy I6): a password manager must never silently run a
  // partially-understood protocol.
  send("ping", {})
    .then((r) => {
      versionInfo = r;
      const nmh = (r && r.nmh_version) || "0.0.0";
      if (compareVersions(nmh, MIN_NMH_VERSION) < 0) {
        versionSkew = true;
        console.error(
          `[baluard] NMH version ${nmh} < required ${MIN_NMH_VERSION}. Extension disabled until the Baluard desktop app is updated.`
        );
      } else {
        versionSkew = false;
      }
    })
    .catch(() => {
      // NMH not installed / not reachable — surfaced to the popup on next action.
    });
}

function onMessage(msg) {
  if (!msg || msg.id == null) return;
  const entry = pending.get(msg.id);
  if (!entry) return;
  pending.delete(msg.id);
  if (msg.ok) entry.resolve(msg);
  else entry.reject(buildError(msg));
}

function buildError(msg) {
  const e = new Error(msg.error || "unknown");
  e.code = msg.code || "proto";
  return e;
}

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
    const id = nextId++;
    pending.set(id, { resolve, reject });
    port.postMessage({
      id: String(id),
      action,
      payload: typeof payload === "string" ? payload : JSON.stringify(payload),
    });
  });
}

function err(message, code) {
  const e = new Error(message);
  e.code = code;
  return e;
}

// semver-ish compare (only needs major.minor.patch). Returns <0, 0, >0.
function compareVersions(a, b) {
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
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg.action !== "string") return;
  // Version-skew gate: refuse everything except ping (review agy I6).
  if (versionSkew && msg.action !== "ping") {
    sendResponse({
      ok: false,
      error: "Baluard desktop app is out of date. Update it to use the extension.",
      code: "version-skew",
    });
    return false;
  }
  send(msg.action, msg.payload || {})
    .then((r) => sendResponse({ ok: true, payload: r.payload }))
    .catch((e) => sendResponse({ ok: false, error: e.message, code: e.code }));
  return true; // async
});

// Connect on worker start.
connect();
