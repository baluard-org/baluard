// Offscreen document: clipboard bridge for the service worker.
// The SW has no DOM, so navigator.clipboard lives here. This document also
// OWNS the auto-clear timer: it outlives service-worker restarts, and
// unlike chrome.alarms it can fire below Chrome's 30s alarm clamp.
//
// Messages from the SW (routed via chrome.runtime.sendMessage with
// target:"offscreen"):
//   offscreen-copy { text, clearSeconds } -> write text; clear after
//       clearSeconds (0 or absent = never)
//   offscreen-clear                       -> overwrite clipboard with a space

let clearTimer = null;

// Overwrite (not empty string) so clipboard managers record a space, not a
// captured secret, as the last history entry.
function scheduleClear(seconds) {
  if (clearTimer) clearTimeout(clearTimer);
  clearTimer = null;
  const s = Number(seconds);
  if (!Number.isFinite(s) || s <= 0) return;
  clearTimer = setTimeout(() => {
    clearTimer = null;
    writeClipboard(" ").catch(() => {});
  }, s * 1000);
}

// The async Clipboard API only writes from a FOCUSED document, and an
// offscreen document can never be focused (Chrome's own offscreen
// reference: "Offscreen documents can't be focused"). On Chrome 109-156
// navigator.clipboard.writeText() therefore rejects with
// "NotAllowedError: ... Document is not focused." and the secret never
// reaches the clipboard. document.execCommand("copy") is the supported
// path for an unfocused extension document, so it is the fallback; when
// the document somehow IS focused, writeText is tried first.
function writeClipboard(text) {
  const value = String(text ?? "");
  if (document.hasFocus?.() && navigator.clipboard?.writeText) {
    return navigator.clipboard
      .writeText(value)
      .catch((cause) => execCopy(value, cause));
  }
  return execCopy(value);
}

// Copy through a hidden textarea. execCommand is deprecated but still the
// only clipboard write that works from an unfocused extension document.
// The failing writeText rejection rides along so the surfaced error keeps
// its cause.
function execCopy(text, cause) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("aria-hidden", "true");
  ta.style.position = "fixed";
  ta.style.top = "-1000px";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  if (!ok) {
    const why = cause?.message ? `: ${cause.message}` : "";
    return Promise.reject(new Error(`clipboard write failed${why}`));
  }
  return Promise.resolve();
}

export function handleOffscreenMessage(msg, sender, sendResponse) {
  if (!msg || msg.target !== "offscreen") return;
  // B6: only this extension's own service worker may drive the clipboard.
  // Content scripts never legitimately send target:"offscreen"; fail
  // closed on anything that is not the extension itself without a tab.
  if (!sender || sender.id !== chrome.runtime.id || sender.tab) return;
  if (msg.action === "offscreen-copy") {
    writeClipboard(msg.text || "")
      .then(() => {
        // A fresh copy always cancels a pending clear for the previous one.
        scheduleClear(msg.clearSeconds);
        sendResponse({ ok: true });
      })
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg.action === "offscreen-clear") {
    if (clearTimer) clearTimeout(clearTimer);
    clearTimer = null;
    writeClipboard(" ")
      .catch(() => {})
      .finally(() => sendResponse({ ok: true }));
    return true;
  }
}

chrome.runtime.onMessage.addListener(handleOffscreenMessage);
