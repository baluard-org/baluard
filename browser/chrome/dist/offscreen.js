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
    navigator.clipboard.writeText(" ").catch(() => {});
  }, s * 1000);
}

export function handleOffscreenMessage(msg, sender, sendResponse) {
  if (!msg || msg.target !== "offscreen") return;
  // B6: only this extension's own service worker may drive the clipboard.
  // Content scripts never legitimately send target:"offscreen"; fail
  // closed on anything that is not the extension itself without a tab.
  if (!sender || sender.id !== chrome.runtime.id || sender.tab) return;
  if (msg.action === "offscreen-copy") {
    navigator.clipboard
      .writeText(msg.text || "")
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
    navigator.clipboard
      .writeText(" ")
      .catch(() => {})
      .finally(() => sendResponse({ ok: true }));
    return true;
  }
}

chrome.runtime.onMessage.addListener(handleOffscreenMessage);
