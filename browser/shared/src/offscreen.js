// Offscreen document: clipboard bridge for the service worker.
// The SW has no DOM, so navigator.clipboard lives here. Auto-clears after 20s.
//
// Two messages from the SW (routed via chrome.runtime.sendMessage with
// target:"offscreen"):
//   offscreen-copy { text } -> write text to clipboard
//   offscreen-clear        -> overwrite clipboard with empty string

export function handleOffscreenMessage(msg, _sender, sendResponse) {
  if (!msg || msg.target !== "offscreen") return;
  if (msg.action === "offscreen-copy") {
    navigator.clipboard
      .writeText(msg.text || "")
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg.action === "offscreen-clear") {
    navigator.clipboard
      .writeText(" ")
      .catch(() => {})
      .finally(() => sendResponse({ ok: true }));
    return true;
  }
}

chrome.runtime.onMessage.addListener(handleOffscreenMessage);
