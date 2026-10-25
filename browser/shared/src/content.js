// Content script: fill executor only (Decision 9).
//
// Injected TOP-FRAME ONLY via chrome.scripting.executeScript({frameIds:[0]})
// from the popup when the user clicks Fill. NOT continuously registered.
// Receives a baluard-fill message, re-verifies the page origin matches the
// credential's expected origin, then fills the best-detected login form.
//
// Field detection + fill logic lives in autofill.js (shared with inline.js).

import { fillLoginForm } from "./autofill.js";

(() => {
  // Guard against double-injection in one frame.
  if (window.__baluardFillInjected) return;
  window.__baluardFillInjected = true;

  const listener = (msg, sender) => {
    // Only our own extension may drive a fill.
    if (sender && sender.id && sender.id !== chrome.runtime.id) return;
    if (!msg || msg.type !== "baluard-fill") return;
    // The listener stays registered: SPA logins fill more than once per
    // document, and the double-injection guard would block a re-injected
    // script from adding a second one.

    // Fill-time ORIGIN re-check (B1: scheme+host+port, not hostname-only).
    // The popup matched the tab's URL, but the tab may have navigated during
    // the IPC round trip — including an https -> http downgrade.
    if (!msg.expectedOrigin || location.origin !== msg.expectedOrigin) {
      // Refuse: the page is no longer the one the user approved, or origin missing. Fail closed.
      console.warn("[baluard] fill refused: origin changed during fill");
      return;
    }

    fillLoginForm(msg.credential);
  };
  chrome.runtime.onMessage.addListener(listener);
})();
