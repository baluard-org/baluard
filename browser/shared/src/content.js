// Content script: fill executor only (Decision 9).
//
// Injected TOP-FRAME ONLY via chrome.scripting.executeScript({frameIds:[0]})
// from the popup when the user clicks Fill. NOT continuously registered.
// Receives a baluard-fill message, re-verifies the page origin matches the
// credential's expected origin (review sonnet A-5), then fills the best-
// detected login form.

(() => {
  // Guard against double-injection in one frame.
  if (window.__baluardFillInjected) return;
  window.__baluardFillInjected = true;

  const listener = (msg) => {
    if (!msg || msg.type !== "baluard-fill") return;
    chrome.runtime.onMessage.removeListener(listener);

    // Fill-time origin re-check (review sonnet A-5). The popup matched the
    // tab's URL, but the tab may have navigated during the IPC round trip.
    const currentHost = location.hostname.toLowerCase();
    if (msg.expectedOrigin && currentHost !== msg.expectedOrigin) {
      // Refuse: the page is no longer the one the user approved. Fail closed.
      console.warn("[baluard] fill refused: origin changed during fill");
      return;
    }

    fillLoginForm(msg.credential);
  };
  chrome.runtime.onMessage.addListener(listener);
})();

function fillLoginForm(cred) {
  const password = cred.password || "";
  const username = cred.username || "";

  // Find the best password field, then the username field in the same form.
  const passwords = visibleInputs("password");
  if (passwords.length === 0) {
    // No password field on the page. Some flows (e.g. username-only step)
    // still want the username filled.
    const userOnly = visibleInputs("text").concat(visibleInputs("email"));
    if (username && userOnly.length > 0) {
      setNativeValue(userOnly[0], username);
    }
    return;
  }

  const pwField = passwords[0];
  setNativeValue(pwField, password);

  // Find the username field: the last visible text-like input BEFORE the
  // password field in DOM order, within the same form (review agy I5).
  // Considering inputs AFTER the password (search boxes, captcha, OTP)
  // would misroute the username into the wrong field.
  const form = pwField.form;
  let userField = null;
  if (form) {
    const allInputs = Array.from(form.querySelectorAll("input"));
    const pwIndex = allInputs.indexOf(pwField);
    const candidates = allInputs
      .slice(0, pwIndex)
      .filter((i) => isTextLike(i) && isVisible(i));
    userField = candidates[candidates.length - 1] || null;
  }
  if (!userField) {
    // Fallback: any visible text-like input preceding the password.
    const all = visibleInputs("text").concat(visibleInputs("email"));
    userField = all[0] || null;
  }
  if (username && userField) {
    setNativeValue(userField, username);
  }

  // Best-effort: submit the form if there's a submit button and the page
  // seems to expect it (autofill UX). Defer to the user otherwise — many
  // modern logins do client-side validation. We do NOT auto-submit; the
  // user presses Enter. This is the safer default.
}

function visibleInputs(type) {
  return Array.from(document.querySelectorAll(`input[type="${type}"]`)).filter(isVisible);
}

function isTextLike(input) {
  const t = (input.type || "text").toLowerCase();
  return t === "text" || t === "email" || t === "tel" || t === "username";
}

function isVisible(el) {
  if (!el || !el.getBoundingClientRect) return false;
  const rect = el.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return false;
  const style = window.getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden") return false;
  return true;
}

// Set a value the way React/Vue/Svelte can hear: native setter + input event.
function setNativeValue(el, value) {
  const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  try {
    setter ? setter.call(el, value) : (el.value = value);
  } catch {
    el.value = value;
  }
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}
