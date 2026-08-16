// Shared field detection + fill heuristics.
//
// Used by BOTH content scripts:
//   content.js — popup-driven fill executor (injected on demand, Decision 9)
//   inline.js  — in-field dropdown (opt-out setting; amends Decision 9)
//
// Bundled into each content script as an IIFE by the vite closeBundle plugin
// (content scripts are classic scripts: no ES imports at runtime).

// Fill the best-detected login form with one credential. Fills the first
// visible password field + the best username field before it (same form).
export function fillLoginForm(cred) {
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
  // password field in DOM order, within the same form.
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

export function visibleInputs(type) {
  return Array.from(document.querySelectorAll(`input[type="${type}"]`)).filter(isVisible);
}

export function isTextLike(input) {
  const t = (input.type || "text").toLowerCase();
  return t === "text" || t === "email" || t === "tel" || t === "username";
}

export function isVisible(el) {
  if (!el || !el.getBoundingClientRect) return false;
  const rect = el.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return false;
  const style = window.getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden") return false;
  return true;
}

// Set a value the way React/Vue/Svelte can hear: native setter + input event.
export function setNativeValue(el, value) {
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

// Username-ish hints. Word-boundary regex so "mailchimp" does not count as
// "mail". Applied to name/id/placeholder/autocomplete/aria-label.
const USERNAME_HINT = /\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;

// Should the inline icon appear on this field? (Used by inline.js only.)
//
// True for password fields and for text-like fields that look like a
// username input. A generic text box (site search, newsletter signup) must
// NOT grow our icon — every false positive is noise the user learns to
// ignore, and hint-based matching keeps the icon rare enough to stay
// meaningful.
export function isUsernameField(input) {
  if (!input || input.tagName !== "INPUT") return false;
  const type = (input.type || "text").toLowerCase();
  if (type === "password") return true;
  if (!isTextLike(input)) return false;
  const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
  if (autocomplete === "username" || autocomplete === "email" || autocomplete === "current-password") return true;
  const hints = [input.name, input.id, input.getAttribute("placeholder"), input.getAttribute("aria-label")]
    .filter(Boolean)
    .join(" ");
  if (USERNAME_HINT.test(hints)) return true;
  // No explicit hints: a text-like input directly followed by a password
  // field in the same form is almost always the username box.
  if (input.form) {
    const all = Array.from(input.form.querySelectorAll("input"));
    const next = all[all.indexOf(input) + 1];
    if (next && (next.type || "").toLowerCase() === "password") return true;
  }
  return false;
}
