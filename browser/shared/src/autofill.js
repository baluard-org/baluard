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
// When cred.totpCode is set, also fills the first detected TOTP field.
export function fillLoginForm(cred) {
  const password = cred.password || "";
  const username = cred.username || "";
  const totpCode = cred.totpCode || "";

  // B10: TOTP-detected fields are NEVER password or username candidates,
  // even when styled type=password (Bitwarden's Citrix bug, inverse form:
  // the login password must not land in a masked OTP box).
  const passwords = visibleInputs("password").filter((i) => !isTotpField(i));
  if (passwords.length === 0) {
    // No password field on the page. Some flows (e.g. username-only step)
    // still want the username filled.
    const userOnly = visibleInputs("text")
      .concat(visibleInputs("email"))
      .filter((i) => !isTotpField(i));
    if (username && userOnly.length > 0) {
      setNativeValue(userOnly[0], username);
    }
    if (totpCode) fillTotpField(totpCode);
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
      .filter((i) => isTextLike(i) && isVisible(i) && !isTotpField(i));
    userField = candidates[candidates.length - 1] || null;
  }
  if (!userField) {
    // Fallback: any visible text-like input preceding the password.
    const all = visibleInputs("text").concat(visibleInputs("email"));
    userField = all.find((i) => !isTotpField(i)) || null;
  }
  if (username && userField) {
    setNativeValue(userField, username);
  }

  if (totpCode) fillTotpField(totpCode);

  // Best-effort: submit the form if there's a submit button and the page
  // seems to expect it (autofill UX). Defer to the user otherwise — many
  // modern logins do client-side validation. We do NOT auto-submit; the
  // user presses Enter. This is the safer default.
}

export function visibleInputs(type) {
  return Array.from(document.querySelectorAll(`input[type="${type}"]`)).filter(isVisible);
}

// Fill the first detected TOTP field with a code. Returns whether a field
// was found. Segmented boxes (maxlength<=1) are already excluded from
// detection: writing a full code into one would silently truncate and
// corrupt whatever the user types next.
export function fillTotpField(totpCode) {
  const field = findTotpFields()[0];
  if (field) setNativeValue(field, totpCode);
  return Boolean(field);
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

// ── TOTP field detection ──
// Precedence (do not reorder — KeePassXC #1785 shipped exactly this class
// of bug when a heuristic overrode the explicit attribute):
//   1. hard safety floor: segmented boxes (maxlength<=1) are rejected
//      BEFORE the explicit attribute. A 6-digit code in a 1-char box
//      silently truncates and corrupts manual entry. No signal overrides
//      this — not even autocomplete="one-time-code".
//   2. autocomplete="one-time-code" — explicit, trusted over all heuristics
//   3. ignore hints — search boxes, commerce/postal codes
//   4. strict name match — normalized equality against TOTP_FIELD_NAMES
//   5. ambiguous token + corroboration — numeric inputmode/pattern/maxlength
const TOTP_FIELD_NAMES = new Set([
  "2facode",
  "approvalscode",
  "mfacode",
  "onetimecode",
  "onetimepassword",
  "otccode",
  "otcconfirmation",
  "otpcode",
  "secondfactor",
  "securitycode",
  "totp",
  "totpcode",
  "twofa",
  "twofactor",
  "twofactorcode",
  "verificationcode",
]);

// Match only as whole tokens, never substrings: "discountcode" must not
// match "code" (KeePassXC #2856: postcode, product_code, language code...).
const AMBIGUOUS_TOTP_NAMES = new Set(["code", "otp", "pin", "2fa", "mfa", "otc"]);

const TOTP_IGNORE_TOKENS = new Set([
  "captcha",
  "forgot",
  "search",
  "query",
  "find",
  "go",
  "zip",
  "postal",
  "postcode",
  "promo",
  "coupon",
  "discount",
  "product",
  "language",
  "reference",
  "redirect",
  "phone",
  "country",
  "dial",
  "area",
  "tel",
  "currency",
  "tax",
  "cvv",
  "cvc",
  "csc",
]);

function normalizeHint(s) {
  return (s || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

// Is this input a one-time-code box? Used by fillLoginForm (B10 exclusion),
// isUsernameField, and inline.js (icon targeting + code-only fill mode).
export function isTotpField(input) {
  if (!input || input.tagName !== "INPUT") return false;
  const type = (input.type || "text").toLowerCase();
  const candidateType = isTextLike(input) || type === "number" || type === "password";
  if (!candidateType) return false;
  const ml = parseInt(input.getAttribute("maxlength"), 10);
  const size = parseInt(input.getAttribute("size"), 10);
  // Segmented per-digit boxes cannot receive a full code.
  if (Number.isFinite(ml) && ml <= 1) return false;
  if (Number.isFinite(size) && size === 1 && !Number.isFinite(ml)) return false;
  // 2. Explicit attribute wins over every heuristic.
  const ac = (input.getAttribute("autocomplete") || "").trim().toLowerCase();
  if (ac === "one-time-code") {
    return true;
  }
  if (ac.startsWith("cc-")) return false;
  const attrs = [
    input.name,
    input.id,
    input.getAttribute("placeholder"),
    input.getAttribute("aria-label"),
  ];
  const raw = attrs.filter(Boolean).join(" ").toLowerCase();
  const tokens = raw.split(/[^a-z0-9]+/).filter(Boolean);
  // 3. Ignore hints (search boxes, commerce/postal codes).
  if (tokens.some((t) => TOTP_IGNORE_TOKENS.has(t))) return false;
  // 4. Name-based matches only. CVV fields are 3-4 digits ("security-code",
  // incl. Amex CID maxlength=4); real OTP boxes are 5-10. No upper bound: an
  // explicit name with a generous maxlength is still an OTP field.
  if (Number.isFinite(ml) && ml < 5) return false;
  // 5. Strict: normalized whole-attribute equality ("security_code" ->
  // "securitycode").
  if (attrs.some((a) => TOTP_FIELD_NAMES.has(normalizeHint(a)))) return true;
  // 6. Ambiguous token + numeric corroboration.
  const patternQuant = /(?:\\d|\[0-9\])\{(\d+)\}/.exec(
    input.getAttribute("pattern") || ""
  );
  const corroborated =
    (input.getAttribute("inputmode") || "").toLowerCase() === "numeric" ||
    (!!patternQuant && +patternQuant[1] >= 4 && +patternQuant[1] <= 8) ||
    (Number.isFinite(ml) && ml >= 5 && ml <= 8);
  return corroborated && tokens.some((t) => AMBIGUOUS_TOTP_NAMES.has(t));
}

// All visible TOTP fields on the page, DOM order.
export function findTotpFields() {
  return Array.from(document.querySelectorAll("input")).filter(
    (i) => isVisible(i) && isTotpField(i)
  );
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
  // B10: an OTP field never counts as a username field (it gets its own
  // icon path in inline.js) and is never a username fill target.
  if (isTotpField(input)) return false;
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
