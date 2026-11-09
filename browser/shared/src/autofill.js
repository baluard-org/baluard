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
    userField =
      all.find(
        (i) =>
          !isTotpField(i) &&
          pwField.compareDocumentPosition(i) & Node.DOCUMENT_POSITION_PRECEDING
      ) || null;
  }
  if (username && userField) {
    setNativeValue(userField, username);
  }

  if (totpCode) fillTotpField(totpCode);

  // Deliberately NO auto-submit: modern logins often do client-side
  // validation; the user presses Enter when the page is ready.
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
  flashFilledField(el);
}

// Visual fill confirmation: the brand-lime ring pops once, then the field
// breathes a neon halo three times (~1s per bright-dim-bright cycle, 50%
// faster than the 2s reference) and the final frame lands back on
// transparent so the field returns to its normal look with no glow. One
// keyframe timeline rather than two animations because both effects paint
// box-shadow and the last animation on a property wins. Implemented as a
// class + injected keyframes (NOT inline styles) so the field's own
// box-shadow and transitions are left untouched once the class comes off.
// One stylesheet per document, reused across fills.
const FLASH_STYLE_ID = "baluard-fill-flash-style";
const FLASH_CLASS = "baluard-fill-flash";
export function flashFilledField(el) {
  if (!el || !el.classList) return;
  const doc = el.ownerDocument;
  if (!doc.getElementById(FLASH_STYLE_ID)) {
    const style = doc.createElement("style");
    style.id = FLASH_STYLE_ID;
    style.textContent =
      "@keyframes baluard-fill-glow{" +
      "0%{box-shadow:0 0 0 0 rgba(179,229,92,0)}" +
      "10%{box-shadow:0 0 0 4px rgba(179,229,92,.75)}" +
      "25%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}" +
      "40%{box-shadow:0 0 3px -1px rgba(179,229,92,.4)}" +
      "55%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}" +
      "70%{box-shadow:0 0 3px -1px rgba(179,229,92,.4)}" +
      "85%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}" +
      "100%{box-shadow:0 0 0 0 rgba(179,229,92,0)}}" +
      `.${FLASH_CLASS}{animation:baluard-fill-glow 3.3s ease-in-out}`;
    (doc.head || doc.documentElement).appendChild(style);
  }
  // Restart the animation on repeat fills of the same field.
  el.classList.remove(FLASH_CLASS);
  void el.offsetWidth;
  el.classList.add(FLASH_CLASS);
  clearTimeout(el.__baluardFlashTimer);
  el.__baluardFlashTimer = setTimeout(() => {
    el.classList.remove(FLASH_CLASS);
    delete el.__baluardFlashTimer;
  }, 3400);
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
//   4. strong name — substring inside name/id identifiers (Bitwarden-style
//      AppearsWithin), whole-value match on placeholder/aria-label
//   5. ambiguous token + corroboration — numeric inputmode/pattern/maxlength
// Bitwarden-parity name list. Their spellings collapse onto these after
// normalizeHint ("security code" -> "securitycode"), so nothing is missing.
const TOTP_FIELD_NAMES = [
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
];
const TOTP_NAME_SET = new Set(TOTP_FIELD_NAMES);
// Substring search over name/id only — never over placeholder/aria-label
// prose, where "Password or one-time code" must not reclassify a login box.
const TOTP_NAME_RE = new RegExp(TOTP_FIELD_NAMES.join("|"));

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
  // Payment context: CVV boxes share OTP-ish names ("card security code").
  "card",
  "payment",
  // TOTP setup/admin metadata: a secret or issuer field is not a code box.
  "secret",
  "seed",
  "uri",
  "url",
  "issuer",
  "label",
  "nickname",
  "length",
  "period",
  "algorithm",
]);

function normalizeHint(s) {
  return (s || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

// Classify an input as a one-time-code box. Returns -1 when it is not one,
// else the evidence tier (explicit autocomplete > strong name > ambiguous
// token), so consumers can prefer the strongest signal over DOM order.
// Used by fillLoginForm (B10 exclusion), isUsernameField, and inline.js
// (icon targeting + code-only fill mode).
export function totpFieldTier(input) {
  if (!input || input.tagName !== "INPUT") return -1;
  const type = (input.type || "text").toLowerCase();
  if (!(isTextLike(input) || type === "number" || type === "password")) return -1;
  // A readonly or disabled field cannot receive a typed code.
  if (input.readOnly || input.disabled) return -1;
  const ml = parseInt(input.getAttribute("maxlength"), 10);
  const size = parseInt(input.getAttribute("size"), 10);
  // Segmented per-digit boxes cannot receive a full code.
  if (Number.isFinite(ml) && ml <= 1) return -1;
  if (Number.isFinite(size) && size === 1 && !Number.isFinite(ml)) return -1;
  // autocomplete is a space-separated token list.
  const acTokens = (input.getAttribute("autocomplete") || "")
    .trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (acTokens.includes("one-time-code")) return 0;
  if (acTokens.some((t) => t.startsWith("cc-"))) return -1;
  const idAttrs = [input.name, input.id].filter(Boolean);
  const textAttrs = [input.getAttribute("placeholder"), input.getAttribute("aria-label")].filter(Boolean);
  // camelCase must split ("phoneVerificationCode" -> phone + verification +
  // code) or glued identifiers slip past the token guards.
  const tokensOf = (s) =>
    String(s)
      .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
  const idTokens = idAttrs.flatMap(tokensOf);
  const allTokens = [...idTokens, ...textAttrs.flatMap(tokensOf)];
  // Identifier ignore tokens are a hard reject; prose ignore tokens only
  // veto the ambiguous path, so a "code from your phone" placeholder does
  // not kill a strongly named field.
  if (idTokens.some((t) => TOTP_IGNORE_TOKENS.has(t))) return -1;
  // CVV fields are 3-4 digits (incl. Amex CID maxlength=4); real OTP boxes
  // are 5+. No upper bound: a generous maxlength is still an OTP field.
  if (Number.isFinite(ml) && ml < 5) return -1;
  if (idAttrs.some((a) => TOTP_NAME_RE.test(normalizeHint(a)))) return 1;
  if (textAttrs.some((a) => TOTP_NAME_SET.has(normalizeHint(a)))) return 1;
  const patternQuant = /(?:\\d|\[0-9\])\{(\d+)\}/.exec(
    input.getAttribute("pattern") || ""
  );
  const corroborated =
    (input.getAttribute("inputmode") || "").toLowerCase() === "numeric" ||
    (!!patternQuant && +patternQuant[1] >= 4 && +patternQuant[1] <= 8) ||
    (Number.isFinite(ml) && ml >= 5 && ml <= 8);
  if (!corroborated) return -1;
  if (allTokens.some((t) => TOTP_IGNORE_TOKENS.has(t))) return -1;
  return allTokens.some((t) => AMBIGUOUS_TOTP_NAMES.has(t)) ? 2 : -1;
}

export function isTotpField(input) {
  return totpFieldTier(input) >= 0;
}

// All visible TOTP fields on the page, strongest evidence first (DOM order
// within a tier): a weak match earlier in the document must not steal
// fields[0] from an explicit autocomplete=one-time-code box.
export function findTotpFields() {
  return Array.from(document.querySelectorAll("input"))
    .filter((i) => isVisible(i))
    .map((i) => ({ input: i, tier: totpFieldTier(i) }))
    .filter((e) => e.tier >= 0)
    .sort((a, b) => a.tier - b.tier)
    .map((e) => e.input);
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
