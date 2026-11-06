// Unit tests for autofill.js inline-icon targeting heuristics.
//
// isUsernameField decides whether a focused input grows the Baluard icon.
// False positives (search boxes, newsletter signups) are noise; false
// negatives break the feature. The heuristic layers explicit signals
// (autocomplete, name/id/placeholder hints) then the structural "text input
// directly before a password field in the same form" pattern.

import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  isUsernameField,
  isTotpField,
  findTotpFields,
  fillLoginForm,
  setNativeValue,
} from "../src/autofill.js";

function makeInput(type, attrs = {}) {
  const el = document.createElement("input");
  el.type = type;
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

describe("isUsernameField", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("always targets password fields", () => {
    expect(isUsernameField(makeInput("password"))).toBe(true);
  });

  it("targets autocomplete=username/email/current-password", () => {
    expect(isUsernameField(makeInput("text", { autocomplete: "username" }))).toBe(true);
    expect(isUsernameField(makeInput("text", { autocomplete: "email" }))).toBe(true);
    expect(isUsernameField(makeInput("text", { autocomplete: "current-password" }))).toBe(true);
  });

  it("targets text inputs with username-ish name/id/placeholder hints", () => {
    expect(isUsernameField(makeInput("text", { name: "user" }))).toBe(true);
    expect(isUsernameField(makeInput("text", { id: "login-email" }))).toBe(true);
    expect(isUsernameField(makeInput("email", { placeholder: "Your e-mail address" }))).toBe(true);
    expect(isUsernameField(makeInput("text", { "aria-label": "Account" }))).toBe(true);
  });

  it("uses word-boundary matching so hint substrings do not fire", () => {
    // "mailchimp" contains "mail" but not as a word — must NOT match.
    expect(isUsernameField(makeInput("text", { id: "mailchimp-signup" }))).toBe(false);
    // "username2" has no word boundary after "username" (digits are word
    // chars), so the bare regex does not fire — the structural rule may
    // still catch it if it sits before a password field.
    expect(isUsernameField(makeInput("text", { name: "username2" }))).toBe(false);
  });

  it("rejects generic search and text fields without hints", () => {
    expect(isUsernameField(makeInput("text", { name: "q" }))).toBe(false);
    expect(isUsernameField(makeInput("text", { placeholder: "Search" }))).toBe(false);
    expect(isUsernameField(makeInput("text"))).toBe(false);
  });

  it("rejects non-text-like types", () => {
    expect(isUsernameField(makeInput("checkbox"))).toBe(false);
    expect(isUsernameField(makeInput("hidden"))).toBe(false);
    expect(isUsernameField(makeInput("number"))).toBe(false);
  });

  it("targets a text input directly before a password field in the same form", () => {
    const form = document.createElement("form");
    const user = makeInput("text", { name: "anything" });
    const pw = makeInput("password");
    form.appendChild(user);
    form.appendChild(pw);
    document.body.appendChild(form);
    expect(isUsernameField(user)).toBe(true);
  });

  it("does not treat a far-away search box as a username field", () => {
    const form = document.createElement("form");
    const search = makeInput("text", { name: "query" });
    const other = makeInput("text");
    const pw = makeInput("password");
    // search is NOT adjacent to the password field.
    form.appendChild(search);
    form.appendChild(other);
    form.appendChild(pw);
    document.body.appendChild(form);
    expect(isUsernameField(search)).toBe(false);
  });

  it("rejects non-input elements and null", () => {
    expect(isUsernameField(document.createElement("textarea"))).toBe(false);
    expect(isUsernameField(null)).toBe(false);
  });

  it("never claims a TOTP field (B10)", () => {
    expect(isUsernameField(makeInput("text", { name: "totp" }))).toBe(false);
    expect(
      isUsernameField(makeInput("text", { autocomplete: "one-time-code" }))
    ).toBe(false);
  });
});

// ── TOTP field detection ──
// Precedence: segmented-box floor (maxlength<=1, before everything) >
// autocomplete="one-time-code" > ignore tokens > strict name match >
// ambiguous token + numeric corroboration. The false-positive class
// (postcode, product_code, discount-code, CVV "security-code") is the
// KeePassXC #2856 bug list — every member gets a test.

describe("isTotpField", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("trusts autocomplete=one-time-code over every heuristic", () => {
    expect(isTotpField(makeInput("text", { autocomplete: "one-time-code" }))).toBe(true);
    // Explicit attribute beats even ignore-token names.
    expect(
      isTotpField(makeInput("text", { autocomplete: "one-time-code", name: "postcodex" }))
    ).toBe(true);
  });

  it("matches strict names via normalized equality", () => {
    expect(isTotpField(makeInput("text", { name: "totp" }))).toBe(true);
    expect(isTotpField(makeInput("text", { name: "TOTP_Code" }))).toBe(true);
    expect(isTotpField(makeInput("text", { id: "security_code" }))).toBe(true);
    expect(isTotpField(makeInput("text", { id: "otp-code" }))).toBe(true);
    expect(isTotpField(makeInput("text", { placeholder: "verification code" }))).toBe(true);
    expect(isTotpField(makeInput("text", { name: "approvals_code" }))).toBe(true);
    expect(isTotpField(makeInput("text", { "aria-label": "one-time password" }))).toBe(true);
    expect(isTotpField(makeInput("text", { name: "mfacode" }))).toBe(true);
    expect(isTotpField(makeInput("text", { name: "second-factor" }))).toBe(true);
    expect(isTotpField(makeInput("text", { name: "otc-confirmation" }))).toBe(true);
  });

  it("requires numeric corroboration for ambiguous names", () => {
    expect(
      isTotpField(makeInput("text", { name: "code", inputmode: "numeric" }))
    ).toBe(true);
    expect(isTotpField(makeInput("text", { name: "code", maxlength: "6" }))).toBe(true);
    expect(isTotpField(makeInput("text", { name: "otp", pattern: "\\d{6}" }))).toBe(true);
    expect(isTotpField(makeInput("text", { name: "2fa", placeholder: "Enter 2FA code", maxlength: "8" }))).toBe(true);
    // Ambiguous name without corroboration: never a TOTP field.
    expect(isTotpField(makeInput("text", { name: "code" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "otp", maxlength: "20" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "pin" }))).toBe(false);
  });

  it("rejects the KeePassXC #2856 false-positive class", () => {
    expect(isTotpField(makeInput("text", { name: "postcode" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "postal_code", maxlength: "6" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "product_code", maxlength: "6" }))).toBe(false);
    expect(isTotpField(makeInput("text", { id: "discount-code", maxlength: "6" }))).toBe(false);
    expect(isTotpField(makeInput("text", { placeholder: "Language code" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "reference_code", maxlength: "8" }))).toBe(false);
  });

  it("rejects the CVV lookalike (security-code with maxlength=3)", () => {
    expect(isTotpField(makeInput("text", { name: "security-code", maxlength: "3" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "securitycode", maxlength: "3" }))).toBe(false);
    // A real OTP field of the same name passes the length gate.
    expect(isTotpField(makeInput("text", { name: "security-code", maxlength: "6" }))).toBe(true);
  });

  it("rejects CVV-zone lengths (3-4) for name matches; no upper bound", () => {
    expect(isTotpField(makeInput("text", { name: "totp", maxlength: "2" }))).toBe(false);
    // Amex CID: a 4-digit "security-code" is a CVV, not an OTP box.
    expect(isTotpField(makeInput("text", { name: "security-code", maxlength: "4" }))).toBe(false);
    // Generous maxlength on an explicit name: still an OTP field.
    expect(isTotpField(makeInput("text", { name: "totp", maxlength: "12" }))).toBe(true);
    expect(isTotpField(makeInput("text", { name: "totp", maxlength: "6" }))).toBe(true);
    // No maxlength at all: unconstrained, still matches.
    expect(isTotpField(makeInput("text", { name: "totp" }))).toBe(true);
  });

  it("never targets segmented per-digit boxes", () => {
    expect(
      isTotpField(makeInput("text", { autocomplete: "one-time-code", maxlength: "1" }))
    ).toBe(false);
    expect(isTotpField(makeInput("text", { name: "digit", maxlength: "1" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "otp", size: "1" }))).toBe(false);
  });

  it("rejects phone country code and credit card autocomplete fields", () => {
    expect(isTotpField(makeInput("tel", { name: "phone_code", inputmode: "numeric" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "country_code", inputmode: "numeric" }))).toBe(false);
    expect(isTotpField(makeInput("text", { name: "security_code", autocomplete: "cc-csc" }))).toBe(false);
  });

  it("accepts masked (type=password) and numeric OTP boxes", () => {
    expect(isTotpField(makeInput("password", { name: "totp" }))).toBe(true);
    expect(isTotpField(makeInput("number", { name: "otp", maxlength: "6" }))).toBe(true);
    expect(isTotpField(makeInput("tel", { name: "totp" }))).toBe(true);
  });

  it("rejects non-candidate input types and junk", () => {
    expect(isTotpField(makeInput("checkbox", { name: "totp" }))).toBe(false);
    expect(isTotpField(makeInput("hidden", { name: "totp" }))).toBe(false);
    expect(isTotpField(makeInput("submit", { name: "totp" }))).toBe(false);
    expect(isTotpField(document.createElement("textarea"))).toBe(false);
    expect(isTotpField(null)).toBe(false);
  });
});

// ── fillLoginForm TOTP integration (B10 exclusion + code fill) ──
// jsdom lays out nothing, so every attached input gets a fake non-zero rect
// to pass isVisible().

function attach(input) {
  document.body.appendChild(input);
  input.getBoundingClientRect = () => ({
    width: 100,
    height: 20,
    top: 0,
    left: 0,
    right: 100,
    bottom: 20,
  });
  return input;
}

function valueOf(input) {
  return input.value;
}

describe("fillLoginForm TOTP integration", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("fills username, password, and the detected TOTP field", () => {
    const user = attach(makeInput("text", { name: "username" }));
    const pw = attach(makeInput("password", { name: "password" }));
    const totp = attach(makeInput("text", { name: "totpcode" }));
    fillLoginForm({ username: "u", password: "p", totpCode: "123456" });
    expect(valueOf(user)).toBe("u");
    expect(valueOf(pw)).toBe("p");
    expect(valueOf(totp)).toBe("123456");
  });

  it("never puts the login password in a masked OTP field (B10, Citrix inverse)", () => {
    attach(makeInput("text", { name: "user" }));
    const realPw = attach(makeInput("password", { name: "password" }));
    const maskedOtp = attach(makeInput("password", { name: "totp" }));
    fillLoginForm({ username: "u", password: "p", totpCode: "123456" });
    expect(valueOf(realPw)).toBe("p");
    expect(valueOf(maskedOtp)).toBe("123456");
  });

  it("never puts the username in a TOTP field preceding the password (B10)", () => {
    const totp = attach(makeInput("text", { name: "verificationcode" }));
    const user = attach(makeInput("text", { name: "user" }));
    attach(makeInput("password", { name: "password" }));
    fillLoginForm({ username: "u", password: "p", totpCode: "123456" });
    expect(valueOf(totp)).toBe("123456");
    expect(valueOf(user)).toBe("u");
  });

  it("leaves TOTP fields alone when the credential has no code", () => {
    const totp = attach(makeInput("text", { name: "totpcode" }));
    attach(makeInput("text", { name: "user" }));
    attach(makeInput("password", { name: "password" }));
    fillLoginForm({ username: "u", password: "p" });
    expect(valueOf(totp)).toBe("");
  });

  it("findTotpFields returns visible detected fields in DOM order", () => {
    attach(makeInput("text", { name: "postcode" }));
    attach(makeInput("text", { name: "totp" }));
    attach(makeInput("text", { name: "otp", maxlength: "6" }));
    const found = findTotpFields();
    expect(found.length).toBe(2);
    expect(found[0].name).toBe("totp");
    expect(found[1].name).toBe("otp");
  });
});

describe("TOTP detection review hardening", () => {
  beforeEach(() => { document.body.innerHTML = ""; });

  // MAJOR 1: substring matching is identifier-only; free-text attributes
  // keep whole-value matching so prose cannot smuggle a strong name in.
  it("keeps a password box whose placeholder mentions one-time codes as a password target", () => {
    const el = makeInput("password", { name: "pw", placeholder: "Password or one-time code" });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(false);
  });

  it("keeps an email-first box mentioning verification codes as a username target", () => {
    const el = makeInput("email", { placeholder: "We'll email you a verification code" });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(false);
  });

  it("keeps filter prose with two-factor words out of OTP classification", () => {
    const el = makeInput("text", { "aria-label": "Filter by two-factor status" });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(false);
  });

  // MAJOR 2: camelCase identifiers must split into tokens for the guards.
  it("rejects camelCase CVV and phone code names", () => {
    for (const name of ["phoneVerificationCode", "cardSecurityCode", "cvvSecurityCode"]) {
      const el = makeInput("text", { name });
      document.body.appendChild(el);
      expect(isTotpField(el), name).toBe(false);
    }
  });

  it("still matches camelCase OTP identifiers", () => {
    const el = makeInput("password", { name: "signInTotpCode" });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(true);
  });

  // MINOR 1: setup/admin fields are not code entry boxes.
  it("rejects TOTP setup metadata fields", () => {
    for (const name of ["totp_secret", "totp_seed", "totp_uri", "totp_label", "otp_code_length"]) {
      const el = makeInput("text", { name });
      document.body.appendChild(el);
      expect(isTotpField(el), name).toBe(false);
    }
  });

  it("rejects readonly and disabled fields", () => {
    const ro = makeInput("text", { name: "totp" });
    ro.readOnly = true;
    const dis = makeInput("text", { name: "totp" });
    dis.disabled = true;
    document.body.append(ro, dis);
    expect(isTotpField(ro)).toBe(false);
    expect(isTotpField(dis)).toBe(false);
  });

  // MINOR 3: ignore tokens in prose must not veto a strongly named field.
  it("matches user[totp_code] even with a phone mention in the placeholder", () => {
    const el = makeInput("password", {
      id: "sign_in_totp_code",
      name: "user[totp_code]",
      placeholder: "Enter the code from your phone",
    });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(true);
  });

  // MINOR 4/5: autocomplete is a token list.
  it("accepts one-time-code inside a section-scoped token list", () => {
    const el = makeInput("text", { name: "code", autocomplete: "section-login one-time-code" });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(true);
  });

  it("rejects cc- tokens anywhere in the autocomplete list", () => {
    const el = makeInput("text", { name: "security_code", autocomplete: "billing cc-csc" });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(false);
  });

  it("matches every raw Bitwarden name spelling via placeholder equality", () => {
    for (const ph of ["security code", "verification code", "otc-code", "otp-code", "second-factor", "approvals_code", "otc-confirmation"]) {
      const el = makeInput("text", { placeholder: ph });
      document.body.appendChild(el);
      expect(isTotpField(el), ph).toBe(true);
    }
  });

  it("rejects non-entry element kinds", () => {
    const hidden = makeInput("hidden", { name: "totp" });
    const check = makeInput("checkbox", { name: "totp_enabled" });
    const sub = makeInput("submit", { name: "verify_totp" });
    document.body.append(hidden, check, sub);
    expect(isTotpField(hidden)).toBe(false);
    expect(isTotpField(check)).toBe(false);
    expect(isTotpField(sub)).toBe(false);
  });

  // MINOR 2: explicit signals outrank weaker evidence regardless of DOM order.
  it("ranks explicit autocomplete above a weaker ambiguous match", () => {
    attach(makeInput("text", { name: "otp", maxlength: "6", inputmode: "numeric" }));
    attach(makeInput("text", { name: "code2", autocomplete: "one-time-code" }));
    const found = findTotpFields();
    expect(found[0].getAttribute("autocomplete")).toBe("one-time-code");
  });

  it("routes username, password, and the code to distinct fields on the reported form", () => {
    attach(makeInput("text", { name: "user" }));
    attach(makeInput("password", { name: "password" }));
    attach(makeInput("password", { id: "sign_in_totp_code", name: "user[totp_code]", autocomplete: "off" }));
    fillLoginForm({ username: "u", password: "p", totpCode: "123456" });
    const inputs = document.querySelectorAll("input");
    expect(inputs[0].value).toBe("u");
    expect(inputs[1].value).toBe("p");
    expect(inputs[2].value).toBe("123456");
  });
});

describe("real-world 2FA field detection", () => {
  beforeEach(() => { document.body.innerHTML = ""; });

  it("detects a namespaced password-type OTP input (sign_in_totp_code / user[totp_code])", () => {
    const el = makeInput("password", {
      id: "sign_in_totp_code",
      name: "user[totp_code]",
      autocomplete: "off",
    });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(true);
  });

  it("still rejects a generic code field with no numeric corroboration", () => {
    const el = makeInput("text", { id: "discount_code", name: "discount_code" });
    document.body.appendChild(el);
    expect(isTotpField(el)).toBe(false);
  });

  it("detects the field for fillTotpField on a 2FA-only page", () => {
    attach(makeInput("password", {
      id: "sign_in_totp_code",
      name: "user[totp_code]",
      autocomplete: "off",
    }));
    expect(findTotpFields()).toHaveLength(1);
  });
});

describe("fill flash feedback", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
    document.head.innerHTML = "";
    vi.useRealTimers();
  });

  it("flashes a filled field and clears it after the timeout", () => {
    vi.useFakeTimers();
    const el = makeInput("text");
    document.body.appendChild(el);
    setNativeValue(el, "octocat");
    expect(el.classList.contains("baluard-fill-flash")).toBe(true);
    expect(document.querySelectorAll("#baluard-fill-flash-style").length).toBe(1);
    vi.advanceTimersByTime(2200);
    expect(el.classList.contains("baluard-fill-flash")).toBe(false);
  });

  it("injects the stylesheet once across fields and repeat fills", () => {
    vi.useFakeTimers();
    const a = makeInput("text");
    const b = makeInput("password");
    document.body.append(a, b);
    setNativeValue(a, "u");
    setNativeValue(b, "p");
    setNativeValue(a, "u2");
    expect(document.querySelectorAll("#baluard-fill-flash-style").length).toBe(1);
    expect(a.classList.contains("baluard-fill-flash")).toBe(true);
    expect(b.classList.contains("baluard-fill-flash")).toBe(true);
  });
});
