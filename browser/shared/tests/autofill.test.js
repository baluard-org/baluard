// Unit tests for autofill.js inline-icon targeting heuristics.
//
// isUsernameField decides whether a focused input grows the Baluard icon.
// False positives (search boxes, newsletter signups) are noise; false
// negatives break the feature. The heuristic layers explicit signals
// (autocomplete, name/id/placeholder hints) then the structural "text input
// directly before a password field in the same form" pattern.

import { describe, it, expect, beforeEach } from "vitest";
import { isUsernameField } from "../src/autofill.js";

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
});
