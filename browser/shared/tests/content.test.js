// Unit tests for content.js form-fill helpers.
//
// Covers the pure DOM logic: visibility filter, text-input classification,
// native value setter (React/Vue compat), and the username-field selection
// algorithm (last visible text-like input before the password field, in the
// same form). Origin re-check at fill time is a security-critical path; the
// popup is expected to send expectedOrigin and the content script refuses
// if location.hostname has drifted.
//
// The IIFE that registers the chrome.runtime listener runs at import time
// against the global chrome mock (setup.js), so importing the module is
// safe in tests.

import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  isVisible,
  isTextLike,
  visibleInputs,
  setNativeValue,
  fillLoginForm,
} from "../src/content.js";

function makeInput(type, attrs = {}) {
  const el = document.createElement("input");
  el.type = type;
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  // jsdom doesn't lay out — mock the rect so isVisible returns true by default.
  el.getBoundingClientRect = () => ({
    width: 100,
    height: 20,
    top: 0,
    left: 0,
    right: 100,
    bottom: 20,
  });
  return el;
}

describe("isVisible", () => {
  it("rejects elements with zero rect", () => {
    const el = document.createElement("div");
    el.getBoundingClientRect = () => ({ width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 });
    window.getComputedStyle = () => ({ display: "block", visibility: "visible" });
    expect(isVisible(el)).toBe(false);
  });

  it("rejects display:none elements", () => {
    const el = makeInput("text");
    window.getComputedStyle = () => ({ display: "none", visibility: "visible" });
    expect(isVisible(el)).toBe(false);
  });

  it("rejects visibility:hidden elements", () => {
    const el = makeInput("text");
    window.getComputedStyle = () => ({ display: "block", visibility: "hidden" });
    expect(isVisible(el)).toBe(false);
  });

  it("accepts visible elements", () => {
    const el = makeInput("text");
    window.getComputedStyle = () => ({ display: "block", visibility: "visible" });
    expect(isVisible(el)).toBe(true);
  });
});

describe("isTextLike", () => {
  it("treats text/email/tel/username as text-like", () => {
    for (const t of ["text", "email", "tel", "username"]) {
      expect(isTextLike(makeInput(t))).toBe(true);
    }
  });

  it("rejects password/hidden/checkbox", () => {
    for (const t of ["password", "hidden", "checkbox"]) {
      expect(isTextLike(makeInput(t))).toBe(false);
    }
  });

  it("defaults missing type to text-like", () => {
    const el = document.createElement("input");
    expect(isTextLike(el)).toBe(true);
  });
});

describe("visibleInputs", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("filters out inputs with zero rect", () => {
    const a = makeInput("text");
    const b = makeInput("text");
    b.getBoundingClientRect = () => ({ width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 });
    document.body.appendChild(a);
    document.body.appendChild(b);
    window.getComputedStyle = () => ({ display: "block", visibility: "visible" });
    expect(visibleInputs("text")).toHaveLength(1);
  });

  it("returns only the requested type", () => {
    document.body.appendChild(makeInput("text"));
    document.body.appendChild(makeInput("password"));
    window.getComputedStyle = () => ({ display: "block", visibility: "visible" });
    expect(visibleInputs("password")).toHaveLength(1);
    expect(visibleInputs("text")).toHaveLength(1);
  });
});

describe("setNativeValue", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("sets the value", () => {
    const el = makeInput("text");
    document.body.appendChild(el);
    setNativeValue(el, "hello");
    expect(el.value).toBe("hello");
  });

  it("dispatches input and change events (React/Vue compat)", () => {
    const el = makeInput("text");
    document.body.appendChild(el);
    const inputHandler = vi.fn();
    const changeHandler = vi.fn();
    el.addEventListener("input", inputHandler);
    el.addEventListener("change", changeHandler);
    setNativeValue(el, "x");
    expect(inputHandler).toHaveBeenCalledTimes(1);
    expect(changeHandler).toHaveBeenCalledTimes(1);
  });

  it("invokes the native prototype setter (not just .value=)", () => {
    const el = makeInput("text");
    document.body.appendChild(el);
    // Snapshot the original descriptor; restore in finally so we never
    // mutate the shared prototype across tests.
    const proto = HTMLInputElement.prototype;
    const original = Object.getOwnPropertyDescriptor(proto, "value");
    const calls = [];
    Object.defineProperty(proto, "value", {
      configurable: true,
      enumerable: original.enumerable,
      get: () => "",
      set: (v) => calls.push(v),
    });
    try {
      setNativeValue(el, "via-setter");
      expect(calls).toEqual(["via-setter"]);
    } finally {
      Object.defineProperty(proto, "value", original);
    }
  });
});

describe("fillLoginForm", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
    window.getComputedStyle = () => ({ display: "block", visibility: "visible" });
  });

  it("fills username and password when both fields exist", () => {
    const user = makeInput("text");
    const pw = makeInput("password");
    document.body.appendChild(user);
    document.body.appendChild(pw);
    fillLoginForm({ username: "alice", password: "hunter2" });
    expect(user.value).toBe("alice");
    expect(pw.value).toBe("hunter2");
  });

  it("fills only username when no password field exists", () => {
    const user = makeInput("text");
    document.body.appendChild(user);
    fillLoginForm({ username: "alice", password: "" });
    expect(user.value).toBe("alice");
  });

  it("picks the LAST text-like input before the password (same form)", () => {
    // Username-capture page pattern: search box -> captcha -> username -> password.
    // The search box and captcha are AFTER the password in DOM order, so the
    // fill must NOT route the username into them. Correct answer: the username
    // input that sits before the password in the same form.
    const form = document.createElement("form");
    const realUsername = makeInput("text");
    const pw = makeInput("password");
    form.appendChild(realUsername);
    form.appendChild(pw);
    document.body.appendChild(form);
    // Out-of-form inputs AFTER the password — must be ignored.
    const searchBox = makeInput("text");
    const captcha = makeInput("text");
    document.body.appendChild(searchBox);
    document.body.appendChild(captcha);

    fillLoginForm({ username: "alice", password: "secret" });
    expect(realUsername.value).toBe("alice");
    expect(pw.value).toBe("secret");
    expect(searchBox.value).toBe("");
    expect(captcha.value).toBe("");
  });

  it("does nothing when credential fields are empty", () => {
    const pw = makeInput("password");
    document.body.appendChild(pw);
    fillLoginForm({ username: "", password: "" });
    expect(pw.value).toBe("");
  });
});