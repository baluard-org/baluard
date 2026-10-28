import { describe, test, expect, vi } from "vitest";
import {
  sanitizeError,
  generateSecurePassword,
  uriStr,
  getCuratedColor,
  getDomainInitials,
  detectCardBrand,
  ERROR_PATTERNS,
} from "../lib/utils.js";

const t = (key) => key;

// ── sanitizeError ──

describe("sanitizeError", () => {
  test("matches daemon not running", () => {
    expect(sanitizeError("Cannot connect to daemon", t)).toBe("errors.daemonNotRunning");
  });

  test("matches vault locked", () => {
    expect(sanitizeError("Vault not opened", t)).toBe("errors.vaultNotUnlocked");
  });

  test("matches timeout", () => {
    expect(sanitizeError("request timeout after 5s", t)).toBe("errors.timeout");
  });

  test("matches invalid password variants", () => {
    expect(sanitizeError("invalid password", t)).toBe("errors.invalidPassword");
    expect(sanitizeError("incorrect password", t)).toBe("errors.invalidPassword");
  });

  test("matches security-key touch outcomes with specific copy", () => {
    expect(
      sanitizeError("the security key was not tapped in time; try again", t),
    ).toBe("errors.hwTouchTimeout");
    expect(sanitizeError("the security key touch was cancelled", t)).toBe(
      "errors.hwTouchTimeout",
    );
    expect(
      sanitizeError(
        "the security key is busy in another application; close it and try again",
        t,
      ),
    ).toBe("errors.hwBusy");
    expect(sanitizeError("this is not the security key this vault was sealed to", t)).toBe(
      "errors.hwKeyWrong",
    );
    expect(sanitizeError("no security key is plugged in; plug it in to unlock", t)).toBe(
      "errors.hwKeyMissing",
    );
    expect(
      sanitizeError("Connect a compatible security key.", t),
    ).toBe("errors.hwKeyMissing");
  });

  test("extracts message from Error object", () => {
    expect(sanitizeError(new Error("Cannot connect"), t)).toBe("errors.daemonNotRunning");
  });

  test("returns unexpected for unknown errors in production", () => {
    const orig = import.meta.env.DEV;
    import.meta.env.DEV = false;
    expect(sanitizeError("something odd happened", t)).toBe("errors.unexpected");
    import.meta.env.DEV = orig;
  });

  test("returns DEBUG in dev for unknown errors", () => {
    const orig = import.meta.env.DEV;
    import.meta.env.DEV = true;
    expect(sanitizeError("odd", t)).toBe("DEBUG: odd");
    import.meta.env.DEV = orig;
  });
});

// ── generateSecurePassword ──

describe("generateSecurePassword", () => {
  test("default length is 16", () => {
    expect(generateSecurePassword().length).toBe(16);
  });

  test("respects custom length", () => {
    expect(generateSecurePassword(32).length).toBe(32);
  });

  test("two calls produce different passwords", () => {
    const a = generateSecurePassword();
    const b = generateSecurePassword();
    expect(a).not.toBe(b);
  });

  test("no symbols when disabled", () => {
    const pw = generateSecurePassword(64, true, true, false);
    expect(/^[a-zA-Z0-9]+$/.test(pw)).toBe(true);
  });

  test("no uppercase when disabled", () => {
    const pw = generateSecurePassword(64, false, false, false);
    expect(/^[a-z]+$/.test(pw)).toBe(true);
  });
});

// ── uriStr ──

describe("uriStr", () => {
  test("string pass-through", () => {
    expect(uriStr("https://example.com")).toBe("https://example.com");
  });

  test("object with uri field", () => {
    expect(uriStr({ uri: "https://example.com", match_strategy: null })).toBe("https://example.com");
  });

  test("null returns empty string", () => {
    expect(uriStr(null)).toBe("");
  });

  test("undefined returns empty string", () => {
    expect(uriStr(undefined)).toBe("");
  });
});

// ── getCuratedColor ──

describe("getCuratedColor", () => {
  test("null name returns first color", () => {
    expect(getCuratedColor(null)).toBe("bg-emerald-600");
  });

  test("same name always same color", () => {
    expect(getCuratedColor("GitHub")).toBe(getCuratedColor("GitHub"));
  });

  test("different names may differ", () => {
    // Not guaranteed, but highly likely with different names
    const a = getCuratedColor("GitHub");
    const b = getCuratedColor("GitLab");
    // They happen to be different, but don't assert it strictly
    expect(typeof a).toBe("string");
    expect(typeof b).toBe("string");
  });
});

// ── getDomainInitials ──

describe("getDomainInitials", () => {
  test("null returns ?", () => {
    expect(getDomainInitials(null)).toBe("?");
  });

  test("extracts first char uppercase", () => {
    expect(getDomainInitials("example.com")).toBe("E");
  });

  test("strips https:// prefix", () => {
    expect(getDomainInitials("https://example.com")).toBe("E");
  });

  test("strips www. prefix", () => {
    expect(getDomainInitials("www.example.com")).toBe("E");
  });
});

// ── detectCardBrand ──

describe("detectCardBrand", () => {
  test("visa starts with 4", () => {
    expect(detectCardBrand("4111111111111111")).toBe("Visa");
  });

  test("mastercard 51-55", () => {
    expect(detectCardBrand("5500000000000004")).toBe("Mastercard");
  });

  test("amex 34/37", () => {
    expect(detectCardBrand("341111111111111")).toBe("Amex");
    expect(detectCardBrand("371111111111111")).toBe("Amex");
  });

  test("discover", () => {
    expect(detectCardBrand("6011000000000004")).toBe("Discover");
  });

  test("jcb", () => {
    expect(detectCardBrand("3530111333300000")).toBe("JCB");
  });

  test("unknown returns null", () => {
    expect(detectCardBrand("0000000000000000")).toBeNull();
  });

  test("empty returns null", () => {
    expect(detectCardBrand("")).toBeNull();
  });

  test("ignores spaces", () => {
    expect(detectCardBrand("4111 1111 1111 1111")).toBe("Visa");
  });
});

// ── ERROR_PATTERNS ──

describe("ERROR_PATTERNS", () => {
  test("every entry has pattern and key", () => {
    for (const { pattern, key } of ERROR_PATTERNS) {
      expect(pattern instanceof RegExp).toBe(true);
      expect(typeof key).toBe("string");
      expect(key.startsWith("errors.")).toBe(true);
    }
  });
});
