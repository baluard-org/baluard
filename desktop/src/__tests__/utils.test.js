import { describe, test, expect, vi } from "vitest";
import {
  sanitizeError,
  isHardwareError,
  generateSecurePassword,
  uriStr,
  getCuratedColor,
  getDomainInitials,
  detectCardBrand,
  formatDateIso,
  ERROR_PATTERNS,
} from "../lib/utils.js";

const t = (key) => key;

// ── isHardwareError ──

describe("isHardwareError", () => {
  test.each([
    "this vault is guarded by this device's security chip and the chip is unavailable",
    "this vault demands confirmation on every unlock and this device's security chip cannot do that",
    "no security key is plugged in; plug it in to unlock",
    "this is not the security key this vault was sealed to",
    "the security key was not tapped in time; try again",
    "the security key touch was cancelled",
    "the security key is busy in another application; close it and try again",
    "this security key requires a touch on every unlock and cannot provide a silent seal",
    "this vault's security chip confirmation failed - try again, or recover this device with the recovery phrase",
    "metadata error: security key: transport detail",
  ])("does not treat a hardware failure as a wrong password: %s", (message) => {
    expect(isHardwareError(message)).toBe(true);
    expect(isHardwareError(new Error(message))).toBe(true);
  });

  test("still recognizes a credential failure", () => {
    expect(isHardwareError("master password incorrect")).toBe(false);
  });
});

// ── sanitizeError ──

describe("sanitizeError", () => {
  test("explains incompatible security keys instead of saying they are unplugged", () => {
    expect(sanitizeError("Connect a compatible security key. (uv-forced)", t)).toBe(
      "errors.hwKeyUvForced",
    );
    expect(sanitizeError("Connect a compatible security key. (pin-required)", t)).toBe(
      "errors.hwKeyPinRequired",
    );
    expect(sanitizeError("security key: this token requires its PIN for hmac-secret", t)).toBe(
      "errors.hwKeyPinRequired",
    );
  });

  test("matches daemon not running", () => {
    expect(sanitizeError("Cannot connect to daemon", t)).toBe("errors.daemonNotRunning");
  });

  test("matches vault locked", () => {
    expect(sanitizeError("Vault not opened", t)).toBe("errors.vaultNotUnlocked");
    expect(
      sanitizeError(
        "This downloaded vault has no device key on this machine. Unlock with your 24-word recovery phrase to enroll it.",
        t,
      ),
    ).toBe("errors.phraseEnrollRequired");
  });

  test("matches attachment compaction refusals", () => {
    expect(
      sanitizeError(
        "some files have not finished syncing to the vault yet; sync once and retry compaction",
        t,
      ),
    ).toBe("errors.attachPending");
    expect(
      sanitizeError(
        "Compaction needs every entry readable on this device; sync and unlock fully",
        t,
      ),
    ).toBe("errors.attachReadable");
  });

  test("matches timeout", () => {
    expect(sanitizeError("request timeout after 5s", t)).toBe("errors.timeout");
  });

  test("matches invalid password variants", () => {
    expect(sanitizeError("invalid password", t)).toBe("errors.invalidPassword");
    expect(sanitizeError("incorrect password", t)).toBe("errors.invalidPassword");
  });

  test("maps the clone wizard's pre-vault failures to real copy", () => {
    expect(
      sanitizeError("No active vault. Open or unlock one first, or pass a slug.", t),
    ).toBe("errors.noVault");
    expect(
      sanitizeError("Device flow start failed: API error: token validation failed: invalid_client", t),
    ).toBe("errors.providerSignin");
    expect(
      sanitizeError("oauth_start failed: error sending request for url (https://github.com)", t),
    ).toBe("errors.network");
    expect(
      sanitizeError("Cloned repository has no .baluard marker (not a Baluard vault)", t),
    ).toBe("errors.cloneFailed");
    expect(
      sanitizeError("Cloned, but storing the credentials failed: no keyring backend", t),
    ).toBe("errors.cloneFailed");
    expect(sanitizeError('sync error: {"error":"host_key_untrusted"}', t)).toBe(
      "errors.hostKey",
    );
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

// ── formatDateIso ──

describe("formatDateIso", () => {
  // Built from a local-noon Date so the expectation holds in any TZ.
  test("renders the local calendar date as YYYY-MM-DD", () => {
    const d = new Date(2021, 11, 3, 12, 0, 0);
    expect(formatDateIso(Math.floor(d.getTime() / 1000))).toBe("2021-12-03");
  });

  test("stays on the local date for times near midnight", () => {
    const d = new Date(2021, 8, 11, 23, 30, 0);
    expect(formatDateIso(Math.floor(d.getTime() / 1000))).toBe("2021-09-11");
  });

  test("returns null for missing timestamps", () => {
    expect(formatDateIso(null)).toBeNull();
    expect(formatDateIso(undefined)).toBeNull();
    expect(formatDateIso(0)).toBeNull();
  });
});
