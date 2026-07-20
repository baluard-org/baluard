// Tests for desktop/src/lib/vaultTimeout.js — preset list + token
// normalization. Mirrors baluard-core VaultTimeout token format.

import { describe, it, expect } from "vitest";
import {
  VAULT_TIMEOUT_PRESETS,
  DEFAULT_VAULT_TIMEOUT,
  normalizeVaultTimeout,
} from "../lib/vaultTimeout.js";

describe("VAULT_TIMEOUT_PRESETS", () => {
  it("includes the standard preset tokens", () => {
    const tokens = VAULT_TIMEOUT_PRESETS.map((p) => p.token);
    expect(tokens).toContain("immediately");
    expect(tokens).toContain("1m");
    expect(tokens).toContain("15m");
    expect(tokens).toContain("1h");
    expect(tokens).toContain("on_app_exit");
  });

  it("returns a frozen-by-convention default of 15m", () => {
    expect(DEFAULT_VAULT_TIMEOUT).toBe("15m");
  });
});

describe("normalizeVaultTimeout", () => {
  it("returns default for null", () => {
    expect(normalizeVaultTimeout(null)).toBe("15m");
  });

  it("returns default for undefined", () => {
    expect(normalizeVaultTimeout(undefined)).toBe("15m");
  });

  it("returns default for empty string", () => {
    expect(normalizeVaultTimeout("")).toBe("15m");
  });

  it("returns the same token for known preset tokens", () => {
    expect(normalizeVaultTimeout("immediately")).toBe("immediately");
    expect(normalizeVaultTimeout("1h")).toBe("1h");
    expect(normalizeVaultTimeout("on_app_exit")).toBe("on_app_exit");
  });

  it("is case-insensitive", () => {
    expect(normalizeVaultTimeout("15M")).toBe("15m");
    expect(normalizeVaultTimeout("1H")).toBe("1h");
  });

  it("trims whitespace", () => {
    expect(normalizeVaultTimeout("  5m  ")).toBe("5m");
  });

  it("normalizes bare integer minutes", () => {
    expect(normalizeVaultTimeout("30")).toBe("30m");
  });

  it("normalizes Nh format to N*60 minutes", () => {
    expect(normalizeVaultTimeout("2h")).toBe("120m");
  });

  it("falls back to default on garbage", () => {
    expect(normalizeVaultTimeout("not-a-number")).toBe("15m");
    expect(normalizeVaultTimeout("!!!")).toBe("15m");
  });

  it("preserves arbitrary minute values exactly", () => {
    // 17 minutes isn't a preset, so we get the canonical "17m" back.
    expect(normalizeVaultTimeout("17")).toBe("17m");
  });
});