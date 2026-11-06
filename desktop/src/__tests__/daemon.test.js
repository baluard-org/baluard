import { describe, it, expect, vi, beforeEach } from "vitest";

const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a) => invokeMock(...a) }));

import { daemon } from "../lib/daemon.js";

describe("daemon session expiry signal", () => {
  beforeEach(() => invokeMock.mockReset());

  it("emits baluard:session-expired when the daemon rejects the session token", async () => {
    invokeMock.mockResolvedValue({ success: false, error: "Invalid session token. Re-unlock the vault." });
    const seen = vi.fn();
    window.addEventListener("baluard:session-expired", seen, { once: true });
    await expect(daemon("cipher.totp_code", "some-id")).rejects.toThrow(/Invalid session token/);
    expect(seen).toHaveBeenCalledTimes(1);
  });

  it("does not emit for unrelated errors", async () => {
    invokeMock.mockResolvedValue({ success: false, error: "vault is locked" });
    const seen = vi.fn();
    window.addEventListener("baluard:session-expired", seen, { once: true });
    await expect(daemon("vault.add", "x")).rejects.toThrow(/vault is locked/);
    expect(seen).not.toHaveBeenCalled();
  });
});
