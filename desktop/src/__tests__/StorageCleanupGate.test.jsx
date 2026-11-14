import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@solidjs/testing-library";

// StorageCleanupGate: a remote compaction of the attachments line is
// blocking. The daemon call is mocked at the IPC boundary, returning
// the RAW transport shape (a JSON string), since a parsed-object mock
// would hide a missing JSON.parse exactly like the settings-payload
// defect did.

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({
    t: (k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k),
    locale: () => "en",
  }),
  I18nProvider: (props) => props.children,
}));

vi.mock("../lib/utils.js", () => ({
  sanitizeError: (e) => String(e?.message ?? e),
}));

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...args) => daemonMock(...args) }));

const toasts = { error: vi.fn(), success: vi.fn() };
vi.mock("../context/toastSignal.js", () => ({
  toastError: (...a) => toasts.error(...a),
  toastSuccess: (...a) => toasts.success(...a),
}));

const vaultMock = { refreshCiphers: vi.fn() };
vi.mock("../context/VaultContext.jsx", () => ({
  useVault: () => vaultMock,
}));

const switcherMock = { activeSlug: () => null };
vi.mock("../context/VaultSwitcherContext.jsx", () => ({
  useVaultSwitcher: () => switcherMock,
}));

import StorageCleanupGate from "../components/StorageCleanupGate.jsx";

const REWRITTEN = JSON.stringify({
  tip: "a".repeat(64),
  rewritten: true,
  foreign: false,
  rewrite_signed: true,
  compaction: {
    device_id: "12345678-abc",
    at: 1,
    reclaimed: 3,
    reclaimed_bytes: 5 * 1024 * 1024,
    kept: 12,
  },
});
const CLEAN = JSON.stringify({
  tip: "b".repeat(64),
  rewritten: false,
  foreign: false,
});

beforeEach(() => {
  cleanup();
  daemonMock.mockReset();
  vaultMock.refreshCiphers.mockReset();
  toasts.error.mockReset();
  toasts.success.mockReset();
});

describe("StorageCleanupGate", () => {
  it("renders nothing on a clean status", async () => {
    daemonMock.mockResolvedValue(CLEAN);
    render(() => <StorageCleanupGate />);
    await waitFor(() => expect(daemonMock).toHaveBeenCalled());
    expect(screen.queryByTestId("cleanup-gate")).toBeNull();
    expect(screen.queryByTestId("cleanup-bar")).toBeNull();
  });

  it("blocks on a rewrite: the overlay carries the plain copy, the git disclosure, and no close affordance", async () => {
    daemonMock.mockResolvedValue(REWRITTEN);
    render(() => <StorageCleanupGate />);
    const gate = await waitFor(() => screen.getByTestId("cleanup-gate"));
    expect(gate.textContent).toContain("sync.cleanupTitle");
    expect(gate.textContent).toContain("sync.cleanupBody");
    // The detail line carries the device prefix, the count, and the size.
    expect(gate.textContent).toContain("sync.attachCleanedDetails");
    expect(gate.textContent).toContain('"device":"12345678"');
    expect(gate.textContent).toContain('"count":3');
    expect(gate.textContent).toContain('"size":"5.0 MB"');
    // Advanced git disclosure exists for those who want it.
    expect(gate.textContent).toContain("sync.cleanupAdvanced");
    // Non-dismissable: no X, only the two actions.
    expect(screen.getByTestId("cleanup-resolve").textContent).toContain(
      "sync.cleanupAction"
    );
    expect(screen.getByTestId("cleanup-keep-reading")).toBeTruthy();
  });

  it("falls back to the verified hint when the rewrite carries no details", async () => {
    daemonMock.mockResolvedValue(
      JSON.stringify({
        tip: "c".repeat(64),
        rewritten: true,
        foreign: false,
        rewrite_signed: true,
        compaction: null,
      })
    );
    render(() => <StorageCleanupGate />);
    const gate = await waitFor(() => screen.getByTestId("cleanup-gate"));
    expect(gate.textContent).toContain("sync.attachCleanedVerifiedHint");
    expect(gate.textContent).not.toContain("attachCleanedDetails");
  });

  it("resolve pulls, refreshes ciphers, toasts the discarded count, and dismisses", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "vault.attach_status") return Promise.resolve(REWRITTEN);
      if (action === "vault.attach_resolve")
        return Promise.resolve(JSON.stringify({ discarded: 4 }));
      throw new Error(`unexpected action ${action}`);
    });
    vaultMock.refreshCiphers.mockResolvedValue(undefined);
    render(() => <StorageCleanupGate />);
    await waitFor(() => screen.getByTestId("cleanup-gate"));
    fireEvent.click(screen.getByTestId("cleanup-resolve"));
    await waitFor(() =>
      expect(toasts.success).toHaveBeenCalledWith(
        expect.stringContaining('"count":4')
      )
    );
    expect(daemonMock).toHaveBeenCalledWith("vault.attach_resolve");
    expect(vaultMock.refreshCiphers).toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.queryByTestId("cleanup-gate")).toBeNull()
    );
    expect(screen.queryByTestId("cleanup-bar")).toBeNull();
  });

  it("keep reading collapses to the persistent bar, which has no dismiss", async () => {
    daemonMock.mockResolvedValue(REWRITTEN);
    render(() => <StorageCleanupGate />);
    await waitFor(() => screen.getByTestId("cleanup-gate"));
    fireEvent.click(screen.getByTestId("cleanup-keep-reading"));
    await waitFor(() => screen.getByTestId("cleanup-bar"));
    expect(screen.queryByTestId("cleanup-gate")).toBeNull();
    // The bar carries the action button but no dismiss affordance.
    expect(screen.getByTestId("cleanup-bar-resolve")).toBeTruthy();
    expect(screen.getByTestId("cleanup-bar").textContent).toContain(
      "sync.cleanupBar"
    );
    // Acting from the bar resolves too.
    daemonMock.mockImplementation((action) => {
      if (action === "vault.attach_resolve")
        return Promise.resolve(JSON.stringify({ discarded: 0 }));
      if (action === "vault.attach_status") return Promise.resolve(CLEAN);
      throw new Error(`unexpected action ${action}`);
    });
    fireEvent.click(screen.getByTestId("cleanup-bar-resolve"));
    await waitFor(() =>
      expect(toasts.success).toHaveBeenCalledWith(
        expect.stringContaining("sync.cleanupDoneNone")
      )
    );
    await waitFor(() => expect(screen.queryByTestId("cleanup-bar")).toBeNull());
  });

  it("a failed resolve surfaces the mapped toast and keeps the gate up", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "vault.attach_status") return Promise.resolve(REWRITTEN);
      if (action === "vault.attach_resolve")
        return Promise.reject(
          new Error(
            "Get the latest updates before making changes: another device cleaned up shared storage."
          )
        );
      throw new Error(`unexpected action ${action}`);
    });
    render(() => <StorageCleanupGate />);
    await waitFor(() => screen.getByTestId("cleanup-gate"));
    fireEvent.click(screen.getByTestId("cleanup-resolve"));
    await waitFor(() =>
      expect(toasts.error).toHaveBeenCalledWith(
        expect.stringContaining("Get the latest updates before making changes")
      )
    );
    // Still blocked.
    expect(screen.getByTestId("cleanup-gate")).toBeTruthy();
  });
});
