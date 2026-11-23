import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";

const { daemonMock } = await vi.hoisted(() => ({ daemonMock: vi.fn() }));

vi.mock("../lib/daemon.js", () => ({ daemon: (...a) => daemonMock(...a) }));
vi.mock("../lib/clipboard.js", () => ({
  copyToClipboard: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("../context/toastSignal.js", () => ({
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}));
vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({
    t: (key, vars) => key + (vars ? " " + Object.values(vars).join(" ") : ""),
  }),
}));

import { flush } from "solid-js";

import McpPairingsSection from "../components/McpPairingsSection.jsx";

const statusPayload = (pairings = [], server = { running: true, port: 17990, error: null }) =>
  JSON.stringify({ server, pairings });

const pairingRow = (over = {}) => ({
  id: "pair-1",
  name: "Claude Code",
  vault_slug: "personal",
  created_at_ms: Date.UTC(2026, 10, 22, 12, 0, 0),
  yolo_expires_in_secs: null,
  ...over,
});

describe("McpPairingsSection", () => {
  beforeEach(() => {
    cleanup();
    daemonMock.mockReset();
    daemonMock.mockResolvedValue(statusPayload());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("reports a running endpoint with its port", async () => {
    daemonMock.mockResolvedValue(statusPayload());
    const screen = render(() => <McpPairingsSection />);
    await waitFor(() => expect(screen.getByTestId("mcp-server-status").textContent).toContain("17990"));
  });

  it("fails closed visibly when the endpoint could not bind", async () => {
    daemonMock.mockResolvedValue(
      statusPayload([], { running: false, port: 17990, error: "bind refused" }),
    );
    const screen = render(() => <McpPairingsSection />);
    await waitFor(() => expect(screen.getByTestId("mcp-server-error").textContent).toContain("bind refused"));
  });

  it("pairs an agent and shows the one-time token plus the snippet", async () => {
    daemonMock.mockImplementation(async (action) => {
      if (action === "mcp.status") return statusPayload();
      if (action === "mcp.pair")
        return JSON.stringify({
          pairing: { id: "pair-9", name: "Cursor", created_at_ms: 1 },
          token: "blrd_mcp_abc123",
        });
      throw new Error("unexpected " + action);
    });
    const screen = render(() => <McpPairingsSection />);
    await waitFor(() => screen.getByTestId("mcp-pair-name"));
    fireEvent.input(screen.getByTestId("mcp-pair-name"), {
      target: { value: "Cursor" },
    });
    flush();
    fireEvent.click(screen.getByTestId("mcp-pair"));
    await waitFor(() => screen.getByTestId("mcp-new-pairing"));
    expect(screen.getByTestId("mcp-copy-token").textContent).toBeTruthy();
    const snippet = screen.getByTestId("mcp-snippet").textContent;
    expect(snippet).toContain("blrd_mcp_abc123");
    expect(snippet).toContain("http://127.0.0.1:17990/mcp");
    expect(daemonMock).toHaveBeenCalledWith("mcp.pair", { name: "Cursor" });
  });

  it("does not call pair with a blank name", async () => {
    const screen = render(() => <McpPairingsSection />);
    await waitFor(() => screen.getByTestId("mcp-pair-name"));
    fireEvent.click(screen.getByTestId("mcp-pair"));
    expect(daemonMock).not.toHaveBeenCalledWith("mcp.pair", expect.anything());
  });

  it("revokes a pairing", async () => {
    daemonMock.mockImplementation(async (action) => {
      if (action === "mcp.status") return statusPayload([pairingRow()]);
      if (action === "mcp.revoke") return JSON.stringify({ revoked: true });
      throw new Error("unexpected " + action);
    });
    const screen = render(() => <McpPairingsSection />);
    await waitFor(() => screen.getByTestId("mcp-revoke"));
    fireEvent.click(screen.getByTestId("mcp-revoke"));
    await waitFor(() =>
      expect(daemonMock).toHaveBeenCalledWith("mcp.revoke", { pairing_id: "pair-1" }),
    );
  });

  it("shows a live auto-approve window per pairing", async () => {
    daemonMock.mockResolvedValue(
      statusPayload([pairingRow({ yolo_expires_in_secs: 420 })]),
    );
    const screen = render(() => <McpPairingsSection />);
    await waitFor(() => screen.getByTestId("mcp-yolo-pair-1"));
    expect(screen.getByTestId("mcp-pairing-row").textContent).toContain("mcp.expiresIn");
  });

  it("turning auto-approve off calls yolo_set without a password", async () => {
    let live = true;
    daemonMock.mockImplementation(async (action, payload) => {
      if (action === "mcp.status") {
        const rows = live ? [pairingRow({ yolo_expires_in_secs: 420 })] : [pairingRow()];
        return statusPayload(rows);
      }
      if (action === "mcp.yolo_set") {
        if (payload.enabled === false) live = false;
        return JSON.stringify({ enabled: false, yolo_expires_in_secs: null });
      }
      throw new Error("unexpected " + action);
    });
    const screen = render(() => <McpPairingsSection />);
    const toggle = await waitFor(() => screen.getByTestId("mcp-yolo-pair-1"));
    const input = toggle.querySelector('input[type="checkbox"]') || toggle;
    fireEvent.click(input);
    await waitFor(() =>
      expect(daemonMock).toHaveBeenCalledWith(
        "mcp.yolo_set",
        expect.objectContaining({ pairing_id: "pair-1", enabled: false }),
      ),
    );
    // The kill path never sends a master password.
    const call = daemonMock.mock.calls.find((c) => c[0] === "mcp.yolo_set");
    expect(call[1].master_password).toBeUndefined();
  });
});
