import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, waitFor, cleanup } from "@solidjs/testing-library";

const mocks = vi.hoisted(() => ({
  daemon: vi.fn(),
  invoke: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock("../lib/daemon.js", () => ({ daemon: mocks.daemon }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("../i18n/index.jsx", () => ({ useI18n: () => ({ t: (key) => key }) }));
vi.mock("../context/VaultContext.jsx", () => ({
  useVault: () => ({ ciphers: () => [{ id: "item-1", name: "GitHub" }] }),
}));
vi.mock("../context/VaultSwitcherContext.jsx", () => ({
  useVaultSwitcher: () => ({ activeSlug: () => "personal" }),
}));
vi.mock("../context/toastSignal.js", () => ({
  toastSuccess: mocks.toastSuccess,
  toastError: mocks.toastError,
}));
vi.mock("../components/AgentApprovalModal.jsx", () => ({ default: () => null }));

import { AgentApprovalProvider, useAgentApprovals } from "../context/AgentApprovalContext.jsx";

const pendingRow = {
  request_id: "req-1",
  claimed_name: "Local agent",
  exe_path: "/usr/bin/local-agent",
  need: "deploy",
  item_ids: ["item-1"],
};

function payloadFor(action) {
  if (action === "agents.pending") {
    return JSON.stringify({ pending: [pendingRow] });
  }
  if (action === "agents.list") {
    return JSON.stringify({ grants: [{ exe_path: "/usr/bin/local-agent", item_ids: ["item-1"] }], yolo: false });
  }
  return "{}";
}

describe("AgentApprovalProvider", () => {
  let api;
  function Capture() {
    api = useAgentApprovals();
    return null;
  }

  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
    mocks.daemon.mockImplementation(async (action) => payloadFor(action));
    mocks.invoke.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.useRealTimers();
    cleanup();
  });

  it("polls pending and running grants, then stops after unmount", async () => {
    vi.useFakeTimers();
    const view = render(() => <AgentApprovalProvider><Capture /></AgentApprovalProvider>);
    await vi.advanceTimersByTimeAsync(0);
    expect(api.pending()).toHaveLength(1);
    expect(api.grants()).toHaveLength(1);
    const before = mocks.daemon.mock.calls.length;
    await vi.advanceTimersByTimeAsync(2100);
    expect(mocks.daemon.mock.calls.length).toBeGreaterThan(before);
    view.unmount();
    const stopped = mocks.daemon.mock.calls.length;
    await vi.advanceTimersByTimeAsync(5000);
    expect(mocks.daemon.mock.calls.length).toBe(stopped);
  });

  it("approves, denies, and revokes through the expected routes", async () => {
    render(() => <AgentApprovalProvider><Capture /></AgentApprovalProvider>);
    await waitFor(() => expect(api.pending()).toHaveLength(1));
    await api.approve("req-1");
    expect(mocks.daemon).toHaveBeenCalledWith("agents.approve", { request_id: "req-1" });
    expect(api.pending()).toHaveLength(0);
    await api.deny("req-2");
    expect(mocks.daemon).toHaveBeenCalledWith("agents.deny", { request_id: "req-2" });
    await api.revoke();
    expect(mocks.daemon).toHaveBeenCalledWith("agents.revoke");
    expect(api.grants()).toHaveLength(0);
  });

  it("sends the verified password only when permissive mode is enabled", async () => {
    render(() => <AgentApprovalProvider><Capture /></AgentApprovalProvider>);
    await waitFor(() => expect(api.grants()).toHaveLength(1));
    await api.setYolo(true, "verified-password");
    expect(mocks.daemon).toHaveBeenCalledWith("agents.set_yolo", {
      enabled: true,
      master_password: "verified-password",
    });
    await api.setYolo(false);
    expect(mocks.daemon).toHaveBeenCalledWith("agents.set_yolo", { enabled: false });
  });

  it("notifies a hidden app once per request", async () => {
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    render(() => <AgentApprovalProvider><Capture /></AgentApprovalProvider>);
    await waitFor(() => expect(api.pending()).toHaveLength(1));
    await api.refresh();
    expect(mocks.invoke).toHaveBeenCalledTimes(1);
    expect(mocks.invoke).toHaveBeenCalledWith("notify_agent_request", {
      title: "agents.notifyTitle",
      body: "agents.notifyBody",
    });
    Object.defineProperty(document, "hidden", { configurable: true, value: false });
  });
});
