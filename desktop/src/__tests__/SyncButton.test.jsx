import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...a) => daemonMock(...a) }));
const toastSuccessMock = vi.fn();
const toastErrorMock = vi.fn();
vi.mock("../context/toastSignal.js", () => ({
  toastSuccess: (...a) => toastSuccessMock(...a),
  toastError: (...a) => toastErrorMock(...a),
}));
vi.mock("../i18n/index.jsx", () => ({ useI18n: () => ({ t: (k) => k, locale: () => "en" }) }));

import SyncButton from "../components/SyncButton.jsx";

describe("SyncButton", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    toastSuccessMock.mockClear();
    toastErrorMock.mockClear();
    cleanup();
  });

  it("runs pull then push and confirms", async () => {
    daemonMock.mockResolvedValue("{}");
    const { container } = render(() => <SyncButton />);
    fireEvent.click(container.querySelector("[data-testid='sync-now']"));
    await waitFor(() => expect(toastSuccessMock).toHaveBeenCalled(), { timeout: 3000 });
    const actions = daemonMock.mock.calls.map((c) => c[0]);
    expect(actions).toEqual(["sync.pull", "sync.push"]);
  });

  it("is disabled while a sync is in flight", async () => {
    let resolvePull;
    daemonMock.mockImplementation((action) => {
      if (action === "sync.pull") return new Promise((r) => { resolvePull = r; });
      return Promise.resolve("{}");
    });
    const { container } = render(() => <SyncButton />);
    const btn = container.querySelector("[data-testid='sync-now']");
    fireEvent.click(btn);
    await waitFor(() => expect(btn.disabled).toBe(true));
    fireEvent.click(btn);
    expect(daemonMock.mock.calls.filter((c) => c[0] === "sync.pull")).toHaveLength(1);
    resolvePull("{}");
    await waitFor(() => expect(btn.disabled).toBe(false));
  });

  it("surfaces a failure instead of confirming", async () => {
    daemonMock.mockRejectedValue(new Error("offline"));
    const { container } = render(() => <SyncButton />);
    fireEvent.click(container.querySelector("[data-testid='sync-now']"));
    await waitFor(() => expect(toastErrorMock).toHaveBeenCalled(), { timeout: 3000 });
    expect(toastSuccessMock).not.toHaveBeenCalled();
  });
});
