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

  it("runs the guarded full reconcile and confirms", async () => {
    daemonMock.mockResolvedValue("\"up_to_date\"");
    const { container } = render(() => <SyncButton />);
    fireEvent.click(container.querySelector("[data-testid='sync-now']"));
    await waitFor(() => expect(toastSuccessMock).toHaveBeenCalled(), { timeout: 3000 });
    const actions = daemonMock.mock.calls.map((c) => c[0]);
    expect(actions).toEqual(["sync.now"]);
  });

  it("is disabled while a sync is in flight", async () => {
    let resolveSync;
    daemonMock.mockImplementation((action) => {
      if (action === "sync.now") return new Promise((r) => { resolveSync = r; });
      return Promise.resolve("{}");
    });
    const { container } = render(() => <SyncButton />);
    const btn = container.querySelector("[data-testid='sync-now']");
    fireEvent.click(btn);
    await waitFor(() => expect(btn.disabled).toBe(true));
    fireEvent.click(btn);
    expect(daemonMock.mock.calls.filter((c) => c[0] === "sync.now")).toHaveLength(1);
    resolveSync("{}");
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

describe("SyncButton indicator events", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    toastSuccessMock.mockClear();
    toastErrorMock.mockClear();
    cleanup();
  });

  // The titlebar indicator cannot reconcile a manual sync from polled state:
  // with nothing pending the runtime stays "idle", the polled value never
  // changes, and the dot froze at "Changes pending" forever. The button must
  // drive the indicator's phases directly.
  it("drives the indicator with manual-sync start/success events", async () => {
    daemonMock.mockResolvedValue("{}");
    const seen = [];
    const listener = (e) => seen.push([e.type, e.detail]);
    window.addEventListener("baluard:manual-sync", listener);
    const { container } = render(() => <SyncButton />);
    fireEvent.click(container.querySelector("[data-testid='sync-now']"));
    await waitFor(() => expect(toastSuccessMock).toHaveBeenCalled(), { timeout: 3000 });
    window.removeEventListener("baluard:manual-sync", listener);
    expect(seen).toEqual([["baluard:manual-sync", "start"], ["baluard:manual-sync", "success"]]);
  });

  it("reports failure to the indicator instead of success", async () => {
    daemonMock.mockRejectedValue(new Error("offline"));
    const seen = [];
    const listener = (e) => seen.push(e.detail);
    window.addEventListener("baluard:manual-sync", listener);
    const { container } = render(() => <SyncButton />);
    fireEvent.click(container.querySelector("[data-testid='sync-now']"));
    await waitFor(() => expect(toastErrorMock).toHaveBeenCalled(), { timeout: 3000 });
    window.removeEventListener("baluard:manual-sync", listener);
    expect(seen).toEqual(["start", "failure"]);
  });
});
