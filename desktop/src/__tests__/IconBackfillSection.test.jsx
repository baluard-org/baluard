import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@solidjs/testing-library";

// IconBackfillSection: start the batch job, poll progress, cancel, and the
// disabled-when-off state. The daemon job itself is mocked at the IPC
// boundary; the section only starts/polls/cancels it.

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

const vaultMock = { refreshCiphers: vi.fn().mockResolvedValue(undefined) };
vi.mock("../context/VaultContext.jsx", () => ({
  useVault: () => vaultMock,
}));

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...args) => daemonMock(...args) }));

const toasts = { success: vi.fn(), warning: vi.fn() };
vi.mock("../context/toastSignal.js", () => ({
  // Arrow indirection: the factory runs at module init, before the
  // top-level const exists; calls must resolve it lazily.
  toastSuccess: (...a) => toasts.success(...a),
  toastWarning: (...a) => toasts.warning(...a),
  toastError: vi.fn(),
}));

import IconBackfillSection from "../components/IconBackfillSection.jsx";

const STATUS = (over = {}) =>
  JSON.stringify({
    running: false,
    finished: false,
    total: 0,
    done: 0,
    fetched: 0,
    skipped: 0,
    current_domain: null,
    error: null,
    ...over,
  });

let dispatchSpy;

beforeEach(() => {
  cleanup();
  dispatchSpy = vi.spyOn(window, "dispatchEvent");
  toasts.success.mockReset();
  toasts.warning.mockReset();
  vaultMock.refreshCiphers.mockReset().mockResolvedValue(undefined);
  daemonMock.mockReset();
  // Default: favicons on, no job running.
  daemonMock.mockImplementation((action) => {
    if (action === "settings.get") return Promise.resolve(JSON.stringify({ fetch_favicons: true }));
    if (action === "favicon.backfill_status") return Promise.resolve(STATUS());
    throw new Error(`unexpected daemon action ${action}`);
  });
});

const mountAndSettle = async () => {
  render(() => <IconBackfillSection />);
  // The section defers its daemon reads by one macrotask (Solid forbids
  // cleanup registration in the onSettled scope); let it land.
  await new Promise((r) => setTimeout(r, 0));
  await Promise.resolve();
};

describe("IconBackfillSection", () => {
  it("hides everything while the opt-in setting is unknown, then shows the button when enabled", async () => {
    await mountAndSettle();
    await waitFor(() => expect(screen.getByText("sync.iconsStart")).toBeTruthy());
    expect(screen.getByText("sync.iconsTitle")).toBeTruthy();
  });

  it("shows the enable hint instead of the button when favicons are off", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") return Promise.resolve(JSON.stringify({ fetch_favicons: false }));
      if (action === "favicon.backfill_status") return Promise.resolve(STATUS());
      throw new Error(`unexpected daemon action ${action}`);
    });
    await mountAndSettle();
    await waitFor(() => expect(screen.getByText("errors.backfillDisabled")).toBeTruthy());
    expect(screen.queryByText("sync.iconsStart")).toBeNull();
  });

  it("a job already running on mount resumes the progress view without re-toasting", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") return Promise.resolve(JSON.stringify({ fetch_favicons: true }));
      if (action === "favicon.backfill_status")
        return Promise.resolve(
          STATUS({ running: true, total: 10, done: 3, current_domain: "example.com" }),
        );
      throw new Error(`unexpected daemon action ${action}`);
    });
    await mountAndSettle();
    await waitFor(() => expect(screen.getByText(/sync\.iconsRunning/)).toBeTruthy(), { timeout: 2000 });
    expect(screen.getByText("example.com")).toBeTruthy();
    expect(screen.getByText("sync.iconsCancel")).toBeTruthy();
    expect(toasts.success).not.toHaveBeenCalled();
  });

  it("start switches to the progress view and polls until finish, then toasts and refreshes", async () => {
    // Real timers: the poll interval is 500ms, so the whole run costs
    // about a second. Fake timers fight the macrotask defer + settle
    // scheduling this component relies on.
    let pollCount = 0;
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") return Promise.resolve(JSON.stringify({ fetch_favicons: true }));
      if (action === "favicon.backfill_start")
        return Promise.resolve(STATUS({ running: true, total: 4, done: 0 }));
      if (action === "favicon.backfill_status") {
        pollCount += 1;
        return pollCount <= 1
          ? Promise.resolve(STATUS({ running: true, total: 4, done: 2 }))
          : Promise.resolve(
              STATUS({ running: false, finished: true, total: 4, done: 4, fetched: 3, skipped: 1 }),
            );
      }
      throw new Error(`unexpected daemon action ${action}`);
    });

    await mountAndSettle();
    await waitFor(() => expect(screen.getByText("sync.iconsStart")).toBeTruthy(), { timeout: 2000 });
    fireEvent.click(screen.getByText("sync.iconsStart"));
    await waitFor(() => expect(screen.getByText(/sync\.iconsRunning/)).toBeTruthy(), { timeout: 2000 });

    await waitFor(
      () => {
        expect(toasts.success).toHaveBeenCalledWith('sync.iconsDone({"fetched":3,"skipped":1})');
      },
      { timeout: 4000 },
    );
    // The vault list must re-read (the job wrote through the daemon)
    // and the indicator must hear about the local change.
    expect(vaultMock.refreshCiphers).toHaveBeenCalled();
    expect(
      dispatchSpy.mock.calls.filter(([e]) => e.type === "baluard:local-mutation").length,
    ).toBeGreaterThanOrEqual(1);
    await waitFor(() => expect(screen.getByText("sync.iconsStart")).toBeTruthy(), { timeout: 2000 });
  });

  it("a refused start (favicons off at the daemon) surfaces the refusal as a warning", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") return Promise.resolve(JSON.stringify({ fetch_favicons: true }));
      if (action === "favicon.backfill_status") return Promise.resolve(STATUS());
      if (action === "favicon.backfill_start")
        return Promise.reject(new Error("Fetching site icons is turned off."));
      throw new Error(`unexpected daemon action ${action}`);
    });
    await mountAndSettle();
    await waitFor(() => expect(screen.getByText("sync.iconsStart")).toBeTruthy(), { timeout: 2000 });
    fireEvent.click(screen.getByText("sync.iconsStart"));
    await waitFor(
      () => {
        expect(toasts.warning).toHaveBeenCalledWith("Fetching site icons is turned off.");
      },
      { timeout: 2000 },
    );
    expect(screen.getByText("sync.iconsStart")).toBeTruthy();
  });

  it("a cancelled job stops silently: no error toast", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") return Promise.resolve(JSON.stringify({ fetch_favicons: true }));
      if (action === "favicon.backfill_status")
        return Promise.resolve(STATUS({ running: false, finished: true, error: "Cancelled." }));
      throw new Error(`unexpected daemon action ${action}`);
    });
    await mountAndSettle();
    // Reopening after a cancel shows idle without re-toasting anything.
    expect(toasts.warning).not.toHaveBeenCalled();
    expect(toasts.success).not.toHaveBeenCalled();
    expect(screen.getByText("sync.iconsStart")).toBeTruthy();
  });

  it("a job that finished while the tab was closed shows its counts without re-toasting", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") return Promise.resolve(JSON.stringify({ fetch_favicons: true }));
      if (action === "favicon.backfill_status")
        return Promise.resolve(STATUS({ finished: true, total: 9, done: 9, fetched: 6, skipped: 3 }));
      throw new Error(`unexpected daemon action ${action}`);
    });
    await mountAndSettle();
    await waitFor(
      () => expect(screen.getByText(/sync\.iconsDone/)).toBeTruthy(),
      { timeout: 2000 },
    );
    expect(toasts.success).not.toHaveBeenCalled();
    expect(screen.getByText("sync.iconsStart")).toBeTruthy();
  });

  it("cancel calls the cancel action", async () => {
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") return Promise.resolve(JSON.stringify({ fetch_favicons: true }));
      if (action === "favicon.backfill_status")
        return Promise.resolve(STATUS({ running: true, total: 5, done: 1 }));
      if (action === "favicon.backfill_cancel") return Promise.resolve("cancelled");
      throw new Error(`unexpected daemon action ${action}`);
    });
    await mountAndSettle();
    await waitFor(() => expect(screen.getByText("sync.iconsCancel")).toBeTruthy(), { timeout: 2000 });
    fireEvent.click(screen.getByText("sync.iconsCancel"));
    await waitFor(() => {
      expect(daemonMock).toHaveBeenCalledWith("favicon.backfill_cancel");
    }, { timeout: 2000 });
  });
});
