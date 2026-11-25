// UpdateContext decision-logic tests: install failure surfaces the error
// while keeping the offer retryable, check failures surface only on manual
// checks. The update lib is mocked at the module boundary (no Tauri IPC).

import { describe, expect, it, vi, beforeEach } from "vitest";

const mocks = vi.hoisted(() => ({
  status: vi.fn(),
  check: vi.fn(),
  install: vi.fn(),
  listen: vi.fn(async () => () => {}),
  listenMenu: vi.fn(async () => () => {}),
  toastSuccess: vi.fn(),
}));

vi.mock("../context/toastSignal.js", () => ({
  toastSuccess: mocks.toastSuccess,
}));

vi.mock("../lib/update.js", () => ({
  updaterStatus: mocks.status,
  updaterCheck: mocks.check,
  updaterInstall: mocks.install,
  listenUpdateProgress: mocks.listen,
  listenMenuCheckUpdates: mocks.listenMenu,
  noteCheckNow: vi.fn(),
  backgroundCheckDue: vi.fn(() => false),
  startupDelayMs: vi.fn(() => 0),
  CHECK_INTERVAL_MS: 3600_000,
}));

import { render } from "@solidjs/testing-library";
import { createEffect } from "solid-js";
import { I18nProvider } from "../i18n/index.jsx";
import { UpdateProvider, useUpdater } from "../context/UpdateContext.jsx";

// Mount the provider with a harness that captures the context value and
// resolves once the async status probe has landed (tracked reactively —
// a one-shot harness render runs before the probe resolves).
function mountWithUpdater() {
  let resolveReady;
  const ready = new Promise((r) => (resolveReady = r));
  let ref;
  const Harness = () => {
    ref = useUpdater();
    createEffect(
      () => ref?.status()?.configured,
      (ok) => {
        if (ok) resolveReady();
      },
    );
    return null;
  };
  render(() => (
    <I18nProvider>
      <UpdateProvider>
        <Harness />
      </UpdateProvider>
    </I18nProvider>
  ));
  return ready.then(() => ref);
}

describe("UpdateContext", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.status.mockResolvedValue({
      configured: true,
      channel: "stable",
      version: "0.1.2",
    });
  });

  it("keeps the offer retryable when the install fails", async () => {
    const offer = { version: "0.1.3", notes: null, currentVersion: "0.1.2" };
    mocks.check.mockResolvedValue(offer);
    mocks.install.mockRejectedValue(new Error("boom"));
    const u = await mountWithUpdater();

    await u.check({ manual: true });
    expect(u.available()?.version).toBe("0.1.3");
    expect(u.error()).toBeNull();

    await u.install();
    expect(u.error()).toBe("boom");
    // the offer survives: the banner's error-first view offers Retry
    expect(u.available()?.version).toBe("0.1.3");
    expect(u.installing()).toBe(false);
  });

  it("a manual check failure surfaces, a background one stays quiet", async () => {
    mocks.check.mockRejectedValue(new Error("offline"));
    const u = await mountWithUpdater();

    await u.check({ manual: false });
    expect(u.error()).toBeNull();

    await u.check({ manual: true });
    expect(u.error()).toBe("offline");
    expect(mocks.toastSuccess).not.toHaveBeenCalled();
  });

  it("a manual up-to-date check toasts, a background one stays quiet", async () => {
    mocks.check.mockResolvedValue(null);
    const u = await mountWithUpdater();

    await u.check({ manual: false });
    expect(mocks.toastSuccess).not.toHaveBeenCalled();

    await u.check({ manual: true });
    expect(u.upToDate()).toBe(true);
    expect(mocks.toastSuccess).toHaveBeenCalledTimes(1);
    expect(mocks.toastSuccess).toHaveBeenCalledWith("You're up to date.");
  });

  it("an available update shows the banner instead of a toast", async () => {
    mocks.check.mockResolvedValue({ version: "0.1.3", notes: null, currentVersion: "0.1.2" });
    const u = await mountWithUpdater();

    await u.check({ manual: true });
    expect(u.available()?.version).toBe("0.1.3");
    expect(mocks.toastSuccess).not.toHaveBeenCalled();
  });

  it("menu:check-updates triggers a manual check and toasts when up to date", async () => {
    let menuHandler;
    mocks.listenMenu.mockImplementationOnce(async (cb) => {
      menuHandler = cb;
      return () => {};
    });
    mocks.check.mockResolvedValue(null);
    await mountWithUpdater();

    expect(menuHandler).toBeTypeOf("function");
    menuHandler();
    await vi.waitFor(() => {
      expect(mocks.toastSuccess).toHaveBeenCalledWith("You're up to date.");
    });
  });
});
