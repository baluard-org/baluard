// UpdateContext decision-logic tests: install failure surfaces the error
// while keeping the offer retryable, check failures surface only on manual
// checks. The update lib is mocked at the module boundary (no Tauri IPC).

import { describe, expect, it, vi, beforeEach } from "vitest";

const mocks = vi.hoisted(() => ({
  status: vi.fn(),
  check: vi.fn(),
  install: vi.fn(),
  listen: vi.fn(async () => () => {}),
}));

vi.mock("../lib/update.js", () => ({
  updaterStatus: mocks.status,
  updaterCheck: mocks.check,
  updaterInstall: mocks.install,
  listenUpdateProgress: mocks.listen,
  noteCheckNow: vi.fn(),
  backgroundCheckDue: vi.fn(() => false),
  startupDelayMs: vi.fn(() => 0),
  CHECK_INTERVAL_MS: 3600_000,
}));

import { render } from "@solidjs/testing-library";
import { createEffect } from "solid-js";
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
    <UpdateProvider>
      <Harness />
    </UpdateProvider>
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
  });
});
