import { afterEach, describe, expect, it, vi } from "vitest";
import { createSignal, createRoot, flush } from "solid-js";
import { render } from "@solidjs/web";

// Mock daemon so the autosync poll (every 10s) + the needsdecision fetch don't
// hit real IPC. Default: nothing active, idle.
const daemonMock = vi.fn(async () => JSON.stringify({ active: false, state: "idle" }));
vi.mock("../lib/daemon.js", () => ({
  daemon: (...args) => daemonMock(...args),
  showWindow: vi.fn(),
}));
vi.mock("../lib/conflictFlow.js", () => ({
  fetchPendingConflict: vi.fn(async () => ({ pending: false })),
  toPendingConflict: vi.fn(),
  resolveConflict: vi.fn(),
}));

import { ConflictResolutionProvider, useConflictResolution } from "../context/ConflictResolutionContext.jsx";
import { mockSampleConflict } from "../lib/conflictMocks.js";
import { AutoSyncProvider } from "../context/AutoSyncContext.jsx";
import { VaultSwitcherContext } from "../context/VaultSwitcherContext.jsx";

// A minimal controllable VaultSwitcher so we can flip activeSlug mid-test.
// AutoSyncContext only reads activeSlug() from it, so a signal is enough.
function makeFakeSwitcher() {
  const [activeSlug, setActiveSlug] = createSignal("vault-a");
  return { activeSlug, setActiveSlug };
}

// Mount AutoSyncProvider inside a fake VaultSwitcher + ConflictResolutionProvider.
// Returns the conflict queue handle + the switcher setter to drive a switch.
function mount() {
  const switcher = makeFakeSwitcher();
  const wrap = document.createElement("div");
  document.body.appendChild(wrap);
  let conflicts;
  const Capture = () => {
    conflicts = useConflictResolution();
    return null;
  };
  const dispose = createRoot((disposeFn) => {
    render(
      () => (
        <VaultSwitcherContext value={switcher}>
          <ConflictResolutionProvider>
            <AutoSyncProvider>
              <Capture />
            </AutoSyncProvider>
          </ConflictResolutionProvider>
        </VaultSwitcherContext>
      ),
      wrap,
    );
    return disposeFn;
  });
  return {
    conflicts,
    setActiveSlug: switcher.setActiveSlug,
    cleanup: () => {
      dispose();
      wrap.remove();
    },
  };
}

afterEach(() => {
  daemonMock.mockClear();
  document.body.innerHTML = "";
});

describe("AutoSyncContext vault-switch conflict clear (Phase 4)", () => {
  it("clears the conflict queue when the active vault switches", () => {
    const { conflicts, setActiveSlug, cleanup } = mount();

    // Enqueue a conflict for vault A.
    conflicts.enqueue(mockSampleConflict({ cipherId: "a-conflict" }));
    flush();
    expect(conflicts.hasPending()).toBe(true);

    // Switch to vault B. AutoSyncContext's createEffect on activeSlug fires
    // conflicts.clear() so vault A's conflict doesn't bleed into vault B.
    setActiveSlug("vault-b");
    flush();
    flush();
    expect(conflicts.hasPending()).toBe(false);
    expect(conflicts.count()).toBe(0);

    cleanup();
  });

  it("does NOT clear the queue when the slug stays the same (no spurious clear)", () => {
    const { conflicts, setActiveSlug, cleanup } = mount();
    conflicts.enqueue(mockSampleConflict({ cipherId: "a-conflict" }));
    flush();
    expect(conflicts.hasPending()).toBe(true);

    // Setting the same slug is a no-op for the clear effect.
    setActiveSlug("vault-a");
    flush();
    flush();
    expect(conflicts.hasPending()).toBe(true);

    cleanup();
  });
});
