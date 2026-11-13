import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { createSignal } from "solid-js";

// Real signal so reconciliation tests can move the polled state the way the
// 10s context poll would.
const [stateSig, setStateSig] = createSignal("idle");
vi.mock("../context/AutoSyncContext.jsx", () => ({
  useAutoSync: () => ({ active: () => true, state: () => stateSig() }),
}));
vi.mock("../lib/daemon.js", () => ({ daemon: vi.fn().mockResolvedValue("{}") }));
vi.mock("../i18n/index.jsx", () => ({ useI18n: () => ({ t: (k) => k, locale: () => "en" }) }));

import AutoSyncIndicator from "../components/AutoSyncIndicator.jsx";

// The leaving label lingers under <Transition> in jsdom (no transitionend),
// so phase assertions read the container title and the dot color — both
// render outside the Transition.
const indicator = (container) => container.querySelector(".autosync-indicator");
const title = (container) => indicator(container)?.getAttribute("title");
const dotClass = (container) =>
  indicator(container)?.querySelector("span.relative.inline-flex.rounded-full")?.className ?? "";

describe("AutoSyncIndicator manual sync", () => {
  beforeEach(() => {
    setStateSig("idle");
    cleanup();
  });

  // The component registers its window listeners in onSettled, and Solid
  // settles signal effects on a later tick — every dispatch needs a tick
  // before the DOM is asserted.
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const mount = async () => {
    const c = render(() => <AutoSyncIndicator />);
    await tick();
    return c;
  };

  it("a manual sync with no pending changes must not freeze at Changes pending", async () => {
    // The reported bug: the runtime state stays "idle" (never changes), the
    // poll never reconciles, and the dot sat at amber "Changes pending".
    const { container } = await mount();
    window.dispatchEvent(new CustomEvent("baluard:manual-sync", { detail: "start" }));
    await tick();
    expect(title(container)).toBe("autosync.syncing");
    expect(dotClass(container)).toContain("bg-[var(--color-primary)]");
    window.dispatchEvent(new CustomEvent("baluard:manual-sync", { detail: "success" }));
    await tick();
    expect(title(container)).toBe("autosync.upToDate");
    expect(dotClass(container)).toContain("bg-emerald-400");
    expect(dotClass(container)).not.toContain("bg-amber-400");
  });

  it("the native menu sync runs the pair and lands on synced", async () => {
    const { container } = await mount();
    window.dispatchEvent(new Event("baluard:sync-vault"));
    // The daemon mock resolves on the microtask queue; let the awaits and
    // the phase effects settle.
    await tick();
    await tick();
    expect(title(container)).toBe("autosync.upToDate");
    expect(dotClass(container)).toContain("bg-emerald-400");
  });

  it("a failed manual sync shows offline until a real state change", async () => {
    const { container } = await mount();
    window.dispatchEvent(new CustomEvent("baluard:manual-sync", { detail: "start" }));
    await tick();
    window.dispatchEvent(new CustomEvent("baluard:manual-sync", { detail: "failure" }));
    await tick();
    expect(title(container)).toBe("autosync.offline");
    // Still armed: a later polled transition reconciles away from offline.
    setStateSig("syncing");
    await tick();
    expect(title(container)).toBe("autosync.syncing");
  });

  it("mutation-armed waiting reconciles forward on polled transitions", async () => {
    const { container } = await mount();
    window.dispatchEvent(new CustomEvent("baluard:local-mutation"));
    await tick();
    expect(title(container)).toBe("sync.statusChangesPending");
    expect(dotClass(container)).toContain("bg-amber-400");
    setStateSig("syncing");
    await tick();
    expect(title(container)).toBe("autosync.syncing");
    setStateSig("idle");
    await tick();
    expect(title(container)).toBe("autosync.upToDate");
    expect(dotClass(container)).toContain("bg-emerald-400");
  });
});
