import { afterEach, describe, expect, it, vi } from "vitest";
import { createRoot, flush } from "solid-js";
import { render } from "@solidjs/web";

// Mock the IPC layer so clicks don't hit the daemon. The panel's default
// resolver calls resolveConflict; we spy on it to assert the verdict wiring.
const resolveConflictMock = vi.fn(async () => ({ resolved: true, remaining: 0 }));
vi.mock("../lib/conflictFlow.js", () => ({
  resolveConflict: (verdict) => resolveConflictMock(verdict),
  // unused by the panel but exported from the module:
  fetchPendingConflict: vi.fn(),
  toPendingConflict: vi.fn(),
}));
vi.mock("../lib/daemon.js", () => ({ daemon: vi.fn(), showWindow: vi.fn() }));

import { I18nProvider } from "../i18n/index.jsx";
import {
  ConflictResolutionProvider,
  useConflictResolution,
} from "../context/ConflictResolutionContext.jsx";
import { mockSampleConflict, mockSampleTypeChange } from "../lib/conflictMocks.js";
import ConflictResolutionPanel from "../components/ConflictResolutionPanel.jsx";

// Mount the panel (inside its providers) in a fresh DOM node. The panel
// renders into document.body via <Portal>, so assertions query document.body.
// Registers state on a module-level ref so afterEach can dispose + clean DOM
// even if an assertion throws mid-test (otherwise a leaked live Portal from a
// failed test pollutes the next test's querySelector — cascading false
// results).
let _dispose = null;
let _wrap = null;

function mountPanel() {
  _wrap = document.createElement("div");
  document.body.appendChild(_wrap);
  let conflicts;
  const Capture = () => {
    conflicts = useConflictResolution();
    return null;
  };
  _dispose = createRoot((disposeFn) => {
    render(
      () => (
        <I18nProvider>
          <ConflictResolutionProvider>
            <Capture />
            <ConflictResolutionPanel />
          </ConflictResolutionProvider>
        </I18nProvider>
      ),
      _wrap,
    );
    return disposeFn;
  });
  return conflicts;
}

afterEach(() => {
  resolveConflictMock.mockClear();
  if (_dispose) {
    _dispose();
    _dispose = null;
  }
  if (_wrap) {
    _wrap.remove();
    _wrap = null;
  }
  // Portal content renders at document.body, not inside the mount node.
  document.body.innerHTML = "";
});

describe("ConflictResolutionPanel", () => {
  it("renders nothing when the queue is empty", () => {
    mountPanel();
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  });

  it("renders the modal with role/aria + 3 decision buttons when a conflict is enqueued", () => {
    const conflicts = mountPanel();
    conflicts.enqueue(mockSampleConflict({ name: "GitHub" }));
    flush();

    const dialog = document.querySelector('[role="alertdialog"]');
    expect(dialog).not.toBeNull();
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(dialog.getAttribute("aria-labelledby")).toBe("conflict-title");
    expect(dialog.getAttribute("aria-describedby")).toBe("conflict-desc");

    // 3 decision buttons by their i18n'd titles (English locale).
    const texts = [...document.querySelectorAll("button")].map((b) =>
      b.textContent.trim(),
    );
    expect(texts.some((t) => t.includes("Keep this device's version"))).toBe(true);
    expect(texts.some((t) => t.includes("Keep the other device's version"))).toBe(
      true,
    );
    expect(texts.some((t) => t.includes("Keep both as separate items"))).toBe(true);
  });

  // Helper: find a decision button by its title substring.
  function findButton(substr) {
    const buttons = [...document.querySelectorAll("button")];
    return buttons.find((b) => b.textContent.includes(substr));
  }

  it("clicking 'keep local' calls the resolver with keep_local and clears the queue", async () => {
    const conflicts = mountPanel();
    conflicts.enqueue(mockSampleConflict({ cipherId: "c1" }));
    flush();

    findButton("Keep this device's version").click();
    // Flush the async resolver + queue update. vi.waitFor is robust to the
    // exact microtask hop count (the panel's decide() awaits resolve()).
    await vi.waitFor(() => expect(resolveConflictMock).toHaveBeenCalledTimes(1));
    expect(resolveConflictMock).toHaveBeenCalledWith("keep_local");
    await vi.waitFor(() => expect(conflicts.hasPending()).toBe(false));
  });

  it("routes keep_remote and keep_both verdicts to the resolver correctly", async () => {
    const conflicts = mountPanel();
    conflicts.enqueue(mockSampleConflict({ cipherId: "c1" }));
    flush();

    findButton("Keep the other device's version").click();
    await vi.waitFor(() =>
      expect(resolveConflictMock).toHaveBeenCalledWith("keep_remote"),
    );
    await vi.waitFor(() => expect(conflicts.hasPending()).toBe(false));

    // Second conflict -> keep_both. The panel unmounted on the drain; wait for
    // the c2 buttons to re-mount before clicking.
    conflicts.enqueue(mockSampleConflict({ cipherId: "c2" }));
    flush();
    await vi.waitFor(() =>
      expect(findButton("Keep both as separate items")).toBeTruthy(),
    );
    findButton("Keep both as separate items").click();
    await vi.waitFor(() =>
      expect(resolveConflictMock).toHaveBeenCalledWith("keep_both"),
    );
  });

  it("shows the type-changed block (not the field chips) when typeChanged is true", () => {
    const conflicts = mountPanel();
    conflicts.enqueue(mockSampleTypeChange());
    flush();

    const bodyText = document.querySelector('[role="alertdialog"]').textContent;
    expect(bodyText).toContain("different type");
    // The field-chip section header "What changed" should NOT render.
    expect(bodyText).not.toContain("What changed");
  });

  it("renders the mask bullet for sensitive field labels", () => {
    const conflicts = mountPanel();
    // Include a hypothetical plaintext `value` on the sensitive field to prove
    // the component never renders it even if present (the real wire contract
    // omits values; this hardens against a future regression).
    conflicts.enqueue(
      mockSampleConflict({
        fields: [
          { key: "password", label: "Password", sensitive: true, value: "hunter2-leak" },
          { key: "notes", label: "Notes", sensitive: false },
        ],
      }),
    );
    flush();

    const chips = [...document.querySelectorAll("li")];
    const labels = chips.map((c) => c.textContent);
    expect(labels.some((l) => l.includes("Password"))).toBe(true);
    expect(labels.some((l) => l.includes("Notes"))).toBe(true);
    // Sensitive chip shows the bullet mask.
    expect(chips.some((c) => c.textContent.includes("••••"))).toBe(true);
    // No plaintext secret value anywhere in the rendered panel.
    expect(
      document.querySelector('[role="alertdialog"]').textContent,
    ).not.toContain("hunter2-leak");
  });

  it("isResolving guards against double-click + disables buttons during in-flight resolve", async () => {
    const conflicts = mountPanel();
    conflicts.enqueue(mockSampleConflict({ cipherId: "c1" }));
    flush();

    // Resolver that stays pending until we resolve it — simulates an IPC in
    // flight long enough for a second click to land.
    let releaseResolve;
    resolveConflictMock.mockImplementationOnce(
      () => new Promise((resolve) => (releaseResolve = resolve)),
    );

    const btn = findButton("Keep this device's version");
    btn.click(); // first click -> isResolving=true
    // Buttons must disable while the resolver is in flight (re-entrancy guard
    // against last-write-wins on a destructive UI).
    await vi.waitFor(() => expect(btn.disabled).toBe(true));

    // Second click while in flight must NOT fire a second resolve.
    btn.click();
    expect(resolveConflictMock).toHaveBeenCalledTimes(1);

    releaseResolve({ resolved: true, remaining: 0 });
    // The queue drains on success (the meaningful completion signal). NB: once
    // hasPending() is false the panel unmounts via <Show>, so the button node
    // goes stale — we assert on the queue, not the detached button's disabled.
    await vi.waitFor(() => expect(conflicts.hasPending()).toBe(false));
  });

  it("on resolver error: keeps the conflict in the queue + surfaces a toast (retry-friendly)", async () => {
    const conflicts = mountPanel();
    conflicts.enqueue(mockSampleConflict({ cipherId: "c1" }));
    flush();

    resolveConflictMock.mockRejectedValueOnce(new Error("IPC down"));
    findButton("Keep this device's version").click();

    // The conflict stays (resolve() re-throws, head not dropped); the panel's
    // decide() catches it + fires toastError. User can retry.
    await vi.waitFor(() => expect(resolveConflictMock).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(conflicts.hasPending()).toBe(true));
    expect(conflicts.current().cipherId).toBe("c1");
    // isResolving must reset even on the error path (finally) so retry works.
    await vi.waitFor(() =>
      expect(findButton("Keep this device's version").disabled).toBe(false),
    );
  });

  it("mock head (dev trigger): drains the queue WITHOUT calling the real IPC resolver", async () => {
    const conflicts = mountPanel();
    // Dev-trigger mocks enqueue with { mock: true } — the daemon has no
    // matching pending_conflict, so a real sync.conflict.resolve would toast.
    // The __mock flag on the item swaps in a no-op resolver so clicks drain
    // the queue locally.
    conflicts.enqueue(mockSampleConflict({ cipherId: "mock-1" }), { mock: true });
    flush();

    findButton("Keep this device's version").click();
    await vi.waitFor(() => expect(conflicts.hasPending()).toBe(false));
    // The real IPC resolver must NOT be called for a mock head.
    expect(resolveConflictMock).not.toHaveBeenCalled();
  });

  it("mock flag is per-item: a real conflict behind a mock still uses the IPC resolver", async () => {
    const conflicts = mountPanel();
    // Mock first, then a REAL conflict enqueued without { mock }. The mock is
    // head; resolving it must not leak its no-op resolver onto the real one.
    conflicts.enqueue(mockSampleConflict({ cipherId: "mock-1" }), { mock: true });
    flush();
    conflicts.enqueue(mockSampleConflict({ cipherId: "real-1" }));
    flush();
    expect(conflicts.headIsMock()).toBe(true);

    // Resolve the mock head -> no IPC call.
    findButton("Keep this device's version").click();
    await vi.waitFor(() => expect(conflicts.hasPending()).toBe(true));
    flush();
    expect(resolveConflictMock).not.toHaveBeenCalled();

    // Now the real conflict is head -> IPC resolver fires. Re-query the
    // button: the panel re-renders on head change (name/fields differ), so a
    // stale node reference can detach.
    expect(conflicts.headIsMock()).toBe(false);
    await vi.waitFor(() =>
      expect(findButton("Keep this device's version")).toBeTruthy(),
    );
    flush();
    findButton("Keep this device's version").click();
    await vi.waitFor(() =>
      expect(resolveConflictMock).toHaveBeenCalledWith("keep_local"),
    );
  });
});
