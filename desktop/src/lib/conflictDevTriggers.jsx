import { Show, createSignal } from "solid-js";
import {
  useConflictResolution,
  mockSampleConflict,
  mockSampleTypeChange,
} from "../context/ConflictResolutionContext.jsx";

// Dev-only floating trigger for the conflict resolution panel. Hidden in
// production builds (`import.meta.env.DEV` is statically false after
// `vite build`; the component returns null and never mounts). Lets you
// dogfood the panel UX without standing up a real git conflict or wiring
// the deferred `sync.conflict` backend route.
//
// See docs/plan-conflict-resolution-panel.md for the panel contract.

export default function ConflictDevTrigger() {
  // Vite replaces this at build time. `false` in `vite build` -> DCE-friendly
  // early return; the rest of the component (signals, JSX) never runs.
  if (!import.meta.env.DEV) return null;

  const conflicts = useConflictResolution();
  const [open, setOpen] = createSignal(false);

  return (
    <div
      class="fixed bottom-4 right-4 z-40 select-none"
      data-testid="conflict-dev-trigger"
    >
      <Show when={open()}>
        <div class="mb-2 flex flex-col gap-1 p-2 rounded-xl bg-[var(--color-sidebar)] border border-amber-900/40 shadow-xl min-w-[16rem]">
          <button
            type="button"
            onClick={() => conflicts.enqueue(mockSampleConflict(), { mock: true })}
            class="px-3 py-2 rounded-lg text-left text-xs hover:bg-[var(--color-bg)] cursor-pointer"
          >
            Force sample conflict
          </button>
          <button
            type="button"
            onClick={() => conflicts.enqueue(mockSampleTypeChange(), { mock: true })}
            class="px-3 py-2 rounded-lg text-left text-xs hover:bg-[var(--color-bg)] cursor-pointer"
          >
            Force type-change conflict
          </button>
          <button
            type="button"
            onClick={() =>
              conflicts.enqueue(
                mockSampleConflict({
                  cipherId: "mock-generic-" + Math.random().toString(36).slice(2, 8),
                  localDevice: null,
                  remoteDevice: null,
                }),
                { mock: true },
              )
            }
            class="px-3 py-2 rounded-lg text-left text-xs hover:bg-[var(--color-bg)] cursor-pointer"
          >
            Force conflict (generic names)
          </button>
          <Show when={conflicts.hasPending()}>
            <button
              type="button"
              onClick={() => conflicts.clear()}
              class="px-3 py-2 rounded-lg text-left text-xs text-red-400 hover:bg-[var(--color-bg)] cursor-pointer border-t border-[var(--color-border)] mt-1 pt-2"
            >
              Clear queue ({conflicts.count()})
            </button>
          </Show>
        </div>
      </Show>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        class="px-3 py-2 rounded-xl bg-[var(--color-sidebar)] border border-amber-900/40 text-xs font-bold text-amber-400 hover:bg-[var(--color-bg)] shadow-lg cursor-pointer"
        title="Dev only: force a conflict (panel UX dogfood). Hidden in production builds."
      >
        ⚠ Force conflict
      </button>
    </div>
  );
}
