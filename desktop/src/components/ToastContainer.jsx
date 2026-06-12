import { Show, For } from "solid-js";
import { toasts, dismiss } from "../context/toastSignal.js";

const ICONS = {
  success: (
    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  ),
  error: (
    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="15" y1="9" x2="9" y2="15" />
      <line x1="9" y1="9" x2="15" y2="15" />
    </svg>
  ),
  warning: (
    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  info: (
    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  ),
};

const STYLES = {
  success: "bg-emerald-950/90 border-emerald-800/60 text-emerald-300",
  error:   "bg-red-950/90 border-red-800/60 text-red-300",
  warning: "bg-amber-950/90 border-amber-800/60 text-amber-300",
  info:    "bg-sky-950/90 border-sky-800/60 text-sky-300",
};

const ICON_ACCENT = {
  success: "text-emerald-400",
  error:   "text-red-400",
  warning: "text-amber-400",
  info:    "text-sky-400",
};

export default function ToastContainer() {
  return (
    <Show when={toasts().length > 0}>
      <div class="toast-container fixed top-4 right-4 z-[200] flex flex-col gap-2 pointer-events-none" style="max-width: 380px;">
        <For each={toasts()}>
          {(t) => (
            <div
              class={`toast-container__toast pointer-events-auto toast-enter flex items-start gap-2.5 px-4 py-3 rounded-xl border shadow-lg backdrop-blur-sm ${STYLES[t.type]}`}
            >
              <div class={`toast-container__toast-icon shrink-0 mt-0.5 ${ICON_ACCENT[t.type]}`}>
                {ICONS[t.type]}
              </div>
              <p class="toast-container__toast-message text-xs font-medium leading-relaxed flex-1 min-w-0 break-words">
                {t.message}
              </p>
              <Show when={t.manual}>
                <button
                  onClick={() => dismiss(t.id)}
                  class="toast-container__toast-close shrink-0 p-0.5 rounded-md opacity-60 hover:opacity-100 transition-opacity cursor-pointer"
                >
                  <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </Show>
            </div>
          )}
        </For>
      </div>
    </Show>
  );
}
