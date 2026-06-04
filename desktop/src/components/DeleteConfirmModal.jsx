import { createSignal, createEffect, Show } from "solid-js";
import { useApp } from "../context/AppContext.jsx";
import { useActions } from "../hooks/useActions.js";
import { useI18n } from "../i18n/index.jsx";

export default function DeleteConfirmModal() {
  const { viewCipher, setShowDeleteConfirm, showDeleteConfirm, selectedCategory } = useApp();
  const { deleteCipher } = useActions();
  const { t } = useI18n();

  let cancelBtnRef;
  let deleteBtnRef;

  createEffect(() => {
    if (showDeleteConfirm()) {
      setTimeout(() => cancelBtnRef?.focus(), 50);
    }
  });

  function handleKeyDown(e) {
    if (e.key === "Escape") {
      setShowDeleteConfirm(false);
    } else if (e.key === "ArrowLeft" || e.key === "ArrowRight" || e.key === "Tab") {
      e.preventDefault();
      if (document.activeElement === cancelBtnRef) {
        deleteBtnRef?.focus();
      } else {
        cancelBtnRef?.focus();
      }
    }
  }

  return (
    <Show when={showDeleteConfirm()}>
      <div
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
        onKeyDown={handleKeyDown}
      >
        <div class="w-full max-w-sm p-6 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative animate-scale-in text-center">
          <div class="w-12 h-12 rounded-full bg-red-950/20 text-red-500 border border-red-900/30 flex items-center justify-center mx-auto mb-4">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          </div>

          <h3 class="text-lg font-bold text-[var(--color-text)]">
            {selectedCategory() === "Trash" ? "Permanently Delete?" : "Delete Entry?"}
          </h3>
          <p class="text-xs text-[var(--color-muted)] mt-2 leading-relaxed px-2">
            <Show when={selectedCategory() === "Trash"} fallback={
              <span>Are you sure you want to delete <strong class="text-[var(--color-text)] font-semibold select-all">{viewCipher()?.name}</strong>? It will be moved to the Trash.</span>
            }>
              <span>Are you sure you want to permanently delete <strong class="text-[var(--color-text)] font-semibold select-all">{viewCipher()?.name}</strong>? This action is irreversible.</span>
            </Show>
          </p>

          <div class="mt-6 flex gap-3">
            <button
              ref={cancelBtnRef}
              onClick={() => setShowDeleteConfirm(false)}
              class="flex-1 py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold transition-all text-xs outline-none focus:ring-2 focus:ring-[var(--color-primary)] cursor-pointer"
            >
              Cancel
            </button>
            <button
              ref={deleteBtnRef}
              onClick={() => deleteCipher(viewCipher().id, t)}
              class="flex-1 py-3 px-4 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold transition-all text-xs outline-none focus:ring-2 focus:ring-red-400 cursor-pointer"
            >
              {selectedCategory() === "Trash" ? t("entry.deletePermanently") : t("entry.delete")}
            </button>
          </div>
        </div>
      </div>
    </Show>
  );
}
