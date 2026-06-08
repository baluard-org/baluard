import { Show } from "solid-js";
import { Transition } from "solid-transition-group";
import { useI18n } from "../i18n/index.jsx";

export default function DeleteConfirmModal(props) {
  const { t } = useI18n();

  return (
    <Transition name="fade">
      <Show when={props.showDeleteConfirm}>
        <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl">
            <h3 class="text-lg font-bold text-[var(--color-text)] mb-2">{t("entry.deleteTitle")}</h3>
            <p class="text-sm text-[var(--color-muted)] mb-6">
              {props.selectedCategory === "Trash"
                ? t("entry.deletePermanentlyConfirm")
                : t("entry.moveToTrashConfirm")}
            </p>
            <div class="flex gap-3">
              <button
                onClick={() => props.setShowDeleteConfirm(false)}
                class="flex-1 py-2.5 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] font-semibold transition-all cursor-pointer"
              >
                {t("entry.cancel")}
              </button>
              <button
                onClick={() => { props.onDelete?.(props.viewCipher?.id); props.setShowDeleteConfirm(false); }}
                class="flex-1 py-2.5 rounded-xl bg-red-950/40 text-red-400 border border-red-900/30 hover:bg-red-950/60 font-semibold transition-all cursor-pointer"
              >
                {props.selectedCategory === "Trash" ? t("entry.deletePermanently") : t("entry.delete")}
              </button>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
