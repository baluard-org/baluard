import { Show } from "solid-js";
import { Transition } from "solid-transition-group";
import { useI18n } from "../i18n/index.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { Button } from "./Primitives.jsx";

export default function DeleteConfirmModal(props) {
  const { t } = useI18n();
  let dialogRef;

  return (
    <Transition name="fade">
      <Show when={props.showDeleteConfirm}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-confirm-title"
          aria-describedby="delete-confirm-desc"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => props.setShowDeleteConfirm(false)} />
          <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl">
            <h3 id="delete-confirm-title" class="text-lg font-bold text-[var(--color-text)] mb-2">{t("entry.deleteTitle")}</h3>
            <p id="delete-confirm-desc" class="text-sm text-[var(--color-muted)] mb-6">
              {props.selectedCategory === "Trash"
                ? t("entry.deletePermanentlyConfirm")
                : t("entry.moveToTrashConfirm")}
            </p>
            <div class="flex gap-3">
              <Button
                onClick={() => props.setShowDeleteConfirm(false)}
                class="flex-1 py-2.5"
              >
                {t("entry.cancel")}
              </Button>
              <Button
                onClick={() => { props.onDelete?.(props.viewCipher?.id); props.setShowDeleteConfirm(false); }}
                variant="danger"
                class="flex-1 py-2.5"
              >
                {props.selectedCategory === "Trash" ? t("entry.deletePermanently") : t("entry.delete")}
              </Button>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
