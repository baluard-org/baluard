import { Show } from "solid-js";
import { Transition } from "solid-transition-group";
import { useI18n } from "../i18n/index.jsx";
import FocusTrap from "./FocusTrap.jsx";

export default function ArchiveConfirmModal(props) {
  const { t } = useI18n();
  let dialogRef;

  return (
    <Transition name="fade">
      <Show when={props.show}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="archive-confirm-title"
          aria-describedby="archive-confirm-desc"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => props.setShow(false)} />
          <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl">
            <h3 id="archive-confirm-title" class="text-lg font-bold text-[var(--color-text)] mb-2">{t("entry.archiveTitle")}</h3>
            <p id="archive-confirm-desc" class="text-sm text-[var(--color-muted)] mb-6">{t("entry.archiveConfirm")}</p>
            <div class="flex gap-3">
              <button
                onClick={() => props.setShow(false)}
                class="flex-1 py-2.5 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] font-semibold transition-all cursor-pointer"
              >
                {t("entry.cancel")}
              </button>
              <button
                onClick={() => { props.onConfirm?.(); props.setShow(false); }}
                class="flex-1 py-2.5 rounded-xl bg-amber-950/40 text-amber-400 border border-amber-900/30 hover:bg-amber-950/60 font-semibold transition-all cursor-pointer"
              >
                {t("entry.archive")}
              </button>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
