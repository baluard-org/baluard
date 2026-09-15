import { Show } from "solid-js";
import { Transition } from "../lib/transition";
import { useI18n } from "../i18n/index.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { Button } from "./Primitives.jsx";

/**
 * Shared confirmation dialog (code-health R5): overlay + FocusTrap +
 * cancel/confirm pair. All four confirm surfaces in the app render this.
 *
 * Props:
 *   show            — visibility
 *   idPrefix        — unique ids for aria-labelledby/describedby
 *   title, body     — already-translated strings
 *   confirmLabel    — already-translated confirm button text
 *   onConfirm       — fired with the confirm click (dialog closes itself)
 *   onClose         — fired on cancel / overlay click / Escape
 *   confirmClass    — extra classes on the confirm Button (e.g. amber/red)
 */
export default function ConfirmModal(props) {
  const { t } = useI18n();
  let dialogRef;

  return (
    <Transition name="fade">
      <Show when={props.show}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby={`${props.idPrefix}-title`}
          aria-describedby={`${props.idPrefix}-desc`}
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => props.onClose?.()}
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => props.onClose?.()} />
          <div
            class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 id={`${props.idPrefix}-title`} class="text-lg font-bold text-[var(--color-text)] mb-2">
              {props.title}
            </h3>
            <p id={`${props.idPrefix}-desc`} class="text-sm text-[var(--color-muted)] mb-6">
              {props.body}
            </p>
            <div class="flex gap-3">
              <Button onClick={() => props.onClose?.()} class="flex-1 py-2.5">
                {props.cancelLabel || t("entry.cancel")}
              </Button>
              <Button
                onClick={() => { props.onConfirm?.(); props.onClose?.(); }}
                variant={props.confirmVariant}
                class={`flex-1 py-2.5 ${props.confirmClass || ""}`}
              >
                {props.confirmLabel}
              </Button>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
