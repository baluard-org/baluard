import { Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { Button } from "./Primitives.jsx";

// Second, we-are-not-joking confirmation for recovery-phrase ceremonies.
// Shown AFTER the user has already confirmed storage once: the only way
// forward is the explicit confirm; decline keeps the words on screen so the
// user can actually go store them. Callers own the open state.
export default function FinalPhraseCheckDialog(props) {
  const { t } = useI18n();
  let dialogRef;
  return (
    <Show when={props.open}>
      <div class="fixed inset-0 z-[120] flex items-center justify-center bg-black/70 p-4">
        <div
          ref={dialogRef}
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="final-phrase-check-title"
          class="w-full max-w-md rounded-2xl bg-[var(--color-bg)] border border-red-500/50 p-6 space-y-4 shadow-2xl"
        >
          <FocusTrap containerRef={dialogRef} onEscape={props.onDecline} />
          <h3 id="final-phrase-check-title" class="text-sm font-bold text-red-400 font-mono uppercase tracking-wider">
            {t("recovery.finalTitle")}
          </h3>
          <p class="text-xs text-[var(--color-text)] leading-relaxed">{t("recovery.finalBody")}</p>
          <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button onClick={props.onDecline} class="text-xs py-2 px-4 font-mono uppercase">
              {t("recovery.finalDecline")}
            </Button>
            <Button onClick={props.onConfirm} variant="primary" class="text-xs py-2 px-4 font-mono uppercase">
              {t("recovery.finalConfirm")}
            </Button>
          </div>
        </div>
      </div>
    </Show>
  );
}
