import { Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { IconX } from "./Icon.jsx";

/**
 * "What is git?" explainer (UX decision, 2026-09): a plain-words description
 * of the storage backbone for non-technical users. Opens from the Sync tab.
 * Same copy as the mobile GitExplainerDialog (keep both in sync).
 */
export default function GitExplainerModal(props) {
  const { t } = useI18n();
  let dialogRef;

  return (
    <Show when={props.open}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="git-explainer-title"
        class="fixed inset-0 bg-black/60 flex items-center justify-center z-[200]"
        onClick={props.onClose}
      >
        <FocusTrap containerRef={dialogRef} onEscape={props.onClose} />
        <div
          class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[560px] max-w-[92vw] max-h-[90vh] flex flex-col overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          <div class="p-5 pb-4 border-b border-[var(--color-border)] flex items-center justify-between shrink-0">
            <h3 id="git-explainer-title" class="text-base font-bold text-[var(--color-text)]">
              {t("gitWhat.title")}
            </h3>
            <button
              onClick={props.onClose}
              class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-lg border border-transparent hover:border-[var(--color-border)] transition-all cursor-pointer"
              title={t("entry.close")}
            >
              <IconX class="w-4 h-4" />
            </button>
          </div>

          <div class="p-5 overflow-y-auto">
            <GitDiagram />
            <p class="text-sm text-[var(--color-text)] leading-relaxed mt-4">{t("gitWhat.p1")}</p>
            <p class="text-sm text-[var(--color-text)] leading-relaxed mt-3">{t("gitWhat.p2")}</p>
            <p class="text-sm text-[var(--color-text)] leading-relaxed mt-3">{t("gitWhat.p3")}</p>
            <p class="text-sm text-[var(--color-muted)] leading-relaxed mt-3">{t("gitWhat.p4")}</p>
          </div>

          <div class="px-5 py-4 border-t border-[var(--color-border)] flex justify-end shrink-0">
            <button
              onClick={props.onClose}
              class="px-4 py-2 text-sm font-semibold rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] hover:opacity-90 transition-all cursor-pointer"
            >
              {t("entry.close")}
            </button>
          </div>
        </div>
      </div>
    </Show>
  );
}

/** Three-node picture: this device -> (encrypted) -> git account -> other devices. */
function GitDiagram() {
  const { t } = useI18n();

  return (
    <div class="flex items-center justify-center gap-3 py-2" aria-hidden="true">
      <DiagramNode icon="🔐" label={t("gitWhat.diagramDevice")} />
      <Arrow />
      <DiagramNode icon="☁️" label={t("gitWhat.diagramAccount")} />
      <Arrow />
      <DiagramNode icon="💻" label={t("gitWhat.diagramOther")} />
    </div>
  );
}

function DiagramNode(props) {
  return (
    <div class="flex flex-col items-center gap-1">
      <div class="w-11 h-11 rounded-full bg-[var(--color-primary)]/15 border border-[var(--color-primary)]/40 flex items-center justify-center text-lg">
        {props.icon}
      </div>
      <span class="text-[10px] text-[var(--color-muted)] text-center">{props.label}</span>
    </div>
  );
}

function Arrow() {
  const { t } = useI18n();
  return (
    <div class="flex flex-col items-center">
      <span class="text-[var(--color-muted)] text-lg leading-none">→</span>
      <span class="text-[9px] text-[var(--color-muted)]">{t("gitWhat.diagramEncrypted")}</span>
    </div>
  );
}
