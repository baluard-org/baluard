import { Show } from "solid-js";
import { IconCopy, IconCheck } from "./Icon.jsx";
import { useCopyFeedback } from "../lib/useCopyFeedback.js";
import { useI18n } from "../i18n/index.jsx";

/**
 * Reusable copy-to-clipboard button with animated feedback.
 * Shows copy icon → green checkmark for 1.8s.
 *
 * Always auto-clears the clipboard after 30s via copyToClipboard.
 * Only clears if the clipboard still contains the value we wrote
 * (avoids stomping on a user-initiated copy of something else).
 *
 * Props:
 *   value   — string to copy
 *   class?  — extra classes on the button
 *   label?  — optional label shown alongside icon (e.g. "Copy")
 *   title?  — tooltip text
 */
export default function CopyButton(props) {
  const { t } = useI18n();
  const [copied, copy] = useCopyFeedback();

  async function handleCopy(e) {
    e.stopPropagation();
    await copy(props.value);
  }

  return (
    <button
      onClick={handleCopy}
      class={`copy-btn flex items-center gap-1.5 cursor-pointer text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors ${props.class || ""}`}
      title={props.title || t("common.copy")}
      aria-label={props.title || t("common.copy")}
    >
      <Show when={copied()} fallback={
        <IconCopy class="w-4 h-4" />
      }>
        <span class="copy-btn__feedback copy-feedback">
          <IconCheck class="w-4 h-4 text-[var(--color-success)]" />
        </span>
      </Show>
      <Show when={props.label && !copied()}>
        <span class="copy-btn__label text-xs font-semibold">{props.label}</span>
      </Show>
    </button>
  );
}
