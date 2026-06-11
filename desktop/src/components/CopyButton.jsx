import { createSignal, Show } from "solid-js";
import { IconCopy, IconCheck } from "./Icon.jsx";
import { copyToClipboard } from "../lib/clipboard.js";

/**
 * Reusable copy-to-clipboard button with animated feedback.
 * Shows copy icon → green checkmark + "Copied" label for 1.8s.
 *
 * L1 fix: auto-clears the clipboard after `autoClearMs` (default 30s)
 * to limit how long the secret lives in the OS clipboard/clipboard history.
 * Only clears if the clipboard still contains the value we wrote
 * (avoids stomping on a user-initiated copy of something else).
 *
 * Props:
 *   value         — string to copy
 *   class?        — extra classes on the button
 *   label?        — optional label shown alongside icon (e.g. "Copy")
 *   title?        — tooltip text
 *   autoClearMs?  — ms before auto-clearing clipboard (default 30000, 0 = disable)
 */
export default function CopyButton(props) {
  const [copied, setCopied] = createSignal(false);

  async function handleCopy(e) {
    e.stopPropagation();
    const value = props.value || "";
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
    await copyToClipboard(value, { autoClearMs: props.autoClearMs });
  }

  return (
    <button
      onClick={handleCopy}
      class={`flex items-center gap-1.5 cursor-pointer text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors ${props.class || ""}`}
      title={props.title || "Copy to clipboard"}
    >
      <Show when={copied()} fallback={
        <IconCopy class="w-4 h-4" />
      }>
        <span class="copy-feedback">
          <IconCheck class="w-4 h-4 text-[var(--color-success)]" />
        </span>
      </Show>
      <Show when={props.label && !copied()}>
        <span class="text-xs font-semibold">{props.label}</span>
      </Show>
    </button>
  );
}
