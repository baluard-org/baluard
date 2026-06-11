import { createSignal, Show } from "solid-js";
import { IconEye, IconEyeOff, IconCopy, IconCheck } from "./Icon.jsx";
import { CARD_ROW } from "../lib/helpers.js";
import { copyToClipboard } from "../lib/clipboard.js";

export default function CopyableField(props) {
  const [copied, setCopied] = createSignal(false);

  async function handleCopy() {
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
    await copyToClipboard(props.copyValue ?? (props.value || ""));
  }

  return (
    <div class={CARD_ROW}>
      <div class="min-w-0 flex-1">
        <label class="text-[10px] text-[var(--color-muted)] block uppercase tracking-wider font-extrabold">{props.label}</label>
        <Show when={props.isPassword} fallback={
          <div class="text-sm text-[var(--color-text)] font-semibold truncate mt-0.5 select-all">{props.value || "\u2014"}</div>
        }>
          <div class="text-sm font-mono text-[var(--color-text)] tracking-widest mt-0.5 select-all truncate">
            {props.showPassword ? props.value : "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"}
          </div>
        </Show>
      </div>
      <div class="flex items-center gap-1 shrink-0 ml-2">
        <Show when={props.isPassword}>
          <button
            onClick={props.onToggleShow}
            class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer"
            title={props.showPassword ? "Hide" : "Show"}
          >
            <Show when={props.showPassword} fallback={
              <IconEye class="w-4 h-4" />
            }>
              <IconEyeOff class="w-4 h-4" />
            </Show>
          </button>
        </Show>
        <button
          onClick={handleCopy}
          class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer"
          title="Copy to clipboard"
        >
          <Show when={copied()} fallback={
            <IconCopy class="w-4 h-4" />
          }>
            <span class="copy-feedback">
              <IconCheck class="w-4 h-4 text-[var(--color-success)]" />
            </span>
          </Show>
        </button>
      </div>
    </div>
  );
}
