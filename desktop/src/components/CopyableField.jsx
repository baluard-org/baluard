import { createSignal, Show } from "solid-js";

import { IconEye, IconLink, IconCopy } from "./Icon.jsx";

export default function CopyableField(props) {
  const [copied, setCopied] = createSignal(false);

  function handleCopy() {
    navigator.clipboard.writeText(props.value || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] hover:border-[var(--color-primary)] transition-colors flex items-center justify-between group">
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
              <IconLink class="w-4 h-4" />
            </Show>
          </button>
        </Show>
        <button
          onClick={handleCopy}
          class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer relative"
          title="Copy to clipboard"
        >
          <Show when={copied()} fallback={
            <IconCopy class="w-4 h-4" />
          }>
            <span class="text-[9px] text-[var(--color-success)] font-extrabold uppercase tracking-wider">Copied</span>
          </Show>
        </button>
      </div>
    </div>
  );
}
