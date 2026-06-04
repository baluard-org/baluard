import { createSignal, Show } from "solid-js";

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
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
            }>
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
            </Show>
          </button>
        </Show>
        <button
          onClick={handleCopy}
          class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer relative"
          title="Copy to clipboard"
        >
          <Show when={copied()} fallback={
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
          }>
            <span class="text-[9px] text-[var(--color-success)] font-extrabold uppercase tracking-wider">Copied</span>
          </Show>
        </button>
      </div>
    </div>
  );
}
