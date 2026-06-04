import { createSignal, Show } from "solid-js";
import { generateSecurePassword } from "../lib/utils.js";

export default function GeneratorModal(props) {
  const [len, setLen] = createSignal(16);
  const [useUpper, setUseUpper] = createSignal(true);
  const [useNums, setUseNums] = createSignal(true);
  const [useSyms, setUseSyms] = createSignal(true);

  function gen() {
    return generateSecurePassword(len(), useUpper(), useNums(), useSyms());
  }

  return (
    <Show when={props.showGenerator}>
      <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-bold text-[var(--color-text)]">Password Generator</h3>
            <button onClick={() => props.setShowGenerator(false)} class="p-1 text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">✕</button>
          </div>
          <div class="p-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] font-mono text-sm text-[var(--color-text)] text-center mb-4 select-all break-all">
            {gen()}
          </div>
          <div class="space-y-3 mb-4">
            <div class="flex items-center justify-between text-xs">
              <span class="text-[var(--color-muted)]">Length: <strong class="text-[var(--color-primary)]">{len()}</strong></span>
              <input type="range" min="8" max="64" value={len()} onInput={e => setLen(parseInt(e.target.value))} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
            </div>
            <div class="grid grid-cols-3 gap-2">
              <button onClick={() => setUseUpper(!useUpper())} class={`p-2 rounded-lg text-xs font-bold border cursor-pointer ${useUpper() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>A-Z</button>
              <button onClick={() => setUseNums(!useNums())} class={`p-2 rounded-lg text-xs font-bold border cursor-pointer ${useNums() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>0-9</button>
              <button onClick={() => setUseSyms(!useSyms())} class={`p-2 rounded-lg text-xs font-bold border cursor-pointer ${useSyms() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>!@#</button>
            </div>
          </div>
          <button onClick={() => { navigator.clipboard.writeText(gen()); }} class="w-full py-2.5 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold cursor-pointer">Copy Password</button>
        </div>
      </div>
    </Show>
  );
}
