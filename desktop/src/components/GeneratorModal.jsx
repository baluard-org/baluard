import { createSignal, Show } from "solid-js";
import { useApp } from "../context/AppContext.jsx";
import { generateSecurePassword } from "../lib/utils.js";
import { EFF_WORDS } from "../lib/eff-words.js";

export default function GeneratorModal() {
  const { showGenerator, setShowGenerator } = useApp();

  const [genLen, setGenLen] = createSignal(20);
  const [genUpper, setGenUpper] = createSignal(true);
  // Note: lowercase is always included (matches Bitwarden behavior)
  const [genNums, setGenNums] = createSignal(true);
  const [genSyms, setGenSyms] = createSignal(true);
  const [genMode, setGenMode] = createSignal("password");
  const [genResult, setGenResult] = createSignal("");

  // Passphrase settings
  const [passWords, setPassWords] = createSignal(4);
  const [passSep, setPassSep] = createSignal("-");
  const [passCap, setPassCap] = createSignal(false);
  const [passNum, setPassNum] = createSignal(false);

  function generatePassword() {
    if (genMode() === "passphrase") {
      const count = passWords();
      const randArr = new Uint32Array(count * 2); // extra for digits
      crypto.getRandomValues(randArr);
      let words = [];
      for (let i = 0; i < count; i++) {
        let w = EFF_WORDS[randArr[i] % EFF_WORDS.length];
        if (passCap()) w = w.charAt(0).toUpperCase() + w.slice(1);
        if (passNum()) w += (randArr[count + i] % 10);
        words.push(w);
      }
      setGenResult(words.join(passSep()));
    } else {
      setGenResult(generateSecurePassword(genLen(), genUpper(), genNums(), genSyms()));
    }
  }

  return (
    <Show when={showGenerator()}>
      <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-[100]" onClick={() => setShowGenerator(false)}>
        <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[480px] max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
          <div class="p-6">
            <div class="flex items-center justify-between mb-5">
              <h3 class="text-lg font-bold text-[var(--color-text)]">Password Generator</h3>
              <button
                onClick={() => setShowGenerator(false)}
                class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-lg border border-transparent hover:border-[var(--color-border)] transition-all cursor-pointer flex items-center justify-center"
                title="Close"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
              </button>
            </div>

            {/* Mode tabs */}
            <div class="flex gap-2 mb-5">
              <button onClick={() => setGenMode("password")} class={`flex-1 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${genMode() === "password" ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]" : "bg-[var(--color-sidebar)] text-[var(--color-muted)]"}`}>Password</button>
              <button onClick={() => setGenMode("passphrase")} class={`flex-1 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${genMode() === "passphrase" ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]" : "bg-[var(--color-sidebar)] text-[var(--color-muted)]"}`}>Passphrase</button>
            </div>

            <Show when={genMode() === "password"}>
              <div class="flex items-center justify-between text-xs text-[var(--color-text)] mb-3">
                <span>Length: <strong class="text-[var(--color-primary)] text-sm">{genLen()}</strong></span>
                <input type="range" min="4" max="128" value={genLen()} onInput={e => { setGenLen(parseInt(e.target.value)); }} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
              </div>
              <div class="grid grid-cols-3 gap-2 mb-4">
                <button onClick={() => setGenUpper(!genUpper())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genUpper() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>A-Z</button>
                <button onClick={() => setGenNums(!genNums())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genNums() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>0-9</button>
                <button onClick={() => setGenSyms(!genSyms())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genSyms() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>!@#</button>
              </div>
            </Show>

            <Show when={genMode() === "passphrase"}>
              <div class="flex items-center justify-between text-xs text-[var(--color-text)] mb-3">
                <span>Words: <strong class="text-[var(--color-primary)] text-sm">{passWords()}</strong></span>
                <input type="range" min="3" max="10" value={passWords()} onInput={e => setPassWords(parseInt(e.target.value))} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
              </div>
              <div class="grid grid-cols-3 gap-2 mb-4">
                <select value={passSep()} onChange={e => setPassSep(e.target.value)} class="px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer">
                  <option value="-">Dash (-)</option>
                  <option value=" ">Space</option>
                  <option value=".">Dot (.)</option>
                  <option value="_">Underscore (_)</option>
                </select>
                <button onClick={() => setPassCap(!passCap())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${passCap() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>Capitalize</button>
                <button onClick={() => setPassNum(!passNum())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${passNum() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>+ Number</button>
              </div>
            </Show>

            <button onClick={generatePassword} class="w-full py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-bold text-sm transition-all cursor-pointer mb-4">Generate</button>

            {/* Result */}
            <Show when={genResult()}>
              <div class="p-3 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] flex items-center justify-between">
                <code class="text-sm text-[var(--color-text)] font-mono break-all flex-1 select-all">{genResult()}</code>
                <button onClick={() => navigator.clipboard.writeText(genResult())} class="ml-3 p-2 text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer shrink-0" title="Copy">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
                </button>
              </div>
            </Show>
          </div>
        </div>
      </div>
    </Show>
  );
}
