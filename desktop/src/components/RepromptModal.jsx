import { createSignal, Show } from "solid-js";
import { useApp } from "../context/AppContext.jsx";
import { daemon } from "../lib/daemon.js";

export default function RepromptModal() {
  const { showReprompt, setShowReprompt, repromptCallback } = useApp();
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal("");
  const [loading, setLoading] = createSignal(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!password()) return;
    setLoading(true);
    setError("");
    try {
      await daemon("vault.reprompt_verify", password());
      setShowReprompt(false);
      const cb = repromptCallback();
      if (cb) cb();
      setPassword("");
    } catch (e) {
      setError("Incorrect password");
    }
    setLoading(false);
  }

  return (
    <Show when={showReprompt()}>
      <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
        <div class="w-full max-w-sm p-6 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative animate-scale-in">
          <div class="flex items-center gap-3 mb-4">
            <div class="w-10 h-10 rounded-full bg-[var(--color-primary)]/10 text-[var(--color-primary)] flex items-center justify-center">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            </div>
            <div>
              <div class="text-sm font-bold text-[var(--color-text)]">Verify your identity</div>
              <div class="text-xs text-[var(--color-muted)]">Enter your master password to continue</div>
            </div>
          </div>
          <form onSubmit={handleSubmit}>
            <input
              type="password"
              placeholder="Master password"
              value={password()}
              onInput={e => setPassword(e.target.value)}
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all mb-3"
              autofocus
            />
            <Show when={error()}>
              <div class="text-xs text-red-400 mb-3">{error()}</div>
            </Show>
            <div class="flex gap-2">
              <button
                type="button"
                onClick={() => { setShowReprompt(false); setPassword(""); }}
                class="flex-1 py-2.5 rounded-xl text-xs font-bold text-[var(--color-muted)] border border-[var(--color-border)] hover:bg-[var(--color-card)] transition-all cursor-pointer"
              >Cancel</button>
              <button
                type="submit"
                disabled={loading() || !password()}
                class="flex-1 py-2.5 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold disabled:opacity-50 transition-all cursor-pointer"
              >{loading() ? "Verifying..." : "Verify"}</button>
            </div>
          </form>
        </div>
      </div>
    </Show>
  );
}
