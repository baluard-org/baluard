import { createSignal, Show } from "solid-js";
import { Transition } from "solid-transition-group";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import FocusTrap from "./FocusTrap.jsx";

let repromptCallback = null;

export function requestReprompt(cb) { repromptCallback = cb; }

export default function RepromptModal(props) {
  const { t } = useI18n();
  let dialogRef;
  const [show, setShow] = createSignal(false);
  const [password, setPassword] = createSignal("");
  const [failed, setFailed] = createSignal(false);

  // Expose for parent to trigger the modal
  window.__idttyReprompt = { show: () => { setShow(true); setPassword(""); setFailed(false); }, hide: () => setShow(false) };

  async function handleConfirm() {
    const pw = password();
    if (!pw) return;
    try {
      // Verify the password against the daemon before granting access
      await daemon("vault.unlock", pw);
      // If we get here, password is correct. Re-lock since we were already unlocked.
      // The daemon.unlock is idempotent if already unlocked with same password.
      if (repromptCallback) repromptCallback();
      setShow(false);
      setPassword("");
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }

  return (
    <Transition name="fade">
      <Show when={show()}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="reprompt-title"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => { setShow(false); setPassword(""); setFailed(false); }} />
          <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl">
            <h3 id="reprompt-title" class="text-lg font-bold text-[var(--color-text)] mb-2">{t("entry.confirmPassword")}</h3>
            <p class="text-sm text-[var(--color-muted)] mb-4">{t("entry.enterMasterPasswordToContinue")}</p>
            <Show when={failed()}>
              <div class="mb-3 p-2 rounded-lg bg-red-950/40 border border-red-900/30 text-red-300 text-xs">{t("errors.invalidPassword")}</div>
            </Show>
            <input
              type="password"
              autocomplete="current-password"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              placeholder={t("login.passwordPlaceholder")}
              value={password()}
              onInput={e => { setPassword(e.target.value); setFailed(false); }}
              onKeyPress={e => { if (e.key === "Enter") handleConfirm(); }}
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] mb-4"
            />
            <div class="flex gap-3">
              <button
                onClick={() => { setShow(false); setPassword(""); setFailed(false); }}
                class="flex-1 py-2.5 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] font-semibold transition-all cursor-pointer"
              >{t("entry.cancel")}</button>
              <button
                onClick={handleConfirm}
                class="flex-1 py-2.5 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] font-semibold transition-all cursor-pointer"
              >{t("entry.confirm")}</button>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
