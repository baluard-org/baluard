import { createSignal, Show } from "solid-js";
import { Transition } from "../lib/transition";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import ConsolePanel from "./ConsolePanel.jsx";
import { Button, Input } from "./Primitives.jsx";

let repromptCallback = null;

export default function RepromptModal(props) {
  const { t } = useI18n();
  let dialogRef;
  const [show, setShow] = createSignal(false);
  const [password, setPassword] = createSignal("");
  const [failed, setFailed] = createSignal(false);

  // Expose for parents to trigger the modal. The callback is bound at
  // SHOW time, not registration time — a stale registration from another
  // component must never fire (e.g. a rotation callback running because a
  // detail-view re-prompt was confirmed later).
  window.__baluardReprompt = {
    show: (cb) => { if (cb) repromptCallback = cb; setShow(true); setPassword(""); setFailed(false); },
    hide: () => setShow(false),
    // Dev/e2e-only: the delegated onInput signal cannot be driven from a
    // WebDriver synthetic fill, so automation submits through here. The
    // production build strips the DEV branch entirely.
    ...(import.meta.env.DEV ? { submit: (pw) => { setPassword(pw); handleConfirm(); } } : {}),
  };

  async function handleConfirm() {
    const pw = password();
    if (!pw) return;
    try {
      // Verify against the daemon's dedicated reprompt route: it opens a
      // TEMPORARY handle and actually checks the password. vault.unlock
      // would short-circuit Ok on an already-unlocked vault and accept
      // anything. Failures share the unlock rate-limit budget (C23).
      await daemon("vault.reprompt_verify", pw);
      // Verified. The password is passed to the callback so flows that
      // need it as a parameter (e.g. recovery-phrase rotation) can use it.
      if (repromptCallback) repromptCallback(pw);
      setShow(false);
      setPassword("");
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }

  return (
    <Transition name="fade">
      <ConsolePanel
        show={show()}
        accentClass="border-red-600"
        minHeightClass="min-h-[20rem]"
        role="dialog"
        ariaLabelledby="reprompt-title"
        onEscape={() => { setShow(false); setPassword(""); setFailed(false); }}
      >
        <div class="w-full max-w-md mx-auto flex flex-col">
          <h3 id="reprompt-title" class="text-sm font-bold uppercase tracking-wider text-[var(--color-text)] mb-1 font-mono flex items-center gap-2">
            <span class="inline-block w-2.5 h-2.5 bg-red-600 rounded-full animate-pulse" />
            {t("entry.confirmPassword")}
          </h3>
          <p class="text-xs text-[var(--color-muted)] mb-4 font-mono">// {t("entry.enterMasterPasswordToContinue")}</p>
          
          <Show when={failed()}>
            <div class="mb-4 p-2.5 rounded bg-red-950/30 border border-red-900/40 text-red-300 text-xs font-mono">
              ERROR: {t("errors.invalidPassword")}
            </div>
          </Show>
          
          <Input
            data-testid="reprompt-input"
            type="password"
            autocomplete="current-password"
            placeholder={t("login.passwordPlaceholder")}
            value={password()}
            onInput={e => { setPassword(e.target.value); setFailed(false); }}
            onKeyPress={e => { if (e.key === "Enter") handleConfirm(); }}
            class="mb-5 font-mono"
            aria-label={t("entry.confirmPassword")}
          />
          
          <div class="flex gap-3">
            <Button
              onClick={() => { setShow(false); setPassword(""); setFailed(false); }}
              class="flex-1 py-2.5 font-mono text-xs uppercase"
            >{t("entry.cancel")}</Button>
            <Button
              data-testid="reprompt-confirm"
              onClick={handleConfirm}
              variant="primary"
              class="flex-1 py-2.5 font-mono text-xs uppercase bg-red-600 border-transparent text-white hover:bg-red-700 focus-visible:ring-red-600"
            >{t("entry.confirm")}</Button>
          </div>
        </div>
      </ConsolePanel>
    </Transition>
  );
}
