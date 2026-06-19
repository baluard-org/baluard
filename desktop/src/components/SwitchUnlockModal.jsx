// Phase 6: unlock a DIFFERENT (locked) vault without leaving the current
// view. Shown as a modal over the unlocked VaultView when the user picks a
// locked/closed vault from the switcher. Contrast with the full-screen
// LoginScreen (first-launch / lock-all): this keeps the current vault
// visible behind so the action is contextual and easy to cancel.
//
// The current vault stays unlocked (Phase 6 keep-unlocked model). The active
// pointer is NOT flipped when picking a locked vault — the modal unlocks the
// target first, then it becomes active. Cancelling leaves the user on the
// currently-displayed vault with its active pointer untouched.

import { createSignal, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { daemon } from "../lib/daemon.js";
import { biometryPrompt } from "../lib/biometry.js";
import { startVaultPrefetch } from "../lib/vaultPrefetch.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError } from "../context/toastSignal.js";
import FocusTrap from "./FocusTrap.jsx";
import { Button, Input } from "./Primitives.jsx";
import { IconLock, IconFingerprint } from "./Icon.jsx";

export default function SwitchUnlockModal(props) {
  // props: { target, onClose, onUnlocked }
  //   target: { slug, display_name } | null
  //   onClose(): called on cancel / Esc / backdrop
  //   onUnlocked(): called after a successful unlock (parent refreshes data)
  const { t } = useI18n();
  const auth = useAuth();
  let dialogRef;

  const [password, setPassword] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [failed, setFailed] = createSignal(false);

  const name = () => props.target?.display_name || props.target?.slug || "";

  function reset() {
    setPassword("");
    setBusy(false);
    setFailed(false);
  }

  async function handleSubmit() {
    const pw = password();
    if (!pw || busy()) return;
    setBusy(true);
    setFailed(false);
    try {
      // Open + unlock the target slug in one round-trip. We do NOT reuse
      // auth.unlock() here: that reads its password from the login-screen
      // ref and flips status to "locked" on failure, which would boot the
      // user out of the current vault on a typo. The modal owns its field
      // and stays put on failure.
      await daemon("vault.open", "", props.target.slug);
      const infoStr = await daemon(
        "vault.unlock",
        JSON.stringify({ slug: props.target.slug, password: pw }),
        props.target.slug,
      );
      // The daemon's vault.unlock only points active at the unlocked vault
      // when no vault is active yet (to avoid surprise mid-flow). Here the
      // OLD vault is still active, so we must explicitly switch the focus to
      // the newly-unlocked target — otherwise the client (active_slug=target)
      // and daemon (active=old) diverge and the prefetch list_full sends the
      // target's token against the old vault: "Invalid session token".
      // Do this AFTER unlock so a failed unlock never moves the pointer.
      await daemon("vaults.switch", JSON.stringify({ slug: props.target.slug }), props.target.slug);
      try { auth.setVaultInfo(JSON.parse(infoStr)); } catch {}
      auth.setSwitchTarget(null);
      auth.setStatus("unlocked");
      // Prefetch the now-active vault's data so the view swaps instantly.
      startVaultPrefetch();
      reset();
      props.onUnlocked?.();
      props.onClose?.();
    } catch (e) {
      setFailed(true);
      setBusy(false);
    }
  }

  async function handleBiometric() {
    if (busy()) return;
    setBusy(true);
    try {
      // UX gate first (Touch ID / Face ID / PIN prompt).
      await biometryPrompt();
      // Target the chosen slug for both open + biometric_unlock.
      await daemon("vault.open", "", props.target.slug);
      await daemon("vault.biometric_unlock", "", props.target.slug);
      // Explicitly focus the newly-unlocked target (see handleSubmit: the
      // daemon leaves active on the old vault otherwise). After unlock so a
      // failed biometric never moves the pointer.
      await daemon("vaults.switch", JSON.stringify({ slug: props.target.slug }), props.target.slug);
      auth.setStatus("unlocked");
      reset();
      props.onUnlocked?.();
      props.onClose?.();
    } catch (e) {
      if (!/cancelled|canceled|user cancel/i.test(e?.message || "")) {
        toastError(sanitizeError(e, t));
      }
      setBusy(false);
    }
  }

  return (
    <Show when={props.target}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="switch-unlock-title"
        class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      >
        <FocusTrap
          containerRef={dialogRef}
          onEscape={() => { if (!busy()) { reset(); props.onClose?.(); } }}
        />
        <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl">
          <div class="flex items-center gap-3 mb-4">
            <div class="w-10 h-10 rounded-xl bg-[var(--color-primary)]/10 flex items-center justify-center shrink-0">
              <IconLock class="w-5 h-5 text-[var(--color-primary)]" />
            </div>
            <div class="min-w-0">
              <h3 id="switch-unlock-title" class="text-lg font-bold text-[var(--color-text)] leading-tight">
                {t("vault.vaultSwitcher.unlockTitle")}
              </h3>
              <p class="text-xs text-[var(--color-muted)] truncate">{name()}</p>
            </div>
          </div>

          <p class="text-sm text-[var(--color-muted)] mb-4">
            {t("vault.vaultSwitcher.unlockBody")}
          </p>

          <Show when={failed()}>
            <div class="mb-3 p-2 rounded-lg bg-red-950/40 border border-red-900/30 text-red-300 text-xs">
              {t("errors.invalidPassword")}
            </div>
          </Show>

          <form onSubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
            <Input
              type="password"
              autocomplete="current-password"
              placeholder={t("login.passwordPlaceholder")}
              value={password()}
              onInput={(e) => { setPassword(e.target.value); setFailed(false); }}
              aria-label={t("login.passwordPlaceholder")}
              disabled={busy()}
            />
            <Button
              type="submit"
              variant="primary"
              disabled={busy()}
              class="w-full py-3 mt-3"
            >
              {busy() ? t("login.unlocking") : t("login.unlock")}
            </Button>
          </form>

          <Show when={auth.biometricAvailable()}>
            <button
              type="button"
              onClick={handleBiometric}
              disabled={busy()}
              class="w-full mt-2 py-3 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] font-semibold transition-all cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <IconFingerprint class="w-4 h-4" />
              {t("login.quickUnlock")}
            </button>
          </Show>

          <button
            type="button"
            onClick={() => { if (!busy()) { reset(); props.onClose?.(); } }}
            disabled={busy()}
            class="w-full mt-3 py-2 text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer disabled:opacity-50"
          >
            {t("entry.cancel")}
          </button>
        </div>
      </div>
    </Show>
  );
}
