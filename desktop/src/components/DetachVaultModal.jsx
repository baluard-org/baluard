// DetachVaultModal — confirm removing a vault from Baluard.
//
// Safe arm (default): drop the registry entry; vault files stay on disk
// and can be re-attached via "Open local vault".
//
// Destructive arms, gated by a master-password / 24-word recovery-phrase
// reprompt (Bitwarden-style): "Delete from this device" removes the vault
// directory, and — when the vault syncs to a provider repo — "delete the
// repository too" removes the remote copy. The daemon re-verifies the
// credential and rate-limits wrong answers; this UI gate is intent, not
// the security boundary.
//
// Uses FocusTrap per the project's modal accessibility standards.

import { Show, createSignal } from "solid-js";
import { Transition } from "../lib/transition";
import { useI18n } from "../i18n/index.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { Button } from "./Primitives.jsx";

export default function DetachVaultModal(props) {
  const { t } = useI18n();
  let dialogRef;

  const [delFromDevice, setDelFromDevice] = createSignal(false);
  const [delRemote, setDelRemote] = createSignal(false);
  const [credKind, setCredKind] = createSignal("password");
  const [credValue, setCredValue] = createSignal("");
  const [credError, setCredError] = createSignal(null);
  const [busy, setBusy] = createSignal(false);

  const destructive = () => delFromDevice() || delRemote();
  const hasRemote = () => Boolean(props.vault?.provider && props.vault?.remote_url);

  function close() {
    if (busy()) return;
    props.setShow(false);
  }

  function reset() {
    setDelFromDevice(false);
    setDelRemote(false);
    setCredKind("password");
    setCredValue("");
    setCredError(null);
  }

  async function confirm() {
    setCredError(null);
    const payload = { slug: props.vault.slug };
    if (destructive()) {
      if (!credValue()) {
        setCredError(t("vault.vaultSwitcher.verifyRequired"));
        return;
      }
      payload.delete_from_disk = delFromDevice();
      payload.delete_remote = delRemote() && hasRemote();
      payload.confirm = { kind: credKind(), value: credValue() };
    }
    setBusy(true);
    try {
      await props.onConfirm?.(payload);
      props.setShow(false);
      reset();
    } catch (e) {
      setCredError(String(e?.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Transition name="fade">
      <Show when={props.show && props.vault}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="detach-vault-title"
          aria-describedby="detach-vault-desc"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
        >
          <FocusTrap containerRef={dialogRef} onEscape={close} />
          <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-md w-full shadow-2xl">
            <h3 id="detach-vault-title" class="text-lg font-bold text-[var(--color-text)] mb-2">
              {destructive()
                ? t("vault.vaultSwitcher.deleteTitle")
                : t("vault.vaultSwitcher.detachTitle")}
            </h3>
            <p id="detach-vault-desc" class="text-sm text-[var(--color-muted)] mb-1">
              {t("vault.vaultSwitcher.detachBody", { name: props.vault.display_name })}
            </p>
            <Show when={props.vault.path}>
              <p class="text-[10px] font-mono text-[var(--color-muted)] mb-3 break-all">
                {props.vault.path}
              </p>
            </Show>

            <div class="flex flex-col gap-2 mb-3">
              <label class="flex items-center gap-3 p-3 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-xl cursor-pointer select-none">
                <input
                  type="checkbox"
                  class="accent-[var(--color-danger)]"
                  checked={delFromDevice()}
                  onChange={(e) => setDelFromDevice(e.currentTarget.checked)}
                />
                <span class="text-sm text-[var(--color-text)]">
                  {t("vault.vaultSwitcher.deleteFromDevice")}
                </span>
              </label>
              <Show when={hasRemote()}>
                <label class="flex items-center gap-3 p-3 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-xl cursor-pointer select-none">
                  <input
                    type="checkbox"
                    class="accent-[var(--color-danger)]"
                    checked={delRemote()}
                    onChange={(e) => setDelRemote(e.currentTarget.checked)}
                  />
                  <span class="text-sm text-[var(--color-text)]">
                    {t("vault.vaultSwitcher.deleteRemoteRepo", {
                      provider: props.vault.provider,
                    })}
                  </span>
                </label>
              </Show>
            </div>

            <Show when={destructive()}>
              <div class="border border-[var(--color-danger)]/40 rounded-xl p-4 mb-3">
                <p class="text-sm font-semibold text-[var(--color-text)] mb-2">
                  {t("vault.vaultSwitcher.verifyTitle")}
                </p>
                <div class="flex gap-4 mb-2 text-sm">
                  <label class="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="detach-cred-kind"
                      checked={credKind() === "password"}
                      onChange={() => setCredKind("password")}
                    />
                    <span class="text-[var(--color-text)]">
                      {t("vault.vaultSwitcher.credPassword")}
                    </span>
                  </label>
                  <label class="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="detach-cred-kind"
                      checked={credKind() === "phrase"}
                      onChange={() => setCredKind("phrase")}
                    />
                    <span class="text-[var(--color-text)]">
                      {t("vault.vaultSwitcher.credPhrase")}
                    </span>
                  </label>
                </div>
                <input
                  type="password"
                  class="w-full bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-sm text-[var(--color-text)] focus:outline-none focus:border-[var(--color-accent)]"
                  placeholder={
                    credKind() === "password"
                      ? t("vault.vaultSwitcher.credPlaceholderPassword")
                      : t("vault.vaultSwitcher.credPlaceholderPhrase")
                  }
                  value={credValue()}
                  onInput={(e) => setCredValue(e.currentTarget.value)}
                />
              </div>
            </Show>

            <Show when={credError()}>
              <p class="text-sm text-[var(--color-danger)] mb-3">{credError()}</p>
            </Show>

            <div class="flex gap-3">
              <Button onClick={close} class="flex-1 py-2.5">
                {t("vault.vaultSwitcher.detachCancel")}
              </Button>
              <Button
                onClick={confirm}
                disabled={busy()}
                variant={destructive() ? "danger" : "primary"}
                class="flex-1 py-2.5"
              >
                {busy()
                  ? t("vault.vaultSwitcher.working")
                  : destructive()
                    ? t("vault.vaultSwitcher.deleteSubmit")
                    : t("vault.vaultSwitcher.detachSubmit")}
              </Button>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
