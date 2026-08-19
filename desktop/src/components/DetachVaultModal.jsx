// DetachVaultModal — confirm removing a vault from Baluard.
//
// Detach is the SAFE, reversible arm: the vault's registry entry is
// dropped so it stops appearing in the app, but the vault directory is
// left untouched on disk. The user can re-attach it later via the
// "Open local vault" entry point (`baluard open <path>` / the desktop
// Open Vault flow).
//
// The destructive arm (delete-from-disk) is deliberately NOT exposed in
// the UI. Irrecoverable deletion of an unsynced vault is a real harm
// surface (accidental click, casual adversary at an unattended machine),
// and the typed-name gate we'd use to confirm it echoes a name the UI
// itself just displayed — weak proof. The power-user escape hatch is the
// CLI: `baluard vaults detach <slug> --delete-from-disk`, which already
// requires retyping the slug and is gated by the .baluard marker check
// on the daemon side. A future revision may add a master-password-
// reprompt gated destructive arm back to the UI (Bitwarden-style); for
// now, the UI is destructive-action-free.
//
// Uses FocusTrap per the project's modal accessibility standards.

import { Show } from "solid-js";
import { Transition } from "../lib/transition";
import { useI18n } from "../i18n/index.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { Button } from "./Primitives.jsx";

export default function DetachVaultModal(props) {
  const { t } = useI18n();
  let dialogRef;

  function close() {
    props.setShow(false);
  }

  function confirm() {
    props.onConfirm?.();
    close();
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
              {t("vault.vaultSwitcher.detachTitle")}
            </h3>
            <p id="detach-vault-desc" class="text-sm text-[var(--color-muted)] mb-1">
              {t("vault.vaultSwitcher.detachBody", { name: props.vault.display_name })}
            </p>
            <p class="text-[10px] font-mono text-[var(--color-muted)] mb-5 break-all">
              {props.vault.path}
            </p>
            <div class="flex gap-3">
              <Button onClick={close} class="flex-1 py-2.5">
                {t("vault.vaultSwitcher.detachCancel")}
              </Button>
              <Button onClick={confirm} variant="primary" class="flex-1 py-2.5">
                {t("vault.vaultSwitcher.detachSubmit")}
              </Button>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
