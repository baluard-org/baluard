import { createSignal, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "../i18n/index.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError } from "../context/toastSignal.js";
import FocusTrap from "./FocusTrap.jsx";
import { Button, Input } from "./Primitives.jsx";

const ARMOR_BEGIN = "-----BEGIN BALUARD LEGACY KEY-----";

/**
 * Legacy Contact flow (docs/plan-legacy-contact.md step 6): pick the
 * kit letter, type the passphrase, land in a read-only view of the
 * vault copy. The kit passphrase is the only secret collected; the
 * clone, verification, and unlock all happen daemon-side.
 */
export default function LegacyContactOpen({ onClose }) {
  const { t } = useI18n();
  const auth = useAuth();
  let dialogRef;

  const [letter, setLetter] = createSignal("");
  const [passphrase, setPassphrase] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");

  const ownerNote = () => {
    const l = letter();
    const idx = l.indexOf(ARMOR_BEGIN);
    return (idx >= 0 ? l.slice(0, idx) : l).trim();
  };

  async function pick() {
    setError("");
    try {
      const text = await invoke("legacy_read_letter");
      if (text == null) return;
      if (!text.includes(ARMOR_BEGIN)) {
        setError(t("legacy.openNotAKit"));
        return;
      }
      setLetter(text);
    } catch (e) {
      setError(String(e));
    }
  }

  async function open() {
    if (!letter() || !passphrase()) return;
    setBusy(true);
    setError("");
    try {
      const res = JSON.parse(
        await daemon("legacy.contact_view", {
          letter: letter(),
          passphrase: passphrase(),
        })
      );
      onClose();
      auth.finishQuickUnlock(
        JSON.stringify({ display_name: res.vault_name || "Vault" })
      );
    } catch (e) {
      setError(sanitizeError(e, t));
      setBusy(false);
    }
  }

  return (
    <div
      ref={dialogRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby="legacy-open-title"
      class="fixed inset-0 bg-black/50 z-50 flex items-center justify-center"
      onClick={() => !busy() && onClose()}
    >
      <FocusTrap containerRef={() => dialogRef} onEscape={() => !busy() && onClose()} />
      <div
        class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4 mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 id="legacy-open-title" class="text-lg font-bold text-[var(--color-text)]">
          {t("legacy.openTitle")}
        </h3>
        <p class="text-xs text-[var(--color-muted)]">{t("legacy.openDesc")}</p>

        <Show
          when={letter()}
          fallback={
            <Button variant="primary" onClick={pick} disabled={busy()} data-testid="legacy-open-pick">
              {t("legacy.pickKit")}
            </Button>
          }
        >
          <Show when={ownerNote()}>
            <div class="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] p-3">
              <p class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-1">{t("legacy.noteTitle")}</p>
              <p class="text-xs text-[var(--color-text)] whitespace-pre-wrap">{ownerNote()}</p>
            </div>
          </Show>
          <div class="space-y-1.5">
            <label class="text-xs font-bold text-[var(--color-text)]" for="legacy-open-passphrase">
              {t("legacy.passphraseLabel")}
            </label>
            <Input
              id="legacy-open-passphrase"
              type="password"
              value={passphrase()}
              onInput={(e) => setPassphrase(e.currentTarget.value)}
              data-testid="legacy-open-passphrase"
            />
          </div>
        </Show>

        <Show when={error()}>
          <p class="text-xs text-[var(--color-danger)]" data-testid="legacy-open-error">{error()}</p>
        </Show>

        <div class="flex gap-2 justify-end">
          <Button onClick={() => onClose()} disabled={busy()}>{t("entry.cancel")}</Button>
          <Show when={letter()}>
            <Button variant="primary" onClick={open} disabled={busy() || !passphrase()} data-testid="legacy-open-go">
              {busy() ? t("legacy.opening") : t("legacy.openGo")}
            </Button>
          </Show>
        </div>
      </div>
    </div>
  );
}
