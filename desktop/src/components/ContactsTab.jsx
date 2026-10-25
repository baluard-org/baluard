import { createSignal, onSettled, For, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { copyToClipboard } from "../lib/clipboard.js";
import ConfirmModal from "./ConfirmModal.jsx";
import { Button, Input } from "./Primitives.jsx";

/**
 * S2 UI: the address book. Import a contact card (out-of-band code),
 * run the Level 2 verification-code check, remove entries. Trust is
 * computed and stored daemon-side; this tab only displays it.
 */
export default function ContactsTab() {
  const { t } = useI18n();
  const [contacts, setContacts] = createSignal([]);
  const [myCard, setMyCard] = createSignal(null); // {card, verification_code}
  const [showFullCard, setShowFullCard] = createSignal(false);
  const [cardCode, setCardCode] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [revealed, setRevealed] = createSignal(null); // pubkey with code shown
  const [removeTarget, setRemoveTarget] = createSignal(null);

  async function loadContacts() {
    try {
      const res = JSON.parse(await daemon("contacts.list", {}));
      setContacts(res.contacts || []);
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
    try {
      const mine = JSON.parse(await daemon("contacts.my_card", {}));
      setMyCard(mine || null);
    } catch {
      setMyCard(null);
    }
  }

  onSettled(() => void loadContacts());

  async function importCard() {
    const code = cardCode().trim();
    if (!code) return;
    setBusy(true);
    try {
      await daemon("contacts.import_card", { card: code });
      setCardCode("");
      toastSuccess(t("contacts.importedToast"));
      await loadContacts();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function markVerified(pubkey) {
    setBusy(true);
    try {
      await daemon("contacts.mark_verified", { identity_signing_pubkey: pubkey });
      toastSuccess(t("contacts.verifiedToast"));
      await loadContacts();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function doRemove() {
    const target = removeTarget();
    if (!target) return;
    setBusy(true);
    try {
      await daemon("contacts.remove", { identity_signing_pubkey: target.pubkey });
      toastSuccess(t("people.removedToast"));
      await loadContacts();
    } catch (e) {
      toastError(sanitizeError(e, t));
      await loadContacts();
    } finally {
      setBusy(false);
      setRemoveTarget(null);
    }
  }

  return (
    <div class="space-y-6">
      {/* My card: the CODE travels to them; the verification code is
          what both sides compare out of band. */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-1">{t("contacts.myCardTitle")}</h3>
        <p class="text-xs text-[var(--color-muted)] mb-3">{t("contacts.myCardBody")}</p>
        <Show when={myCard()}>
          <div class="space-y-3">
            <div>
              <p class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-1">{t("contacts.cardCodeLabel")}</p>
              <div class="flex items-start gap-2">
                <code class={`flex-1 text-[11px] font-mono text-[var(--color-text)] break-all ${showFullCard() ? "" : "line-clamp-2"}`}>{myCard().card}</code>
                <button
                  onClick={() => setShowFullCard(!showFullCard())}
                  class="text-[10px] font-bold text-[var(--color-primary)] cursor-pointer whitespace-nowrap"
                >
                  {showFullCard() ? t("contacts.hideCode") : t("contacts.showCode")}
                </button>
              </div>
              <Button
                onClick={async () => {
                  await copyToClipboard(myCard().card);
                  toastSuccess(t("contacts.cardCopied"));
                }}
              >
                {t("contacts.copyCard")}
              </Button>
            </div>
            <div>
              <p class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-1">{t("contacts.myCodeLabel")}</p>
              <code data-testid="contacts-my-code" class="text-xs font-mono text-[var(--color-text)]">{myCard().verification_code}</code>
            </div>
          </div>
        </Show>
      </section>

      {/* Import: paste the card code received out of band. */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("contacts.importTitle")}</h3>
        <div class="flex gap-2">
          <Input
            value={cardCode()}
            onInput={(e) => setCardCode(e.currentTarget.value)}
            placeholder={t("contacts.importPlaceholder")}
          />
          <Button onClick={importCard} disabled={busy() || !cardCode().trim()}>
            {t("contacts.importAction")}
          </Button>
        </div>
      </section>

      {/* The book. */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("contacts.listTitle")}</h3>
        <Show
          when={contacts().length > 0}
          fallback={<p class="text-xs text-[var(--color-muted)]">{t("contacts.empty")}</p>}
        >
          <ul class="space-y-2">
            <For each={contacts()}>
              {(c) => (
                <li class="p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)]">
                  <div class="flex items-center justify-between gap-2">
                    <div class="min-w-0">
                      <p class="text-sm font-bold text-[var(--color-text)] truncate">{c.display_name}</p>
                      <p class="text-[11px] text-[var(--color-muted)]">
                        {c.has_wrap_key ? t("contacts.canReceive") : t("contacts.noWrapKey")}
                      </p>
                    </div>
                    <span
                      class={`text-[10px] font-bold border rounded-full px-2 py-0.5 whitespace-nowrap ${
                        c.trust === "verified"
                          ? "text-green-400 border-green-400/30"
                          : "text-amber-500 border-amber-500/30"
                      }`}
                    >
                      {t(c.trust === "verified" ? "contacts.trustVerified" : "contacts.trustChannel")}
                    </span>
                  </div>
                  <Show when={revealed() === c.identity_signing_pubkey}>
                    <div class="mt-2 p-2 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                      <p class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-1">
                        {t("contacts.theirCode")}
                      </p>
                      <code class="text-xs font-mono text-[var(--color-text)] break-all">{c.verification_code}</code>
                    </div>
                  </Show>
                  <div class="flex justify-end gap-2 mt-2">
                    <button
                      onClick={() => setRevealed(revealed() === c.identity_signing_pubkey ? null : c.identity_signing_pubkey)}
                      class="text-[10px] font-bold text-[var(--color-primary)] cursor-pointer"
                    >
                      {revealed() === c.identity_signing_pubkey ? t("contacts.hideCode") : t("contacts.showCode")}
                    </button>
                    <Show when={c.trust !== "verified"}>
                      <button
                        onClick={() => markVerified(c.identity_signing_pubkey)}
                        disabled={busy()}
                        class="text-[10px] font-bold text-[var(--color-primary)] cursor-pointer disabled:opacity-50"
                      >
                        {t("contacts.markVerified")}
                      </button>
                    </Show>
                    <button
                      onClick={() => setRemoveTarget({ pubkey: c.identity_signing_pubkey, name: c.display_name })}
                      class="text-[10px] font-bold text-red-400 cursor-pointer"
                    >
                      {t("contacts.remove")}
                    </button>
                  </div>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </section>

      <Show when={removeTarget()}>
        <ConfirmModal
          show
          idPrefix="contact-remove"
          title={t("contacts.removeTitle")}
          body={t("contacts.removeBody", { name: removeTarget().name })}
          confirmLabel={t("contacts.remove")}
          confirmClass="bg-[var(--color-danger)] text-white"
          onConfirm={() => void doRemove()}
          onClose={() => setRemoveTarget(null)}
        />
      </Show>
    </div>
  );
}
