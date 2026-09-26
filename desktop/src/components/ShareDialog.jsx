import { createSignal, For, onSettled, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { copyToClipboard } from "../lib/clipboard.js";
import FocusTrap from "./FocusTrap.jsx";
import { Button } from "./Primitives.jsx";
import { Transition } from "../lib/transition";

/**
 * S2: share an entry. Two flavors:
 * - guest (default): passphrase-guest reveal — the recipient needs no
 *   account; the passphrase and the file travel by different channels.
 * - contact: sealed to a contact's identity key — no passphrase, but
 *   the recipient must have shared a card and opened it in the app.
 * Login-type entries offer both; every other type offers the package
 * (one-shot import) flavor only. The daemon stays the validator.
 *
 * Props: cipher (the entry being shared), onClose.
 */
export default function ShareDialog(props) {
  const { t } = useI18n();
  let dialogRef;
  const [expiry, setExpiry] = createSignal(7 * 86400);
  const [includeTotp, setIncludeTotp] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [result, setResult] = createSignal(null);
  const [contacts, setContacts] = createSignal([]);
  const [flavor, setFlavor] = createSignal("guest");
  const [contactId, setContactId] = createSignal("");

  const isLogin = !props.cipher?.type || props.cipher?.type === "login";
  // Packages and contact reveals are the only flavors non-login entries
  // have; guest reveals are login-only daemon-side.
  const effectiveFlavor = () => (isLogin ? flavor() : "contact");
  const contactable = () => contacts().filter((c) => c.has_wrap_key);

  onSettled(async () => {
    try {
      const res = JSON.parse(await daemon("contacts.list", {}));
      const usable = (res.contacts || []).filter((c) => c.has_wrap_key);
      setContacts(usable);
      if (usable.length > 0) setContactId(usable[0].identity_signing_pubkey);
    } catch {
      setContacts([]);
    }
  });

  const expiryOptions = [
    [86400, "share.expiry1d"],
    [7 * 86400, "share.expiry7d"],
    [30 * 86400, "share.expiry30d"],
  ];

  async function create() {
    const id = props.cipher?.id;
    if (!id) return;
    const flavorNow = effectiveFlavor();
    if (flavorNow === "contact" && !contactId()) return;
    setBusy(true);
    try {
      const expiresAt = Math.floor(Date.now() / 1000) + expiry();
      if (flavorNow === "contact") {
        if (isLogin) {
          const res = JSON.parse(
            await daemon("reveals.export_contact", {
              cipher_id: id,
              contact: contactId(),
              expires_at: expiresAt,
              include_totp: includeTotp(),
            }),
          );
          setResult(res);
        } else {
          const res = JSON.parse(
            await daemon("packages.export", { cipher_id: id, contact: contactId() }),
          );
          setResult(res);
        }
      } else {
        const res = JSON.parse(
          await daemon("reveals.export_guest", {
            cipher_id: id,
            expires_at: expiresAt,
            include_totp: includeTotp(),
          }),
        );
        setResult(res);
      }
      toastSuccess(t("share.createdToast"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  function saveFile() {
    const r = result();
    const payload = r?.reveal || r?.package;
    if (!payload) return;
    const bytes = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${(props.cipher?.name || "shared").replace(/[^\w.-]+/g, "_")}.baluard-share`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function copyPassphrase() {
    const r = result();
    if (!r?.passphrase) return;
    // Shared utility, not a raw write: auto-clears after 30s and marks
    // the clipboard concealed so OS history skips it.
    await copyToClipboard(r.passphrase);
    toastSuccess(t("share.passphraseCopied"));
  }

  return (
    <Transition name="fade">
      <Show when={props.cipher}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="share-title"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => props.onClose()}
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => props.onClose()} />
          <div
            class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-md w-full shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="share-title" class="text-base font-bold text-[var(--color-text)] mb-1">
              {t("share.title")}
            </h2>
            <p class="text-xs text-[var(--color-muted)] mb-4">
              {t("share.subtitle", { name: props.cipher?.name || "" })}
            </p>
            <Show
              when={result()}
              fallback={
                <>
                  <Show when={contactable().length > 0 && isLogin}>
                    <div class="flex gap-2 mb-4">
                      <button
                        type="button"
                        onClick={() => setFlavor("guest")}
                        class={`flex-1 px-3 py-2 rounded-lg border text-xs font-medium cursor-pointer ${
                          flavor() === "guest"
                            ? "border-[var(--color-primary)] text-[var(--color-primary)]"
                            : "border-[var(--color-border)] text-[var(--color-muted)]"
                        }`}
                      >
                        {t("share.flavorGuest")}
                      </button>
                      <button
                        type="button"
                        onClick={() => setFlavor("contact")}
                        class={`flex-1 px-3 py-2 rounded-lg border text-xs font-medium cursor-pointer ${
                          flavor() === "contact"
                            ? "border-[var(--color-primary)] text-[var(--color-primary)]"
                            : "border-[var(--color-border)] text-[var(--color-muted)]"
                        }`}
                      >
                        {t("share.flavorContact")}
                      </button>
                    </div>
                  </Show>
                  <Show when={effectiveFlavor() === "contact"}>
                    <div class="mb-4">
                      <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="share-contact">
                        {t("share.contactLabel")}
                      </label>
                      <select
                        id="share-contact"
                        value={contactId()}
                        onChange={(e) => setContactId(e.currentTarget.value)}
                        class="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] text-xs text-[var(--color-text)]"
                      >
                        <For each={contactable()}>
                          {(c) => (
                            <option value={c.identity_signing_pubkey}>
                              {c.display_name}
                              {c.trust === "verified" ? " ✓" : ""}
                            </option>
                          )}
                        </For>
                      </select>
                      <Show when={contactable().length === 0}>
                        <p class="text-[11px] text-[var(--color-muted)] mt-1">{t("share.noContactsHint")}</p>
                      </Show>
                    </div>
                  </Show>
                  <Show when={!(effectiveFlavor() === "contact" && !isLogin)}>
                    <p class="block text-xs font-semibold text-[var(--color-muted)] mb-2">{t("share.expiryLabel")}</p>
                    <div class="flex gap-2 mb-4">
                      <For each={expiryOptions}>
                        {([secs, key]) => (
                          <button
                            type="button"
                            onClick={() => setExpiry(secs)}
                            class={`px-3 py-1.5 rounded-lg border text-xs font-medium cursor-pointer ${
                              expiry() === secs
                                ? "border-[var(--color-primary)] text-[var(--color-primary)]"
                                : "border-[var(--color-border)] text-[var(--color-muted)]"
                            }`}
                          >
                            {t(key)}
                          </button>
                        )}
                      </For>
                    </div>
                  </Show>
                  <Show when={isLogin}>
                    <label class="flex items-center gap-2 text-xs text-[var(--color-text)] mb-4 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={includeTotp()}
                        onChange={(e) => setIncludeTotp(e.currentTarget.checked)}
                      />
                      {t("share.includeTotp")}
                    </label>
                  </Show>
                  <div class="flex justify-end gap-2">
                    <Button onClick={() => props.onClose()}>{t("common.close")}</Button>
                    <Button
                      onClick={create}
                      disabled={busy() || (effectiveFlavor() === "contact" && contactable().length === 0)}
                    >
                      {busy() ? t("common.sending") : t("share.createAction")}
                    </Button>
                  </div>
                </>
              }
            >
              <Show when={result().passphrase}>
                <div class="mb-4 p-3 rounded-lg border border-amber-500/30 bg-amber-500/5">
                  <p class="text-xs font-bold text-[var(--color-text)] mb-1">{t("share.passphraseLabel")}</p>
                  <div class="flex items-center gap-2">
                    <code class="flex-1 text-xs font-mono break-all text-[var(--color-text)]">{result().passphrase}</code>
                    <Button onClick={copyPassphrase}>{t("share.copyPassphrase")}</Button>
                  </div>
                  <p class="text-[11px] text-[var(--color-muted)] mt-2">{t("share.separateChannels")}</p>
                </div>
              </Show>
              <Show when={effectiveFlavor() === "contact"}>
                <p class="text-[11px] text-[var(--color-muted)] mb-4">{t("share.contactNote")}</p>
              </Show>
              <div class="flex justify-end gap-2">
                <Button onClick={() => props.onClose()}>{t("common.close")}</Button>
                <Button onClick={saveFile}>{t("share.saveFile")}</Button>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
