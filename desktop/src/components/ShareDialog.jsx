import { createSignal, For, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { copyToClipboard } from "../lib/clipboard.js";
import FocusTrap from "./FocusTrap.jsx";
import { Button } from "./Primitives.jsx";
import { Transition } from "../lib/transition";

/**
 * S2 IS-6: share an entry via a passphrase-guest reveal. Produces a
 * .baluard-share file plus a one-time passphrase; the two travel to the
 * recipient by different channels. The contact-key flavor needs the
 * address book and is a later wave; the daemon stays the validator.
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

  const expiryOptions = [
    [86400, "share.expiry1d"],
    [7 * 86400, "share.expiry7d"],
    [30 * 86400, "share.expiry30d"],
  ];

  async function create() {
    const id = props.cipher?.id;
    if (!id) return;
    setBusy(true);
    try {
      const res = JSON.parse(
        await daemon("reveals.export_guest", {
          cipher_id: id,
          expires_at: Math.floor(Date.now() / 1000) + expiry(),
          include_totp: includeTotp(),
        }),
      );
      setResult(res);
      toastSuccess(t("share.createdToast"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  function saveFile() {
    const r = result();
    if (!r?.reveal) return;
    const bytes = Uint8Array.from(atob(r.reveal), (c) => c.charCodeAt(0));
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
                  <label class="flex items-center gap-2 text-xs text-[var(--color-text)] mb-4 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={includeTotp()}
                      onChange={(e) => setIncludeTotp(e.currentTarget.checked)}
                    />
                    {t("share.includeTotp")}
                  </label>
                  <div class="flex justify-end gap-2">
                    <Button onClick={() => props.onClose()}>{t("common.close")}</Button>
                    <Button onClick={create} disabled={busy()}>
                      {busy() ? t("common.sending") : t("share.createAction")}
                    </Button>
                  </div>
                </>
              }
            >
              <div class="mb-4 p-3 rounded-lg border border-amber-500/30 bg-amber-500/5">
                <p class="text-xs font-bold text-[var(--color-text)] mb-1">{t("share.passphraseLabel")}</p>
                <div class="flex items-center gap-2">
                  <code class="flex-1 text-xs font-mono break-all text-[var(--color-text)]">{result().passphrase}</code>
                  <Button onClick={copyPassphrase}>{t("share.copyPassphrase")}</Button>
                </div>
                <p class="text-[11px] text-[var(--color-muted)] mt-2">{t("share.separateChannels")}</p>
              </div>
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
