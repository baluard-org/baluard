import { createSignal, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import FocusTrap from "./FocusTrap.jsx";
import { Button, Input } from "./Primitives.jsx";
import { Transition } from "../lib/transition";

/** The daemon refuses b64 payloads over MAX_PACKAGE_FILE_BYTES * 2 (8MB);
 *  guard here so a mis-picked huge file cannot lock the webview. */
const MAX_FILE_BYTES = 4 * 1024 * 1024;

/**
 * S2 receive surfaces: open a shared .baluard-share file. Two modes:
 * - vaulted (default): try packages.import (one-shot entry), then
 *   reveals.open_contact (view), then the guest open with a passphrase.
 * - guest (no vault, first-run): file + passphrase straight to the
 *   tokenless reveals.open_guest route.
 * The daemon stays the validator; this modal only routes the file.
 *
 * Props: guest (bool), onClose. Vaulted mode requires an unlocked vault.
 */
export default function OpenSharedModal(props) {
  const { t } = useI18n();
  let dialogRef;
  let fileInput;
  const [passphrase, setPassphrase] = createSignal("");
  const [fileB64, setFileB64] = createSignal(null);
  const [fileName, setFileName] = createSignal("");
  const [needsPassphrase, setNeedsPassphrase] = createSignal(props.guest === true);
  const [busy, setBusy] = createSignal(false);
  const [opened, setOpened] = createSignal(null);
  // The contact-reveal leg often fails with the MOST specific error
  // (expired, wrong recipient); if the guest open then also fails, show
  // that instead of a generic wrong-passphrase message.
  let contactLegError = null;

  function pickFile() {
    fileInput?.click();
  }

  function onFile(e) {
    const f = e.currentTarget.files?.[0];
    if (!f) return;
    if (f.size > MAX_FILE_BYTES) {
      toastError(t("share.fileTooLarge"));
      e.currentTarget.value = "";
      return;
    }
    setFileName(f.name);
    // A new file restarts the auto-detect chain: without this reset the
    // retry would skip straight to the guest open for a package file.
    if (!props.guest) setNeedsPassphrase(false);
    contactLegError = null;
    const reader = new FileReader();
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result);
      let bin = "";
      for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      setFileB64(btoa(bin));
    };
    reader.readAsArrayBuffer(f);
  }

  async function open() {
    const b64 = fileB64();
    if (!b64) return;
    setBusy(true);
    try {
      if (props.guest) {
        await openGuest();
      } else if (needsPassphrase()) {
        // Both vaulted flavors already refused this file: it is a guest
        // reveal and the passphrase is in. Go straight to the open.
        await openGuest();
      } else {
        // One-shot package: imports a fresh entry.
        try {
          const res = JSON.parse(await daemon("packages.import", { package: b64 }));
          toastSuccess(t("share.importedToast", { sender: res.sender || "" }));
          props.onImported?.();
          props.onClose();
          return;
        } catch (_) {
          // Not a package: fall through to the reveal flavors.
        }
        // Contact-key reveal: view-only.
        try {
          const res = JSON.parse(await daemon("reveals.open_contact", { reveal: b64 }));
          setOpened(res);
          return;
        } catch (e) {
          // Not a contact reveal either: guest flavor needs the passphrase.
          contactLegError = e?.message || null;
          setNeedsPassphrase(true);
          toastError(t("share.passphraseRequired"));
          return;
        }
      }
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function openGuest() {
    try {
      const res = JSON.parse(
        await daemon("reveals.open_guest", {
          reveal: fileB64(),
          passphrase: passphrase(),
        }),
      );
      setOpened(res);
    } catch (e) {
      // Wrong passphrase looks identical to a file that was never a
      // guest reveal; the contact leg's error is usually the truth.
      if (contactLegError) throw new Error(contactLegError);
      throw e;
    }
  }

  function fieldType(row) {
    return (
      <Show when={row.value}>
        <div class="mb-3">
          <p class="text-xs font-semibold text-[var(--color-muted)] mb-0.5">{row.label}</p>
          <Show when={row.mono} fallback={<p class="text-sm text-[var(--color-text)] break-all">{row.value}</p>}>
            <code class="text-sm font-mono text-[var(--color-text)] break-all">{row.value}</code>
          </Show>
        </div>
      </Show>
    );
  }

  // Read the signal inside the JSX so the view tracks the decrypted
  // record instead of the null captured at setup.
  const v = () => opened();
  return (
    <Transition name="fade">
      <Show when={true}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="open-shared-title"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => props.onClose()}
        >
          <FocusTrap containerRef={() => dialogRef} onEscape={() => props.onClose()} />
          <div
            class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-md w-full shadow-2xl max-h-[85vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="open-shared-title" class="text-base font-bold text-[var(--color-text)] mb-1">
              {t("share.openTitle")}
            </h2>
            <p class="text-xs text-[var(--color-muted)] mb-4">{t("share.openSubtitle")}</p>
            <Show
              when={opened()}
              fallback={
                <>
                  <input
                    ref={fileInput}
                    type="file"
                    accept=".baluard-share,application/octet-stream"
                    class="hidden"
                    onChange={onFile}
                  />
                  <div class="mb-4">
                    <Button onClick={pickFile} disabled={busy()}>
                      {fileName() || t("share.pickFile")}
                    </Button>
                  </div>
                  <Show when={needsPassphrase()}>
                    <div class="mb-4">
                      <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="share-pass">
                        {t("share.passphraseField")}
                      </label>
                      <Input
                        id="share-pass"
                        type="password"
                        value={passphrase()}
                        onInput={(e) => setPassphrase(e.currentTarget.value)}
                        placeholder={t("share.passphraseField")}
                      />
                    </div>
                  </Show>
                  <div class="flex justify-end gap-2">
                    <Button onClick={() => props.onClose()}>{t("common.close")}</Button>
                    <Button onClick={open} disabled={busy() || !fileB64() || (needsPassphrase() && !passphrase())}>
                      {busy() ? t("common.sending") : t("share.openAction")}
                    </Button>
                  </div>
                </>
              }
            >
              <p class="text-sm font-bold text-[var(--color-text)] mb-3">{v()?.item_name}</p>
              {fieldType({ label: t("share.fromLabel"), value: v()?.sender_name })}
              {fieldType({ label: t("share.urlLabel"), value: v()?.url })}
              {fieldType({ label: t("share.usernameLabel"), value: v()?.username })}
              {fieldType({ label: t("share.passwordLabel"), value: v()?.password, mono: true })}
              {fieldType({ label: t("share.totpLabel"), value: v()?.totp_code, mono: true })}
              <Show when={v()?.expires_at}>
                <p class="text-[11px] text-[var(--color-muted)] mb-3">
                  {t("share.expiresLabel")} {new Date(v()?.expires_at * 1000).toLocaleString()}
                </p>
              </Show>
              <div class="flex justify-end gap-2">
                <Button onClick={() => props.onClose()}>{t("common.close")}</Button>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
