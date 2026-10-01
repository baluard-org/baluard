import { createSignal, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { copyToClipboard } from "../lib/clipboard.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { holdPhrase, takeHeldPhrase, clearHeldPhrase } from "../lib/heldPhrase.js";
import FocusTrap from "./FocusTrap.jsx";
import { Transition } from "../lib/transition";
import { Button } from "./Primitives.jsx";
import { requestReprompt } from "./RepromptModal.jsx";

// Recovery-phrase exit path: replace the vault's 24-word phrase. Rotation
// is master-password gated daemon-side (the daemon stays the validator);
// the phrase is shown exactly once here, with copy and plain-text export,
// because once this dialog closes nobody can read the phrase back.
export default function RecoveryPhraseCard() {
  const { t } = useI18n();
  const [busy, setBusy] = createSignal(false);
  const [phrase, setPhrase] = createSignal("");
  const [stored, setStored] = createSignal(false);
  const [copied, setCopied] = createSignal(false);
  let dialogRef;

  const words = () => phrase().split(/\s+/).filter(Boolean);

  const replace = () => {
    requestReprompt(async (password) => {
      setBusy(true);
      try {
        const r = await daemon("vault.rotate_recovery", { old_password: password });
        const parsed = typeof r === "string" ? JSON.parse(r) : r;
        setStored(false);
        setCopied(false);
        setPhrase(parsed.phrase || "");
        // Blur-lock can unmount the modal mid-showing; the phrase stays
        // recoverable in process memory until the user confirms storage.
        holdPhrase("recovery", parsed.phrase || "");
        toastSuccess(t("recovery.rotatedToast"));
      } catch (e) {
        toastError(sanitizeError(e, t));
      } finally {
        setBusy(false);
      }
    });
  };

  const download = (ext) => {
    const wordsText = words().map((w, i) => `${i + 1}. ${w}`).join("\n");
    const body =
      ext === "md"
        ? `# ${t("recovery.title")}\n\n${t("recovery.warning")}\n\n${wordsText}\n`
        : `${t("recovery.title")}\n${t("recovery.warning")}\n\n${wordsText}\n`;
    const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `baluard-recovery-phrase.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copy = async () => {
    await copyToClipboard(phrase());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const close = () => {
    if (!stored()) return;
    setPhrase("");
    setStored(false);
    clearHeldPhrase("recovery");
  };

  // A blur-lock unmounted the ceremony before the phrase was confirmed:
  // re-show it (still gated on the stored checkbox).
  if (!phrase() && stored() === false) {
    const held = takeHeldPhrase("recovery");
    if (held) setPhrase(held);
  }

  return (
    <div class="space-y-2">
      <div class="flex flex-col">
        <span class="text-xs font-bold text-[var(--color-text)]">{t("recovery.title")}</span>
        <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("recovery.desc")}</span>
      </div>
      <div class="flex items-center gap-3">
        <Button
          onClick={replace}
          disabled={busy()}
          class="text-xs py-2 px-3 font-mono uppercase"
        >
          {t("recovery.replace")}
        </Button>
        <span class="text-[10px] text-[var(--color-muted)]">{t("recovery.replacedNote")}</span>
      </div>

      <Transition name="fade">
        <Show when={phrase()}>
          <div class="fixed inset-0 z-[110] flex items-center justify-center bg-black/60 p-4">
            <div
              ref={dialogRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby="recovery-ceremony-title"
              class="w-full max-w-lg rounded-2xl bg-[var(--color-bg)] border border-amber-500/40 p-6 space-y-4"
            >
              <FocusTrap containerRef={dialogRef} onEscape={close} />
                <h3 id="recovery-ceremony-title" class="text-sm font-bold text-amber-400 font-mono uppercase tracking-wider">
                  {t("recovery.ceremonyTitle")}
                </h3>
                <p class="text-xs text-[var(--color-muted)]">{t("recovery.warning")}</p>
                <div class="rounded-xl bg-[var(--color-sidebar)] border border-amber-500/30 p-4 font-mono text-sm leading-relaxed text-[var(--color-text)] break-words" aria-label={t("recovery.title")}>
                  {words().map((w) => (
                    <span class="inline-block mr-3 mb-1">{w}</span>
                  ))}
                </div>
                <div class="flex flex-wrap gap-2">
                  <Button onClick={copy} class="text-xs py-2 px-3 font-mono uppercase">
                    {copied() ? t("recovery.copied") : t("recovery.copy")}
                  </Button>
                  <Button onClick={() => download("txt")} class="text-xs py-2 px-3 font-mono uppercase">
                    {t("recovery.downloadTxt")}
                  </Button>
                  <Button onClick={() => download("md")} class="text-xs py-2 px-3 font-mono uppercase">
                    {t("recovery.downloadMd")}
                  </Button>
                </div>
                <label class="flex items-center gap-2 text-xs text-[var(--color-text)] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={stored()}
                    onChange={(e) => setStored(e.currentTarget.checked)}
                  />
                  {t("recovery.stored")}
                </label>
                <div class="flex justify-end">
                  <Button
                    onClick={close}
                    disabled={!stored()}
                    variant="primary"
                    class="text-xs py-2 px-4 font-mono uppercase"
                  >
                    {t("recovery.done")}
                  </Button>
                </div>
            </div>
          </div>
        </Show>
      </Transition>
    </div>
  );
}
