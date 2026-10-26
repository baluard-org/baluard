import { createSignal, onMount, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError, generatePassphrase } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { copyToClipboard } from "../lib/clipboard.js";
import ConfirmModal from "./ConfirmModal.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { Button, Input } from "./Primitives.jsx";
import { IconCopy } from "./Icon.jsx";

const WINDOW_PRESETS = [14, 30, 90, 365];

/**
 * Legacy Contact owner tab (docs/plan-legacy-contact.md): arm a kit,
 * watch the silence window, and deny / disarm / replace. The contact
 * surface is a separate read-only flow; this tab is owner-only.
 */
export default function LegacyTab() {
  const { t } = useI18n();
  let kitDialogRef;
  const [status, setStatus] = createSignal(null); // parsed legacy.status
  const [busy, setBusy] = createSignal(false);

  // Arm form
  const [windowDays, setWindowDays] = createSignal(30);
  const [contactName, setContactName] = createSignal("");
  const [letter, setLetter] = createSignal("");
  const [passphrase, setPassphrase] = createSignal("");
  const [savedIt, setSavedIt] = createSignal(false);
  const [kit, setKit] = createSignal(null); // {kit_id, kit_armor} shown once
  const [confirmKind, setConfirmKind] = createSignal(null); // deny|disarm

  onMount(() => void load());

  async function load() {
    try {
      const res = JSON.parse(await daemon("legacy.status", {}));
      setStatus(res || {});
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  function newPassphrase() {
    setPassphrase(generatePassphrase(4, " "));
    setSavedIt(false);
  }

  async function arm() {
    if (!passphrase() || !savedIt()) return;
    setBusy(true);
    try {
      const res = JSON.parse(
        await daemon("legacy.arm", {
          window_days: windowDays(),
          passphrase: passphrase(),
          letter: letter(),
          contact_name: contactName(),
        })
      );
      setPassphrase("");
      setSavedIt(false);
      setKit(res || {});
      await load();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function close(reason) {
    setBusy(true);
    try {
      await daemon("legacy.close", { reason });
      setConfirmKind(null);
      await load();
      toastSuccess(t("legacy.closedToast"));
    } catch (e) {
      toastError(sanitizeError(e, t));
      setConfirmKind(null);
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    try {
      const res = JSON.parse(await daemon("legacy.resend", {}));
      setKit(res || {});
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  function downloadKit() {
    const k = kit();
    if (!k) return;
    const blob = new Blob([k.kit_armor || ""], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `legacy-kit-${k.kit_id || "kit"}.bldlegacy`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  const phase = () => status()?.phase || "none";

  return (
    <div class="space-y-4">
      <div>
        <label class="text-xs font-bold text-[var(--color-text)]">{t("legacy.title")}</label>
        <p class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("legacy.desc")}</p>
      </div>

      <Show
        when={phase() === "quiet" || phase() === "open"}
        fallback={
          <div class="rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]/40 p-4 space-y-4">
            <Show
              when={phase() === "closed"}
              fallback={<p class="text-sm text-[var(--color-muted)]">{t("legacy.notArmed")}</p>}
            >
              <p class="text-sm text-[var(--color-muted)]">{t("legacy.wasClosed")}</p>
            </Show>

            <div class="space-y-1.5">
              <label class="text-xs font-bold text-[var(--color-text)]">{t("legacy.windowLabel")}</label>
              <div class="flex gap-2 flex-wrap">
                <For each={WINDOW_PRESETS}>
                  {(d) => (
                    <button
                      onClick={() => setWindowDays(d)}
                      data-testid={`legacy-window-${d}`}
                      class={`px-3 py-1.5 text-xs font-semibold rounded-lg border transition-all cursor-pointer ${
                        windowDays() === d
                          ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-transparent"
                          : "border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)]"
                      }`}
                    >
                      {t("legacy.windowDays", { days: d })}
                    </button>
                  )}
                </For>
              </div>
              <p class="text-[10px] text-[var(--color-muted)]">{t("legacy.windowHint")}</p>
            </div>

            <div class="space-y-1.5">
              <label class="text-xs font-bold text-[var(--color-text)]" for="legacy-contact">
                {t("legacy.contactLabel")}
              </label>
              <Input
                id="legacy-contact"
                value={contactName()}
                onInput={(e) => setContactName(e.currentTarget.value)}
                placeholder={t("legacy.contactPlaceholder")}
                data-testid="legacy-contact"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-xs font-bold text-[var(--color-text)]" for="legacy-letter">
                {t("legacy.letterLabel")}
              </label>
              <textarea
                id="legacy-letter"
                value={letter()}
                onInput={(e) => setLetter(e.currentTarget.value)}
                placeholder={t("legacy.letterPlaceholder")}
                rows="3"
                data-testid="legacy-letter"
                class="w-full px-3 py-2 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-sm text-[var(--color-text)] placeholder-[var(--color-muted)] outline-none focus:border-[var(--color-primary)] resize-y"
              />
            </div>

            <div class="space-y-1.5">
              <label class="text-xs font-bold text-[var(--color-text)]">{t("legacy.passphraseLabel")}</label>
              <div class="flex gap-2">
                <Show when={passphrase()} fallback={
                  <Button onClick={newPassphrase} data-testid="legacy-new-passphrase">
                    {t("legacy.newPassphrase")}
                  </Button>
                }>
                  <code class="flex-1 px-3 py-2 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-sm text-[var(--color-text)] select-all" data-testid="legacy-passphrase">
                    {passphrase()}
                  </code>
                  <Button
                    onClick={async () => { await copyToClipboard(passphrase()); toastSuccess(t("generator.copied")); }}
                    aria-label={t("common.copy")}
                  >
                    <IconCopy class="w-4 h-4" />
                  </Button>
                </Show>
              </div>
              <p class="text-[10px] text-[var(--color-muted)]">{t("legacy.passphraseHint")}</p>
              <label class="flex items-center gap-2 text-xs text-[var(--color-text)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={savedIt()}
                  onChange={(e) => setSavedIt(e.currentTarget.checked)}
                  data-testid="legacy-saved-it"
                />
                {t("legacy.savedIt")}
              </label>
            </div>

            <Button
              variant="primary"
              onClick={arm}
              disabled={busy() || !passphrase() || !savedIt()}
              data-testid="legacy-arm"
            >
              {t("legacy.arm")}
            </Button>
          </div>
        }
      >
        <div class="rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]/40 p-4 space-y-3">
          <Show when={phase() === "open"} fallback={
            <p class="text-sm text-[var(--color-text)]">{t("legacy.armedQuiet", { days: status()?.window_days ?? 0 })}</p>
          }>
            <p class="text-sm font-semibold text-[var(--color-danger)]">{t("legacy.windowElapsed")}</p>
          </Show>
          <p class="text-xs text-[var(--color-muted)]">
            {t("legacy.silenceSoFar", { days: status()?.silence_days ?? 0 })}
          </p>
          <div class="flex gap-2 flex-wrap pt-1">
            <Button onClick={resend} disabled={busy()} data-testid="legacy-resend">
              {t("legacy.resend")}
            </Button>
            <Button onClick={() => setConfirmKind("disarm")} disabled={busy()} data-testid="legacy-disarm">
              {t("legacy.disarm")}
            </Button>
            <Show when={phase() === "open"}>
              <Button variant="danger" onClick={() => setConfirmKind("deny")} disabled={busy()} data-testid="legacy-deny">
                {t("legacy.deny")}
              </Button>
            </Show>
          </div>
        </div>
      </Show>

      {/* The kit letter, shown once per arm/resend. */}
      <Show when={kit()}>
        <div class="fixed inset-0 bg-black/50 z-50 flex items-center justify-center" onClick={() => setKit(null)}>
          <FocusTrap containerRef={() => kitDialogRef} onEscape={() => setKit(null)} />
          <div
            ref={kitDialogRef}
            class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-lg w-full shadow-2xl space-y-4 mx-4"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="legacy-kit-title"
          >
            <h3 id="legacy-kit-title" class="text-lg font-bold text-[var(--color-text)]">{t("legacy.kitTitle")}</h3>
            <p class="text-xs text-[var(--color-muted)]">{t("legacy.kitDesc")}</p>
            <pre class="max-h-56 overflow-auto text-[10px] leading-4 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg p-3 text-[var(--color-text)] whitespace-pre-wrap select-all" data-testid="legacy-kit-armor">{kit()?.kit_armor}</pre>
            <div class="flex gap-2">
              <Button variant="primary" onClick={downloadKit} data-testid="legacy-kit-download">
                {t("legacy.kitDownload")}
              </Button>
              <Button onClick={async () => { await copyToClipboard(kit()?.kit_armor || ""); toastSuccess(t("generator.copied")); }}>
                {t("legacy.kitCopy")}
              </Button>
              <Button onClick={() => setKit(null)}>{t("entry.close")}</Button>
            </div>
          </div>
        </div>
      </Show>

      <ConfirmModal
        show={confirmKind() !== null}
        idPrefix="legacy-confirm"
        title={t(confirmKind() === "deny" ? "legacy.denyTitle" : "legacy.disarmTitle")}
        body={t(confirmKind() === "deny" ? "legacy.denyBody" : "legacy.disarmBody")}
        confirmLabel={t(confirmKind() === "deny" ? "legacy.deny" : "legacy.disarm")}
        confirmClass="bg-[var(--color-danger)] text-white"
        onConfirm={() => close(confirmKind() === "deny" ? "denied" : "disarmed")}
        onClose={() => setConfirmKind(null)}
      />
    </div>
  );
}
