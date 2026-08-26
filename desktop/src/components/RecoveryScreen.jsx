import { createSignal, createMemo, For, Show } from "solid-js";
import { useAuth } from "../context/AuthContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { IconNote, IconCopy, IconCheck, IconDownload } from "./Icon.jsx";
import ThemeToggleFloating from "./ThemeToggleFloating.jsx";
import { copyToClipboard } from "../lib/clipboard.js";
import { invoke } from "@tauri-apps/api/core";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import { sanitizeError } from "../lib/utils.js";

/**
 * Recovery phrase presentation + mandatory verification.
 *
 * The user MUST prove they wrote down the recovery phrase by re-entering
 * a random subset of words before they can proceed. This is not
 * security theater — the recovery phrase is the only root authority for
 * total device loss. If the user doesn't actually write it down, they
 * lose the vault permanently when all devices fail.
 *
 * The verification positions are deterministic (derived from the phrase
 * itself) so the same phrase always asks for the same words. This is
 * a UX choice, not a security control: since the full phrase is
 * displayed on screen, the positions are visible to an attacker. The
 * verification proves the user *paid attention and wrote something
 * down*, not that they have cryptographic assurance.
 */
function pickVerificationPositions(phrase) {
  // Hash the phrase to pick 4 stable positions out of 24.
  // Simple FNV-1a: good enough for stable position selection.
  const bytes = new TextEncoder().encode(phrase);
  let hash = 0x811c9dc5;
  for (const b of bytes) {
    hash ^= b;
    hash = (hash * 0x01000193) >>> 0;
  }
  const positions = [];
  let h = hash;
  while (positions.length < 4) {
    const pos = (h % 24) + 1; // 1-indexed
    if (!positions.includes(pos)) {
      positions.push(pos);
    }
    // Mix the hash so we get different positions
    h = (h * 0x01000193 + 0x9e3779b9) >>> 0;
  }
  return positions.sort((a, b) => a - b);
}

export default function RecoveryScreen() {
  const auth = useAuth();
  const { t } = useI18n();
  const [copied, setCopied] = createSignal(false);
  const [verifyWords, setVerifyWords] = createSignal(["", "", "", ""]);
  const [showExamples, setShowExamples] = createSignal(false);

  const phrase = () => auth.recoveryPhrase();
  const phraseWords = createMemo(() => phrase().split(/\s+/).filter(Boolean));
  const positions = createMemo(() => pickVerificationPositions(phrase()));

  const allVerified = createMemo(() => {
    const words = phraseWords();
    const inputs = verifyWords();
    return positions().every((pos, i) => {
      const expected = words[pos - 1] || "";
      const got = (inputs[i] || "").trim().toLowerCase();
      return expected.length > 0 && got === expected.toLowerCase();
    });
  });

  const handleCopy = async () => {
    await copyToClipboard(phrase());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = async () => {
    try {
      // D1: save dialog AND file write both run Rust-side. The webview passes
      // only the phrase contents — it never holds a filesystem path, and no
      // arbitrary-path write command exists anymore. Returns false on cancel.
      const saved = await invoke("save_recovery_phrase", { contents: phrase() });
      if (saved) toastSuccess(t("recovery.downloadSuccess"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  };

  const handleConfirm = (e) => {
    e.preventDefault();
    if (!allVerified()) return;
    // Zero recovery phrase from memory, transition to setup wizard
    auth.setRecoveryPhrase("");
    auth.setStatus("setup");
  };

  const updateWord = (i, val) => {
    const next = [...verifyWords()];
    next[i] = val;
    setVerifyWords(next);
  };

  return (
    <div class="h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] relative overflow-y-auto py-8">
      <ThemeToggleFloating />
      <div class="flex items-center justify-center min-h-full px-4">
      <div class="w-full max-w-lg p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">

        <div class="text-center mb-6">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-emerald-600 to-teal-500 flex items-center justify-center shadow-lg">
            <IconNote class="w-8 h-8 text-white" />
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("recovery.title")}</h1>
          <p class="text-sm text-red-400 mt-2 font-semibold">{t("recovery.warning")}</p>
        </div>

        {/* WHY: explain why this matters with concrete examples */}
        <div class="mb-5 p-4 rounded-xl box-warning border">
          <p class="text-sm font-semibold text-warning-title mb-2">{t("recovery.whyTitle")}</p>
          <p class="text-xs text-[var(--color-muted)] leading-relaxed mb-2">
            {t("recovery.whyBody")}
          </p>
          <button
            type="button"
            onClick={() => setShowExamples(!showExamples())}
            class="text-xs font-semibold btn-warning-link underline cursor-pointer"
          >
            {showExamples() ? t("recovery.hideExamples") : t("recovery.showExamples")}
          </button>
          <Show when={showExamples()}>
            <ul class="text-xs text-[var(--color-muted)] mt-2 space-y-1 list-disc list-inside">
              <li>{t("recovery.example1")}</li>
              <li>{t("recovery.example2")}</li>
              <li>{t("recovery.example3")}</li>
              <li>{t("recovery.example4")}</li>
            </ul>
          </Show>
        </div>

        {/* The phrase itself */}
        <div class="relative group px-10 py-5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] font-mono text-sm leading-relaxed text-[var(--color-text)] break-words select-all mb-4 text-center shadow-inner">
          {phrase()}
          <button
            onClick={handleCopy}
            class="absolute top-2 right-2 p-1.5 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-detail)] transition-all cursor-pointer shadow-sm flex items-center gap-1 text-xs"
            title={t("recovery.copyToClipboard")}
          >
            <Show when={copied()} fallback={
              <IconCopy class="w-4 h-4" />
            }>
              <span class="copy-feedback"><IconCheck class="w-4 h-4 text-[var(--color-success)]" /></span>
            </Show>
          </button>
        </div>

        <p class="text-xs text-[var(--color-muted)] text-center mb-5">
          {t("recovery.writeItDown")}
        </p>

        <button
          type="button"
          onClick={handleDownload}
          class="w-full mb-5 flex items-center justify-center gap-2 py-2.5 rounded-xl border border-[var(--color-border)] bg-[var(--color-bg)] text-sm font-medium text-[var(--color-text)] hover:border-[var(--color-primary)] hover:text-[var(--color-primary)] transition-all cursor-pointer"
        >
          <IconDownload class="w-4 h-4" />
          {t("recovery.downloadTxt")}
        </button>

        {/* Verification: re-enter 4 random words */}
        <form onSubmit={handleConfirm} class="space-y-4">
          <fieldset>
            <legend class="text-sm font-semibold text-[var(--color-text)] mb-3">
              {t("recovery.verifyTitle")}
            </legend>
            <div class="grid grid-cols-2 gap-3">
              <For each={positions()}>
                {(pos, i) => (
                  <label class="block">
                    <span class="block text-xs font-medium text-[var(--color-muted)] mb-1">
                      {t("recovery.wordN", { n: pos })}
                    </span>
                    <input
                      type="text"
                      autocomplete="off"
                      spellcheck={false}
                      autocapitalize="off"
                      autocorrect="off"
                      value={verifyWords()[i()]}
                      onInput={e => updateWord(i(), e.target.value)}
                      class="w-full px-3 py-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] font-mono text-sm outline-none focus:border-[var(--color-primary)] transition-all"
                      placeholder="—"
                    />
                  </label>
                )}
              </For>
            </div>
          </fieldset>

          <Show when={allVerified()}>
            <div class="flex items-center gap-2 text-sm text-[var(--color-success)] font-semibold">
              <IconCheck class="w-4 h-4" />
              {t("recovery.verified")}
            </div>
          </Show>

          <button
            type="submit"
            disabled={!allVerified()}
            class={["w-full py-3.5 rounded-xl font-semibold transition-all shadow-lg", {
              "bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] cursor-pointer": allVerified(),
              "bg-[var(--color-border)] text-[var(--color-muted)] cursor-not-allowed": !allVerified(),
            }]}
          >
            {allVerified() ? t("recovery.confirm") : t("recovery.confirmDisabled")}
          </button>
        </form>
      </div>
      </div>
    </div>
  );
}
