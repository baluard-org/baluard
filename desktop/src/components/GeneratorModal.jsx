import { createSignal, createEffect, Show, For } from "solid-js";
import { Transition } from "../lib/transition";
import { useI18n } from "../i18n/index.jsx";
import { generateSecurePassword, generatePassphrase } from "../lib/utils.js";
import { IconCopy, IconCheck, IconRefresh } from "./Icon.jsx";
import { copyToClipboard } from "../lib/clipboard.js";
import { daemon } from "../lib/daemon.js";
import FocusTrap from "./FocusTrap.jsx";

const MODE_PASSWORD = "password";
const MODE_PASSPHRASE = "passphrase";

function timeAgo(ts, t) {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return t("generator.timeJustNow");
  if (diff < 3600) return t("generator.timeMinutesAgo", { n: Math.floor(diff / 60) });
  if (diff < 86400) return t("generator.timeHoursAgo", { n: Math.floor(diff / 3600) });
  return t("generator.timeDaysAgo", { n: Math.floor(diff / 86400) });
}

export default function GeneratorModal(props) {
  const { t } = useI18n();
  let dialogRef;
  const [mode, setMode] = createSignal(MODE_PASSWORD);
  const [copied, setCopied] = createSignal(false);
  const [historyCopied, setHistoryCopied] = createSignal(null);

  // Password params
  const [len, setLen] = createSignal(16);
  const [useUpper, setUseUpper] = createSignal(true);
  const [useNums, setUseNums] = createSignal(true);
  const [useSyms, setUseSyms] = createSignal(true);

  // Passphrase params
  const [wordCount, setWordCount] = createSignal(5);
  const [separator, setSeparator] = createSignal("-");
  const [ppUpper, setPpUpper] = createSignal(false);
  const [ppNumber, setPpNumber] = createSignal(false);
  const [ppSymbol, setPpSymbol] = createSignal(false);

  const [result, setResult] = createSignal("");

  // History state
  const [showHistory, setShowHistory] = createSignal(false);
  const [history, setHistory] = createSignal([]);
  const [clearing, setClearing] = createSignal(false);
  const [confirmClear, setConfirmClear] = createSignal(false);
  const [lastPersisted, setLastPersisted] = createSignal(null);

  async function fetchHistory() {
    try {
      const json = await daemon("generator.history_list");
      const list = JSON.parse(json);
      setHistory(list);
    } catch {
      setHistory([]);
    }
  }

  async function persistToHistory(value, kind, params) {
    try {
      const json = await daemon("generator.history_add", JSON.stringify({ value, kind, params }));
      const list = JSON.parse(json);
      setHistory(list);
    } catch {
      // History persistence is best-effort, don't block generation
    }
  }

  /** Pure generation (no side effects). Called by reactive effect. */
  function generate() {
    if (mode() === MODE_PASSWORD) {
      return generateSecurePassword(len(), useUpper(), useNums(), useSyms());
    }
    return generatePassphrase(wordCount(), separator(), {
      upper: ppUpper(),
      number: ppNumber(),
      symbol: ppSymbol(),
    });
  }

  /** Build params snapshot from current signals. */
  function currentParams() {
    if (mode() === MODE_PASSWORD) {
      return { length: len(), upper: useUpper(), numbers: useNums(), symbols: useSyms(), separator: null };
    }
    return { length: wordCount(), upper: ppUpper(), numbers: ppNumber(), symbols: ppSymbol(), separator: separator() };
  }

  /** User clicked Regenerate: generate + persist. */
  function handleRegenerate() {
    const val = generate();
    const params = currentParams();
    setResult(val);
    setLastPersisted(val);
    persistToHistory(val, mode() === MODE_PASSWORD ? "password" : "passphrase", params);
  }

  createEffect(
    () => {
      mode(); len(); useUpper(); useNums(); useSyms();
      wordCount(); separator(); ppUpper(); ppNumber(); ppSymbol();
      // Pure generation only, no persistence on param changes
      return generate();
    },
    (value) => {
      setResult(value);
    },
  );

  // Load history when panel opens
  createEffect(
    () => showHistory(),
    (show) => {
      if (show) fetchHistory();
    },
  );

  async function handleCopy() {
    const val = result();
    await copyToClipboard(val);
    // Persist to history on copy (user's explicit action)
    // Avoid duplicate if already persisted (e.g. after regenerate)
    if (val !== lastPersisted()) {
      const params = currentParams();
      persistToHistory(val, mode() === MODE_PASSWORD ? "password" : "passphrase", params);
      setLastPersisted(val);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  async function handleHistoryCopy(val, id) {
    await copyToClipboard(val);
    setHistoryCopied(id);
    setTimeout(() => setHistoryCopied(null), 1800);
  }

  async function handleClearHistory() {
    if (!confirmClear()) {
      setConfirmClear(true);
      return;
    }
    setClearing(true);
    try {
      await daemon("generator.history_clear");
      setHistory([]);
    } catch {
      // best-effort
    }
    setClearing(false);
    setConfirmClear(false);
  }

  const TOGGLE_CLS = (active) =>
    `p-2 rounded-lg text-xs font-bold border cursor-pointer ${
      active
        ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]"
        : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"
    }`;

  return (
    <Transition name="fade">
      <Show when={props.showGenerator}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="generator-title"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => props.setShowGenerator(false)} />
          <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl max-w-sm w-full shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
            {/* Header */}
            <div class="p-6 pb-4 border-b border-[var(--color-border)] flex items-center justify-between shrink-0">
              <h3 id="generator-title" class="text-lg font-bold text-[var(--color-text)]">{t("generator.title")}</h3>
              <button onClick={() => props.setShowGenerator(false)} class="p-1 text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">✕</button>
            </div>

            {/* Mode tabs */}
            <div class="px-6 py-3 border-b border-[var(--color-border)] shrink-0 bg-[var(--color-sidebar)]/30 flex gap-2">
              <button
                onClick={() => setMode(MODE_PASSWORD)}
                class={`flex-1 py-1.5 text-xs font-bold rounded-lg transition-all text-center whitespace-nowrap cursor-pointer ${
                  mode() === MODE_PASSWORD
                    ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]"
                    : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)]/50"
                }`}
              >
                {t("generator.passwordTab")}
              </button>
              <button
                onClick={() => setMode(MODE_PASSPHRASE)}
                class={`flex-1 py-1.5 text-xs font-bold rounded-lg transition-all text-center whitespace-nowrap cursor-pointer ${
                  mode() === MODE_PASSPHRASE
                    ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]"
                    : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)]/50"
                }`}
              >
                {t("generator.passphraseTab")}
              </button>
            </div>

            {/* Generator body */}
            <div class="p-6 flex flex-col shrink-0">
              {/* Result display */}
              <div class="p-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] font-mono text-sm text-[var(--color-text)] text-center mb-4 select-all break-all min-h-[3rem] flex items-center justify-center">
                {result()}
              </div>

              {/* Password settings */}
              <Show when={mode() === MODE_PASSWORD}>
                <div class="space-y-3 mb-4">
                  <div class="flex items-center justify-between text-xs">
                    <span class="text-[var(--color-muted)]">{t("generator.length")}: <strong class="text-[var(--color-primary)]">{len()}</strong></span>
                    <input type="range" min="8" max="64" value={len()} onInput={e => setLen(parseInt(e.target.value))} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
                  </div>
                  <div class="grid grid-cols-3 gap-2">
                    <button onClick={() => setUseUpper(!useUpper())} class={TOGGLE_CLS(useUpper())}>A-Z</button>
                    <button onClick={() => setUseNums(!useNums())} class={TOGGLE_CLS(useNums())}>0-9</button>
                    <button onClick={() => setUseSyms(!useSyms())} class={TOGGLE_CLS(useSyms())}>!@#</button>
                  </div>
                </div>
              </Show>

              {/* Passphrase settings */}
              <Show when={mode() === MODE_PASSPHRASE}>
                <div class="space-y-3 mb-4">
                  <div class="flex items-center justify-between text-xs">
                    <span class="text-[var(--color-muted)]">{t("generator.words")}: <strong class="text-[var(--color-primary)]">{wordCount()}</strong></span>
                    <input type="range" min="3" max="12" value={wordCount()} onInput={e => setWordCount(parseInt(e.target.value))} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
                  </div>
                  <div class="flex items-center justify-between text-xs">
                    <span class="text-[var(--color-muted)]">{t("generator.separator")}</span>
                    <input
                      type="text"
                      value={separator()}
                      onInput={e => setSeparator(e.target.value)}
                      class="w-20 px-2 py-1 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-center text-[var(--color-text)] text-xs outline-none focus:border-[var(--color-primary)]"
                      autocomplete="off"
                      spellcheck="false"
                    />
                  </div>
                  <div class="grid grid-cols-3 gap-2">
                    <button onClick={() => setPpUpper(!ppUpper())} class={TOGGLE_CLS(ppUpper())}>Aa</button>
                    <button onClick={() => setPpNumber(!ppNumber())} class={TOGGLE_CLS(ppNumber())}>0-9</button>
                    <button onClick={() => setPpSymbol(!ppSymbol())} class={TOGGLE_CLS(ppSymbol())}>!@#</button>
                  </div>
                  <p class="text-[10px] text-[var(--color-muted)] leading-relaxed">
                    {t("generator.wordlistDesc")}
                  </p>
                </div>
              </Show>

              {/* Actions */}
              <div class="flex gap-2">
                <button onClick={handleRegenerate} class="flex-1 py-2.5 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-text)] text-xs font-bold cursor-pointer hover:border-[var(--color-primary)] transition-colors flex items-center justify-center gap-1.5">
                  <IconRefresh class="w-3.5 h-3.5" /> {t("generator.regenerate")}
                </button>
                <button onClick={handleCopy} class="flex-1 py-2.5 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold cursor-pointer flex items-center justify-center gap-1.5">
                  <Show when={copied()} fallback={<><IconCopy class="w-3.5 h-3.5" /> {t("generator.copy")}</>}>
                    <span class="copy-feedback"><IconCheck class="w-3.5 h-3.5" /></span> {t("generator.copied")}
                  </Show>
                </button>
              </div>

              {/* History toggle link */}
              <button
                onClick={() => setShowHistory(!showHistory())}
                class="mt-3 text-[10px] text-[var(--color-muted)] hover:text-[var(--color-primary)] transition-colors cursor-pointer text-center"
              >
                {t("generator.history")}
              </button>
            </div>

            {/* History panel */}
            <Show when={showHistory()}>
              <div class="border-t border-[var(--color-border)] flex flex-col min-h-0 overflow-hidden">
                <div class="overflow-y-auto flex-1 px-4 py-3 space-y-1.5" style="max-height: 40vh;">
                  <Show
                    when={history().length > 0}
                    fallback={
                      <p class="text-xs text-[var(--color-muted)] text-center py-6">{t("generator.historyEmpty")}</p>
                    }
                  >
                    <For each={history()}>
                      {(entry) => (
                        <div class="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] group">
                          {/* Kind badge */}
                          <span class={`shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded ${entry.kind === "passphrase" ? "bg-purple-500/20 text-purple-400" : "bg-blue-500/20 text-blue-400"}`}>
                            {entry.kind === "passphrase" ? t("generator.passphraseWord") : t("generator.passwordWord")}
                          </span>
                          {/* Value */}
                          <span class="flex-1 font-mono text-xs text-[var(--color-text)] truncate select-all" title={entry.value}>
                            {entry.value}
                          </span>
                          {/* Timestamp */}
                          <span class="text-[9px] text-[var(--color-muted)] shrink-0">{timeAgo(entry.created_at, t)}</span>
                          {/* Copy */}
                          <button
                            onClick={() => handleHistoryCopy(entry.value, entry.created_at)}
                            class="shrink-0 p-1 text-[var(--color-muted)] hover:text-[var(--color-primary)] cursor-pointer opacity-0 group-hover:opacity-100 transition-opacity"
                            title={t("generator.copy")}
                          >
                            <Show when={historyCopied() === entry.created_at} fallback={<IconCopy class="w-3 h-3" />}>
                              <IconCheck class="w-3 h-3 text-green-400" />
                            </Show>
                          </button>
                        </div>
                      )}
                    </For>
                  </Show>
                </div>
                {/* Clear button */}
                <Show when={history().length > 0}>
                  <div class="px-4 py-2 border-t border-[var(--color-border)]">
                    <Show when={confirmClear()} fallback={
                      <button
                        onClick={handleClearHistory}
                        class="w-full py-1.5 text-[10px] text-red-400 hover:text-red-300 cursor-pointer transition-colors"
                      >
                        {t("generator.historyClear")}
                      </button>
                    }>
                      <p class="text-[10px] text-[var(--color-muted)] text-center mb-2">{t("generator.historyClearConfirm")}</p>
                      <div class="flex gap-2">
                        <button
                          onClick={() => setConfirmClear(false)}
                          class="flex-1 py-1.5 text-[10px] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer transition-colors"
                        >{t("entry.cancel")}</button>
                        <button
                          onClick={handleClearHistory}
                          disabled={clearing()}
                          class="flex-1 py-1.5 text-[10px] text-red-400 hover:text-red-300 cursor-pointer transition-colors disabled:opacity-50"
                        >
                          {t("generator.historyClear")}
                        </button>
                      </div>
                    </Show>
                  </div>
                </Show>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
