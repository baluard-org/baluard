import { createSignal, createEffect, Show } from "solid-js";
import { Transition } from "solid-transition-group";
import { useI18n } from "../i18n/index.jsx";
import { generateSecurePassword, generatePassphrase } from "../lib/utils.js";
import { IconCopy, IconCheck, IconRefresh } from "./Icon.jsx";

const MODE_PASSWORD = "password";
const MODE_PASSPHRASE = "passphrase";

export default function GeneratorModal(props) {
  const { t } = useI18n();
  const [mode, setMode] = createSignal(MODE_PASSWORD);
  const [copied, setCopied] = createSignal(false);

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

  function regenerate() {
    if (mode() === MODE_PASSWORD) {
      setResult(generateSecurePassword(len(), useUpper(), useNums(), useSyms()));
    } else {
      setResult(generatePassphrase(wordCount(), separator(), {
        upper: ppUpper(),
        number: ppNumber(),
        symbol: ppSymbol(),
      }));
    }
  }

  createEffect(() => {
    mode(); len(); useUpper(); useNums(); useSyms();
    wordCount(); separator(); ppUpper(); ppNumber(); ppSymbol();
    regenerate();
  });

  function handleCopy() {
    navigator.clipboard.writeText(result());
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
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
        <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl max-w-sm w-full shadow-2xl overflow-hidden flex flex-col">
            {/* Header */}
            <div class="p-6 pb-4 border-b border-[var(--color-border)] flex items-center justify-between shrink-0">
              <h3 class="text-lg font-bold text-[var(--color-text)]">{t("generator.title")}</h3>
              <button onClick={() => props.setShowGenerator(false)} class="p-1 text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">✕</button>
            </div>

            {/* Mode tabs */}
            <div class="px-6 flex gap-4 border-b border-[var(--color-border)] shrink-0 bg-[var(--color-sidebar)]/30">
              <button
                onClick={() => setMode(MODE_PASSWORD)}
                class={`py-3 text-xs font-bold transition-all relative cursor-pointer ${mode() === MODE_PASSWORD ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)]"}`}
              >
                {t("generator.passwordTab")}
                <Show when={mode() === MODE_PASSWORD}>
                   <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-primary)] rounded-full"></div>
                </Show>
              </button>
              <button
                onClick={() => setMode(MODE_PASSPHRASE)}
                class={`py-3 text-xs font-bold transition-all relative cursor-pointer ${mode() === MODE_PASSPHRASE ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)]"}`}
              >
                {t("generator.passphraseTab")}
                <Show when={mode() === MODE_PASSPHRASE}>
                   <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-primary)] rounded-full"></div>
                </Show>
              </button>
            </div>

            {/* Modal Body */}
            <div class="p-6 flex flex-col">
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
                <button onClick={regenerate} class="flex-1 py-2.5 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-text)] text-xs font-bold cursor-pointer hover:border-[var(--color-primary)] transition-colors flex items-center justify-center gap-1.5">
                  <IconRefresh class="w-3.5 h-3.5" /> {t("generator.regenerate")}
                </button>
                <button onClick={handleCopy} class="flex-1 py-2.5 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold cursor-pointer flex items-center justify-center gap-1.5">
                  <Show when={copied()} fallback={<><IconCopy class="w-3.5 h-3.5" /> {t("generator.copy")}</>}>
                    <span class="copy-feedback"><IconCheck class="w-3.5 h-3.5" /></span> {t("generator.copied")}
                  </Show>
                </button>
              </div>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
