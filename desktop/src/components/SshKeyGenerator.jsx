import { createSignal, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import CopyButton from "./CopyButton.jsx";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { sanitizeError } from "../lib/utils.js";
import { IconKey, IconRefresh, IconSpinner } from "./Icon.jsx";

const COPY_BTN = "p-1.5 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer shrink-0";

export default function SshKeyGenerator(props) {
  const { t } = useI18n();
  const [keyType, setKeyType] = createSignal("ed25519");
  const [generating, setGenerating] = createSignal(false);

  async function handleGenerate() {
    setGenerating(true);
    try {
      const result = JSON.parse(await daemon("ssh.generate_key", JSON.stringify({ type: keyType() })));
      props.onGenerated?.({
        publicKey: result.public_key,
        privateKey: result.private_key,
        fingerprint: result.fingerprint,
      });
      toastSuccess(t("entry.sshKeyGenerated"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setGenerating(false);
    }
  }

  // L7 fix: RSA 4096 removed. The rsa crate has RUSTSEC-2023-0071
  // (Marvin Attack, no fix). Ed25519 (recommended) and ECDSA P-256 cover
  // modern needs.
  const TYPES = [
    { id: "ed25519", label: t("entry.sshKeyEd25519"), recommended: true },
    { id: "ecdsa256", label: t("entry.sshKeyEcdsa256") },
  ];

  return (
    <div class="space-y-3">
      <div class="flex items-center justify-between">
        <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("entry.sshKeyType")}</label>
      </div>
      <div class="flex gap-2">
        <For each={TYPES}>
          {tp => (
            <button
              onClick={() => setKeyType(tp.id)}
              class={`flex-1 py-2 px-3 rounded-xl text-xs font-bold border transition-all cursor-pointer relative ${keyType() === tp.id ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
            >
              {tp.label}
              <Show when={tp.recommended}>
                <span class="ml-1.5 px-1.5 py-0.5 rounded-md text-[9px] font-bold bg-white/20 uppercase tracking-wider">{t("common.default")}</span>
              </Show>
            </button>
          )}
        </For>
      </div>
      <button
        onClick={handleGenerate}
        disabled={generating()}
        class="w-full py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-sm flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <Show when={generating()} fallback={<IconRefresh class="w-3.5 h-3.5" />}>
          <IconSpinner class="w-3.5 h-3.5" />
        </Show>
        {generating() ? t("entry.sshKeyGenerating") : t("entry.sshGenerateKey")}
      </button>

      {/* Fingerprint */}
      <Show when={props.fingerprint}>
        <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
          <div class="flex items-center justify-between mb-1">
            <span class="text-[10px] font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("fields.fingerprint")}</span>
            <CopyButton class={COPY_BTN} value={props.fingerprint} title={t("entry.sshKeyCopyFingerprint")} />
          </div>
          <code class="text-xs text-[var(--color-primary)] font-mono break-all">{props.fingerprint}</code>
        </div>
      </Show>

      {/* Public Key */}
      <Show when={props.publicKey}>
        <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
          <div class="flex items-center justify-between mb-1">
            <span class="text-[10px] font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("fields.publicKey")}</span>
            <CopyButton class={COPY_BTN} value={props.publicKey} title={t("entry.sshKeyCopyPublic")} />
          </div>
          <pre class="text-xs text-[var(--color-text)] font-mono break-all whitespace-pre-wrap max-h-32 overflow-y-auto">{props.publicKey}</pre>
        </div>
      </Show>

      {/* Private Key (warning) */}
      <Show when={props.privateKey}>
        <div class="p-3 rounded-xl bg-red-950/20 border border-red-900/30">
          <div class="flex items-center justify-between mb-1">
            <span class="text-[10px] font-bold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
              {t("fields.privateKey")}
            </span>
            <CopyButton class={COPY_BTN} value={props.privateKey} title={t("entry.sshKeyCopyPrivate")} />
          </div>
          <details class="text-xs text-[var(--color-muted)]">
            <summary class="cursor-pointer hover:text-[var(--color-text)] transition-colors">{t("entry.sshShowPrivate")}</summary>
            <pre class="mt-2 text-xs text-[var(--color-text)] font-mono break-all whitespace-pre-wrap max-h-48 overflow-y-auto bg-[var(--color-bg)] p-2 rounded-lg">{props.privateKey}</pre>
          </details>
        </div>
      </Show>
    </div>
  );
}
