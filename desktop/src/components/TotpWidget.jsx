import { createSignal, createEffect, Show } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { copyToClipboard } from "../lib/clipboard.js";
import { useI18n } from "../i18n/index.jsx";
import { IconCopy, IconCheck, IconRefresh } from "./Icon.jsx";

/** The seed wherever the caller's shape carries it: the daemon flattens it
 * to top-level `totp`, the edit form keeps `totp_uri`, and the nested kind
 * JSON holds `kind.data.totp_uri`. */
export function totpSeedOf(c) {
  for (const uri of [c?.totp, c?.totp_uri, c?.kind?.data?.totp_uri]) {
    if (typeof uri === "string" && uri.trim().length > 0) return uri;
  }
  return null;
}

/** Live TOTP card: code, countdown, depleting bar, copy. Mirrors the mobile
 * TotpWidget. Fetch failures render an error with a retry instead of
 * vanishing, so a broken code path is visible instead of silent. */
export default function TotpWidget(props) {
  const { t } = useI18n();
  const [status, setStatus] = createSignal("loading");
  const [code, setCode] = createSignal(null);
  const [period, setPeriod] = createSignal(30);
  const [expiresAt, setExpiresAt] = createSignal(0);
  const [copied, setCopied] = createSignal(false);
  const [now, setNow] = createSignal(Date.now());
  const [retryNonce, setRetryNonce] = createSignal(0);

  const remaining = () => Math.max(0, expiresAt() - Math.floor(now() / 1000));
  const pct = () => (period() > 0 ? Math.min(100, (remaining() / period()) * 100) : 0);

  createEffect(
    () => {
      const c = props.cipher;
      return c?.id && totpSeedOf(c) ? `${c.id}:${retryNonce()}` : null;
    },
    () => {
      const id = props.cipher?.id;
      if (!id) return;
      let active = true;
      let timer = null;
      let tick = setInterval(() => setNow(Date.now()), 1000);
      setStatus("loading");
      setCode(null);

      const fetchCode = async () => {
        if (!active) return;
        try {
          const data = JSON.parse(await daemon("cipher.totp_code", id, props.cipher?._vault?.slug || null));
          if (!active) return;
          setCode(data.code || "");
          setPeriod(data.period_seconds || 30);
          setExpiresAt(data.expires_at || 0);
          setNow(Date.now());
          setStatus("ready");
          if (!tick) tick = setInterval(() => setNow(Date.now()), 1000);
          const msLeft = data.expires_at ? data.expires_at * 1000 - Date.now() : 30000;
          timer = setTimeout(fetchCode, Math.max(200, msLeft + 200));
        } catch (e) {
          if (!active) return;
          console.warn("[totp] code fetch failed", e);
          setStatus("error");
          // A transient daemon hiccup must not strand the card until a
          // manual retry: try again shortly, and stop the countdown tick.
          clearInterval(tick);
          tick = null;
          timer = setTimeout(fetchCode, 5000);
        }
      };
      fetchCode();
      return () => {
        active = false;
        if (timer) clearTimeout(timer);
        if (tick) clearInterval(tick);
      };
    },
  );

  async function copy() {
    await copyToClipboard(code() || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
      <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block mb-2">
        {t("fields.verificationCode")}
      </label>
      <Show when={status() === "ready"}>
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="text-2xl font-mono font-bold tracking-[0.3em] text-[var(--color-text)] select-all">
              {code()?.match(/.{1,3}/g)?.join(" ") || code()}
            </span>
            <button
              data-testid="totp-copy"
              onClick={copy}
              class="p-1.5 rounded-lg text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
              title={t("entry.copyCode")}
            >
              <Show when={!copied()} fallback={<span class="copy-feedback"><IconCheck class="w-4 h-4 text-[var(--color-success)]" /></span>}>
                <IconCopy class="w-4 h-4" />
              </Show>
            </button>
          </div>
          <span data-testid="totp-seconds" class="text-[10px] text-[var(--color-muted)]">{remaining()}s</span>
        </div>
        <div class="mt-2 h-1 rounded-full bg-[var(--color-border)] overflow-hidden">
          <div data-testid="totp-bar" class="h-full rounded-full bg-[var(--color-accent)] transition-[width] duration-1000" style={{ width: `${pct()}%` }} />
        </div>
      </Show>
      <Show when={status() === "loading"}>
        <span class="text-xs text-[var(--color-muted)] animate-pulse">…</span>
      </Show>
      <Show when={status() === "error"}>
        <div class="flex items-center justify-between">
          <span class="text-xs text-[var(--color-muted)]">{t("entry.totpUnavailable")}</span>
          <button
            data-testid="totp-retry"
            onClick={() => setRetryNonce((n) => n + 1)}
            class="p-1.5 rounded-lg text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
            title={t("entry.retry")}
          >
            <IconRefresh class="w-4 h-4" />
          </button>
        </div>
      </Show>
    </div>
  );
}
