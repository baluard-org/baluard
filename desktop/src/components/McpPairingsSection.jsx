import { Show, For, createSignal, onSettled } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { copyToClipboard } from "../lib/clipboard.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import ConfirmModal from "./ConfirmModal.jsx";
import { Toggle } from "./Primitives.jsx";

const LADDER_SECONDS = [
  { secs: 300, mins: 5 },
  { secs: 900, mins: 15 },
  { secs: 1800, mins: 30 },
  { secs: 3600, mins: 60 },
];

const DURATION_DEFAULT = 300;

export default function McpPairingsSection() {
  const { t } = useI18n();
  const [status, setStatus] = createSignal(null);
  const [pairName, setPairName] = createSignal("");
  const [newPairing, setNewPairing] = createSignal(null);
  const [busy, setBusy] = createSignal(false);
  const [confirmPairingId, setConfirmPairingId] = createSignal(null);
  const [durations, setDurations] = createSignal({});
  const [copied, setCopied] = createSignal("");
  let loadTimer;

  async function load() {
    try {
      const data = await daemon("mcp.status").then(JSON.parse);
      setStatus(data);
    } catch {
      // Locked vault or daemon shutdown: the next refresh retries.
    }
  }

  onSettled(() => {
    load();
    loadTimer = setInterval(load, 4000);
    return () => clearInterval(loadTimer);
  });

  async function pair() {
    const name = pairName().trim();
    if (!name || busy()) return;
    setBusy(true);
    try {
      const data = await daemon("mcp.pair", { name }).then(JSON.parse);
      const port = status()?.server?.port;
      setNewPairing({
        ...data,
        snippet: buildSnippet(data.token, port),
      });
      setPairName("");
      toastSuccess(t("mcp.paired"));
      load();
    } catch (e) {
      toastError(e.message);
    } finally {
      setBusy(false);
    }
  }

  function buildSnippet(token, port) {
    // User-global config shape (MCP "HTTP with headers"). Never a
    // project-scoped .mcp.json: the token inherits the file's permissions.
    return JSON.stringify(
      {
        mcpServers: {
          baluard: {
            url: `http://127.0.0.1:${port || 17990}/mcp`,
            headers: { Authorization: `Bearer ${token}` },
          },
        },
      },
      null,
      2,
    );
  }

  async function revoke(pairingId) {
    try {
      await daemon("mcp.revoke", { pairing_id: pairingId });
      toastSuccess(t("mcp.revoked"));
      load();
    } catch (e) {
      toastError(e.message);
    }
  }

  function enableYolo(pairingId) {
    setConfirmPairingId(null);
    window.__baluardReprompt?.show((password) => {
      yoloSet(pairingId, true, password).catch(() => {});
    });
  }

  async function yoloSet(pairingId, enabled, masterPassword = null) {
    const durationSecs = durations()[pairingId] ?? DURATION_DEFAULT;
    try {
      await daemon("mcp.yolo_set", {
        pairing_id: pairingId,
        enabled,
        duration_secs: enabled ? durationSecs : undefined,
        ...(enabled ? { master_password: masterPassword } : {}),
      });
      toastSuccess(t(enabled ? "mcp.yoloEnabled" : "mcp.yoloDisabled"));
      load();
    } catch (e) {
      toastError(e.message);
      throw e;
    }
  }

  async function copy(text, key) {
    try {
      await copyToClipboard(text, { autoClearMs: 0 });
      setCopied(key);
      setTimeout(() => setCopied(""), 2000);
    } catch (e) {
      toastError(e.message);
    }
  }

  const server = () => status()?.server;
  const pairings = () => status()?.pairings || [];

  return (
    <section class="space-y-3 border-t border-[var(--color-border)] pt-4" data-testid="mcp-settings">
      <div>
        <h3 class="text-sm font-semibold text-[var(--color-text)]">{t("mcp.title")}</h3>
        <p class="text-xs text-[var(--color-muted)] mt-1">{t("mcp.desc")}</p>
      </div>

      <Show
        when={server()?.running}
        fallback={
          <div class="text-xs text-[var(--color-danger-strong)]" data-testid="mcp-server-error">
            {t("mcp.serverError", { error: server()?.error || "" })}
          </div>
        }
      >
        <div class="text-xs text-[var(--color-muted)]" data-testid="mcp-server-status">
          {t("mcp.serverRunning", { port: server()?.port })}
        </div>
      </Show>

      <div class="flex gap-2">
        <input
          data-testid="mcp-pair-name"
          class="flex-1 rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)]"
          placeholder={t("mcp.pairNamePlaceholder")}
          maxLength="80"
          value={pairName()}
          onInput={(e) => setPairName(e.currentTarget.value)}
          onKeyDown={(e) => e.key === "Enter" && pair()}
        />
        <button
          data-testid="mcp-pair"
          class={["rounded px-3 py-2 text-xs font-semibold uppercase", { "opacity-50": busy() || !pairName().trim() }]}
          disabled={busy() || !pairName().trim()}
          onClick={pair}
        >
          {t("mcp.pair")}
        </button>
      </div>

      <Show when={newPairing()}>
        <div class="space-y-2 rounded border border-[var(--color-border)] p-3" data-testid="mcp-new-pairing">
          <div class="text-xs font-semibold">{t("mcp.tokenTitle", { name: newPairing().pairing.name })}</div>
          <div class="flex items-start gap-2">
            <code class="flex-1 break-all rounded bg-[var(--color-bg)] p-2 text-[10px] font-mono">
              {newPairing().token}
            </code>
            <button
              data-testid="mcp-copy-token"
              class="rounded px-2 py-1 text-[10px] uppercase"
              onClick={() => copy(newPairing().token, "token")}
            >
              {copied() === "token" ? t("mcp.copied") : t("mcp.copy")}
            </button>
          </div>
          <div class="text-[10px] text-[var(--color-muted)]">{t("mcp.tokenNote")}</div>
          <div class="text-xs font-semibold mt-2">{t("mcp.snippetTitle")}</div>
          <div class="flex items-start gap-2">
            <pre class="flex-1 overflow-x-auto rounded bg-[var(--color-bg)] p-2 text-[10px] font-mono" data-testid="mcp-snippet">
              {newPairing().snippet}
            </pre>
            <button
              data-testid="mcp-copy-snippet"
              class="rounded px-2 py-1 text-[10px] uppercase"
              onClick={() => copy(newPairing().snippet, "snippet")}
            >
              {copied() === "snippet" ? t("mcp.copied") : t("mcp.copy")}
            </button>
          </div>
          <div class="text-[10px] text-[var(--color-muted)]">{t("mcp.snippetNote")}</div>
          <button class="text-[10px] uppercase text-[var(--color-muted)]" onClick={() => setNewPairing(null)}>
            {t("mcp.dismiss")}
          </button>
        </div>
      </Show>

      <Show when={pairings().length > 0}>
        <div class="space-y-2">
          <div class="text-xs font-semibold">{t("mcp.pairings")}</div>
          <For each={pairings()}>
            {(row) => (
              <div class="rounded border border-[var(--color-border)] p-2 space-y-2" data-testid="mcp-pairing-row">
                <div class="flex items-center justify-between gap-2">
                  <div>
                    <div class="text-xs font-semibold">{row.name}</div>
                    <div class="text-[10px] text-[var(--color-muted)]">
                      <Show when={row.yolo_expires_in_secs} fallback={null}>
                        {t("mcp.expiresIn", { n: Math.max(1, Math.round(row.yolo_expires_in_secs / 60)) })} ·{" "}
                      </Show>
                      {t("mcp.pairedAt", { date: new Date(row.created_at_ms).toLocaleString() })}
                    </div>
                  </div>
                  <button
                    data-testid="mcp-revoke"
                    class="rounded px-2 py-1 text-[10px] uppercase"
                    onClick={() => revoke(row.id)}
                  >
                    {t("mcp.revoke")}
                  </button>
                </div>
                <div class="flex items-center gap-2">
                  <select
                    data-testid="mcp-duration"
                    class="rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-xs text-[var(--color-text)]"
                    value={durations()[row.id] ?? DURATION_DEFAULT}
                    onInput={(e) =>
                      setDurations((map) => ({ ...map, [row.id]: Number(e.currentTarget.value) }))
                    }
                  >
                    <For each={LADDER_SECONDS}>
                      {(opt) => <option value={opt.secs}>{t("mcp.durationMinutes", { n: opt.mins })}</option>}
                    </For>
                  </select>
                  <Toggle
                    data-testid={`mcp-yolo-${row.id}`}
                    label={t("mcp.autoApprove")}
                    checked={Boolean(row.yolo_expires_in_secs)}
                    onChange={(e) => {
                      const wants = e.currentTarget.checked;
                      e.currentTarget.checked = Boolean(row.yolo_expires_in_secs);
                      if (wants) setConfirmPairingId(row.id);
                      else yoloSet(row.id, false).catch(() => {});
                    }}
                  />
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>
      <Show when={pairings().length === 0}>
        <div class="text-xs text-[var(--color-muted)]">{t("mcp.noPairings")}</div>
      </Show>

      <ConfirmModal
        show={Boolean(confirmPairingId())}
        idPrefix="mcp-yolo-warning"
        title={t("mcp.autoApprove")}
        body={t("mcp.autoApproveWarning")}
        confirmLabel={t("mcp.autoApprove")}
        onConfirm={() => enableYolo(confirmPairingId())}
        onClose={() => setConfirmPairingId(null)}
      />
    </section>
  );
}
