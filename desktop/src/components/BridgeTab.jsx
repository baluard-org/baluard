// "Browser extensions" settings tab (Decision 8, approve-don't-type ceremony).
//
// Flow:
//   1. User clicks "Add browser extension" -> daemon bridge.pair_start (mints
//      a one-shot pending-approval handle). Returns request_id + browser_hint
//      + pair_code (audit C13).
//   2. The user opens the extension popup and types the displayed pair code;
//      the extension calls bridge.pair_complete with it. The daemon verifies
//      the code (wrong-code callers never supersede the real extension's
//      waiter) and holds the request pending until this UI Approves.
//   3. User clicks "Approve" -> bridge.pair_approve (consumes the one-shot
//      flag). The held pair_complete unblocks, mints the token, writes the
//      pairing file. The extension is now paired. The response carries no
//      secret (audit C13): the NMH reauths via the pairing file.
//   4. The list below shows all paired browsers; revoke per row.
//
// The trust anchors are the desktop session token (all routes here are
// desktop-token-gated) and the one-time pair code typed by the user.

import { createSignal, Show, For, onSettled } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import { IconSpinner } from "./Icon.jsx";
import { Button } from "./Primitives.jsx";

const BROWSER_LABELS = {
  chrome: "Chrome",
  chromium: "Chromium",
  firefox: "Firefox",
  edge: "Edge",
};

function browserLabel(b) {
  const k = String(b || "").toLowerCase();
  return BROWSER_LABELS[k] || b || "Browser";
}

export default function BridgeTab() {
  const { t } = useI18n();

  const [pairings, setPairings] = createSignal([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal(null);

  // Pending pairing ceremony state.
  const [pending, setPending] = createSignal(null); // {request_id, browser_hint, ttl_seconds, pair_code}
  const [pairBusy, setPairBusy] = createSignal(false);
  // Poll the daemon for the pending request while one is active. The
  // extension's pair_complete arrives asynchronously; we reflect it here.
  let pollTimer = null;

  async function loadPairings() {
    setLoading(true);
    setError(null);
    try {
      const data = JSON.parse(await daemon("bridge.list"));
      setPairings(data.pairings || []);
    } catch (e) {
      setError(sanitizeError(e));
    } finally {
      setLoading(false);
    }
  }

  async function startPair() {
    setPairBusy(true);
    setError(null);
    try {
      // The browser hint is unknown until the extension calls pair_complete;
      // pair_start creates the pending slot the extension will attach to.
      const data = JSON.parse(await daemon("bridge.pair_start", JSON.stringify({ browser: "unknown" })));
      // pair_start does not return started_at; stamp it client-side so the
      // TTL poll below can compute elapsed time.
      data.started_at = Date.now() / 1000;
      setPending(data);
      // Begin polling: the pending slot may be superseded or the extension
      // may attach. We refresh pending state every 2s until TTL or approval.
      startPoll();
    } catch (e) {
      setError(sanitizeError(e));
      toastError(t("bridge.pairStartFailed"));
    } finally {
      setPairBusy(false);
    }
  }

  // Extension-connected signal: flips true when the extension's
  // pair_complete arrives (daemon waiter registered). Drives the UI from
  // "Waiting for extension" to "Extension connected — approve now".
  const [extConnected, setExtConnected] = createSignal(false);

  function startPoll() {
    stopPoll();
    pollTimer = setInterval(async () => {
      // TTL guard: abandon the ceremony if pair_start's window elapsed.
      if (pending() && Date.now() / 1000 - (pending().started_at || 0) > (pending().ttl_seconds || 120)) {
        cancelPending();
        return;
      }
      // Peek the daemon: has the extension connected?
      try {
        const data = JSON.parse(await daemon("bridge.pending"));
        setExtConnected(Boolean(data.extension_connected));
      } catch {
        /* daemon busy / locked — keep last known state */
      }
    }, 1000);
  }

  function stopPoll() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
  }

  function cancelPending() {
    stopPoll();
    setPending(null);
    setExtConnected(false);
  }

  async function approve() {
    if (!pending()) return;
    setPairBusy(true);
    try {
      await daemon("bridge.pair_approve", JSON.stringify({ request_id: pending().request_id }));
      // The extension's held pair_complete unblocks here. Give it a moment,
      // then refresh the list.
      setTimeout(loadPairings, 500);
      toastSuccess(t("bridge.approved"));
      cancelPending();
    } catch (e) {
      setError(sanitizeError(e));
      toastError(t("bridge.approveFailed"));
    } finally {
      setPairBusy(false);
    }
  }

  async function revoke(id) {
    try {
      await daemon("bridge.revoke", JSON.stringify({ pairing_id: id }));
      toastSuccess(t("bridge.revoked"));
      loadPairings();
    } catch (e) {
      toastError(sanitizeError(e));
    }
  }

  onSettled(() => {
    void loadPairings();
    return stopPoll;
  });

  return (
    <div class="space-y-5">
      <div>
        <h3 class="text-sm font-bold mb-1">{t("bridge.title")}</h3>
        <p class="text-xs text-[var(--color-muted)]">{t("bridge.description")}</p>
      </div>

      <Show when={pending()}>
        <div class={`p-4 rounded-lg border space-y-3 ${extConnected() ? "border-[var(--color-primary)] bg-[var(--color-primary)]/5" : "border-[var(--color-border)] bg-[var(--color-surface)]"}`}>
          <Show when={extConnected()} fallback={<div class="text-sm font-semibold">{t("bridge.waitingForExtension")}</div>}>
            <div class="text-sm font-semibold text-[var(--color-primary)]">{t("bridge.extensionConnected")}</div>
            <div class="text-xs text-[var(--color-muted)]">{t("bridge.extensionConnectedHint")}</div>
          </Show>
          <Show when={!extConnected()}>
            <div class="text-xs text-[var(--color-muted)]">{t("bridge.waitingHint")}</div>
          </Show>
          <Show when={pending()?.pair_code}>
            <div class="flex flex-col items-center gap-1 py-2 px-3 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-bg)]">
              <div class="text-[10px] font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("bridge.pairCodeLabel")}</div>
              <div class="font-mono text-xl font-bold tracking-[0.3em] text-[var(--color-text)] select-all">{pending().pair_code}</div>
              <div class="text-[10px] text-[var(--color-muted)]">{t("bridge.pairCodeHint")}</div>
            </div>
          </Show>
          <div class="flex gap-2">
            <Button onClick={approve} disabled={pairBusy()}>
              <Show when={pairBusy()} fallback={t("bridge.approve")}>
                <IconSpinner /> {t("common.processing")}
              </Show>
            </Button>
            <Button onClick={cancelPending} variant="ghost">
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      </Show>

      <Show when={!pending()}>
        <Button onClick={startPair} disabled={pairBusy()}>
          <Show when={pairBusy()} fallback={t("bridge.add")}>
            <IconSpinner /> {t("common.processing")}
          </Show>
        </Button>
      </Show>

      <Show when={error()}>
        <div class="text-xs text-red-500">{error()}</div>
      </Show>

      <div class="space-y-2">
        <Show when={loading()}>
          <div class="text-xs text-[var(--color-muted)]">{t("common.loading")}</div>
        </Show>
        <Show when={!loading() && pairings().length === 0}>
          <div class="text-xs text-[var(--color-muted)]">{t("bridge.nonePaired")}</div>
        </Show>
        <For each={pairings()}>
          {(p) => (
            <div class="flex items-center justify-between p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)]">
              <div>
                <div class="text-sm font-medium">{p.name || browserLabel(p.browser)}</div>
                <div class="text-xs text-[var(--color-muted)]">
                  {browserLabel(p.browser)} · {t("bridge.pairedOn")} {new Date((p.created_at || 0) * 1000).toLocaleDateString()}
                </div>
              </div>
              <Button onClick={() => revoke(p.pairing_id)} variant="ghost" class="text-red-500">
                {t("bridge.revoke")}
              </Button>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
