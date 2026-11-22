import { Show, For, createSignal, createEffect } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { toastSuccess } from "../context/toastSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { copyToClipboard } from "../lib/clipboard.js";
import { Button } from "./Primitives.jsx";

// Vault diagnostics: the per-device sync state a support report needs.
// Read-only snapshot from sync.diagnostics; the copy button exports the
// daemon-composed report (redacted by construction in the runtime —
// host-only remote, no entry names, sanitized commit subjects).
const VERDICT_KEY = {
  up_to_date: "diag.verdict.upToDate",
  behind: "diag.verdict.behind",
  local_pending: "diag.verdict.localPending",
  failing: "diag.verdict.failing",
  no_remote: "diag.verdict.noRemote",
  unfetched: "diag.verdict.unfetched",
  needs_decision: "diag.verdict.needsDecision",
};

const VERDICT_CLASS = {
  up_to_date: "text-emerald-400",
  behind: "text-amber-400",
  local_pending: "text-amber-400",
  failing: "text-red-400",
  no_remote: "text-[var(--color-muted)]",
  unfetched: "text-amber-400",
  needs_decision: "text-amber-400",
};

export default function VaultDiagnostics() {
  const { t } = useI18n();
  const switcher = useVaultSwitcher();
  const slug = () => switcher.activeSlug();

  const [snap, setSnap] = createSignal(null);
  const [err, setErr] = createSignal(null);
  const [loading, setLoading] = createSignal(false);

  // Stale-response guard: only the latest request may land, so a slug
  // switch can never leave the other vault's report on screen.
  let seq = 0;
  const load = async (s) => {
    const mine = ++seq;
    setSnap(null);
    setErr(null);
    if (!s) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const raw = await daemon("sync.diagnostics", "", s);
      if (mine !== seq) return;
      setSnap(JSON.parse(raw));
    } catch {
      if (mine !== seq) return;
      setErr(t("diag.error"));
    } finally {
      if (mine === seq) setLoading(false);
    }
  };
  createEffect(
    () => slug(),
    (s) => void load(s),
  );
  const refetch = () => void load(slug());

  const [copied, setCopied] = createSignal(false);
  const copyReport = async () => {
    const s = snap();
    if (!s?.report) return;
    try {
      await copyToClipboard(s.report, { autoClearMs: 0 });
      setCopied(true);
      toastSuccess(t("diag.copied"));
      setTimeout(() => setCopied(false), 3000);
    } catch {
      // Clipboard denied: leave the report on screen, no toast.
    }
  };

  const fmtTime = (secs) => {
    if (!secs) return t("diag.never");
    const d = new Date(secs * 1000);
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  };

  const agoStr = (secs, now) => {
    const d = Math.max(0, Math.floor(now / 1000) - secs);
    if (d < 90) return t("diag.agoSecs", { n: d });
    if (d < 5400) return t("diag.agoMins", { n: Math.floor(d / 60) });
    if (d < 129600) return t("diag.agoHours", { n: Math.floor(d / 3600) });
    return t("diag.agoDays", { n: Math.floor(d / 86400) });
  };

  const rows = () => {
    const s = snap();
    if (!s) return [];
    const now = Date.now();
    const out = [];
    out.push([t("diag.deviceId"), s.deviceId ? s.deviceId.slice(0, 7) : t("diag.never")]);
    if (s.hasRemote) {
      out.push([t("diag.head"), s.headOid ? s.headOid.slice(0, 7) : t("diag.never")]);
      const neverFetched = s.upstreamOid == null;
      const parts = [];
      if (s.behind > 0) parts.push(t("diag.behindCount", { n: s.behind }));
      if (s.ahead > 0) parts.push(t("diag.aheadCount", { n: s.ahead }));
      out.push([
        t("diag.remoteState"),
        neverFetched ? t("diag.never") : parts.join(" / ") || t("diag.inSync"),
      ]);
      if (s.upstreamAt) {
        out.push([t("diag.upstream"), agoStr(s.upstreamAt, now)]);
      }
    } else {
      out.push([t("diag.remote"), t("diag.noneConfigured")]);
    }
    const lastSync = s.autosync?.last_sync;
    out.push([
      t("diag.lastSync"),
      lastSync ? `${agoStr(lastSync, now)} (${fmtTime(lastSync)})` : t("diag.never"),
    ]);
    out.push([
      t("diag.autosync"),
      s.autosync?.active ? t("diag.on") : t("diag.off"),
    ]);
    if (s.autosync?.access_denied_streak > 0) {
      out.push([t("diag.rejections"), String(s.autosync.access_denied_streak)]);
    }
    if (s.autosync?.conflicts_resolved > 0) {
      out.push([t("diag.conflicts"), String(s.autosync.conflicts_resolved)]);
    }
    if (s.staged + s.unstaged > 0) {
      out.push([t("diag.localChanges"), String(s.staged + s.unstaged)]);
    }
    if (s.entries != null) {
      out.push([t("diag.entries"), String(s.entries)]);
    }
    if (s.archived > 0) out.push([t("diag.archived"), String(s.archived)]);
    if (s.trashed > 0) out.push([t("diag.trashed"), String(s.trashed)]);
    return out;
  };

  return (
    <Show when={slug()}>
      <div class="border border-[var(--color-border)] rounded-xl p-4 space-y-3">
        <div class="flex items-center justify-between">
          <h3 class="text-sm font-semibold text-[var(--color-text)]">{t("diag.title")}</h3>
          <Button onClick={() => void refetch()} disabled={loading()} class="px-2 py-1 text-xs">
            {t("diag.refresh")}
          </Button>
        </div>
        <Show when={err()}>
          <p class="text-xs text-red-400">{err()}</p>
        </Show>
        <Show when={!err() && loading()}>
          <p class="text-xs text-[var(--color-muted)]">{t("diag.loading")}</p>
        </Show>
        <Show when={snap()}>
          <div
            class={`text-sm font-semibold ${VERDICT_CLASS[snap().verdict] || "text-[var(--color-text)]"}`}
          >
            {t(VERDICT_KEY[snap().verdict] || "diag.verdict.unknown")}
          </div>
          <div class="divide-y divide-[var(--color-border)]">
            <For each={rows()}>
              {([label, value]) => (
                <div class="flex items-center justify-between py-1.5 text-xs">
                  <span class="text-[var(--color-muted)]">{label}</span>
                  <span class="text-[var(--color-text)] font-medium" title={value}>
                    {value}
                  </span>
                </div>
              )}
            </For>
          </div>
          <Button onClick={() => void copyReport()} class="w-full py-2 text-xs">
            {copied() ? t("diag.copied") : t("diag.copy")}
          </Button>
          <p class="text-[10px] text-[var(--color-muted)] leading-relaxed">
            {t("diag.privacyNote")}
          </p>
        </Show>
      </div>
    </Show>
  );
}
