import { Show, For, createSignal, createEffect } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess } from "../context/toastSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { copyToClipboard } from "../lib/clipboard.js";
import { Button } from "./Primitives.jsx";

// Vault diagnostics: the per-device sync state a support report needs.
// Read-only snapshot from sync.diagnostics; the copy button exports the
// daemon-composed report (redacted by construction in the runtime —
// host-only remote, no entry names, static commit messages).
const VERDICT_KEY = {
  up_to_date: "diag.verdict.upToDate",
  behind: "diag.verdict.behind",
  local_pending: "diag.verdict.localPending",
  failing: "diag.verdict.failing",
  no_remote: "diag.verdict.noRemote",
  unfetched: "diag.verdict.unfetched",
  needs_decision: "diag.verdict.needsDecision",
  locked: "diag.verdict.locked",
};

const VERDICT_CLASS = {
  up_to_date: "text-emerald-400",
  behind: "text-amber-400",
  local_pending: "text-amber-400",
  failing: "text-red-400",
  no_remote: "text-[var(--color-muted)]",
  unfetched: "text-amber-400",
  needs_decision: "text-amber-400",
  locked: "text-[var(--color-muted)]",
};

export default function VaultDiagnostics() {
  const { t } = useI18n();
  const switcher = useVaultSwitcher();
  const slug = () => switcher.activeSlug();

  const [snap, setSnap] = createSignal(null);
  const [err, setErr] = createSignal(null);

  const load = async (s) => {
    if (!s) {
      setSnap(null);
      return;
    }
    try {
      const raw = await daemon("sync.diagnostics", s);
      setSnap(JSON.parse(raw));
      setErr(null);
    } catch (e) {
      setSnap(null);
      setErr(sanitizeError(e));
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
    await copyToClipboard(s.report, { autoClearMs: 0 });
    setCopied(true);
    toastSuccess(t("diag.copied"));
    setTimeout(() => setCopied(false), 3000);
  };

  const fmtTime = (secs) => {
    if (!secs) return t("diag.never");
    const d = new Date(secs * 1000);
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  };

  const rows = () => {
    const s = snap();
    if (!s) return [];
    const out = [];
    if (s.hasRemote) {
      out.push([t("diag.head"), s.headOid ? s.headOid.slice(0, 7) : t("diag.never")]);
      out.push([
        t("diag.remoteState"),
        s.behind > 0
          ? t("diag.behindCount", { n: s.behind })
          : s.ahead > 0
            ? t("diag.aheadCount", { n: s.ahead })
            : t("diag.inSync"),
      ]);
    } else {
      out.push([t("diag.remote"), t("diag.noneConfigured")]);
    }
    out.push([t("diag.lastSync"), fmtTime(s.autosync?.last_sync)]);
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
      if (s.archived > 0) out.push([t("diag.archived"), String(s.archived)]);
      if (s.trashed > 0) out.push([t("diag.trashed"), String(s.trashed)]);
    }
    return out;
  };

  return (
    <Show when={slug()}>
      <div class="border border-[var(--color-border)] rounded-xl p-4 space-y-3">
        <div class="flex items-center justify-between">
          <h3 class="text-sm font-semibold text-[var(--color-text)]">{t("diag.title")}</h3>
          <Button onClick={() => void refetch()} class="px-2 py-1 text-xs">
            {t("diag.refresh")}
          </Button>
        </div>
        <Show when={err()}>
          <p class="text-xs text-red-400">{err()}</p>
        </Show>
        <Show when={snap()}>
          <div
            class={`text-sm font-semibold ${VERDICT_CLASS[snap().verdict] || "text-[var(--color-text)]"}`}
          >
            {t(VERDICT_KEY[snap().verdict] || "diag.verdict.locked")}
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
