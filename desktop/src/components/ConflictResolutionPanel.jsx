import { createSignal, For, Show } from "solid-js";
import { useConflictResolution } from "../context/ConflictResolutionContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { toastError } from "../context/toastSignal.js";
import { resolveConflict } from "../lib/conflictFlow.js";
import ConsolePanel from "./ConsolePanel.jsx";
import { IconAlert, IconCopy, IconMonitor, IconSwitch } from "./Icon.jsx";

// Top-floating, modal decision panel for git-sync conflicts the auto path
// cannot resolve. Slides down from the top (`.animate-conflict-panel`), blocks
// interaction, and is NON-dismissable until the user picks a verdict — by
// design, because every silent default is a potential data-loss path.
//
// Non-technical by construction: no git jargon, decisions framed by device,
// secrets masked (never shown). One conflict at a time (1 of N).
//
// See docs/plan-conflict-resolution-panel.md for the failure modes (F1–F4)
// and the data contract.

export default function ConflictResolutionPanel(props) {
  const conflicts = useConflictResolution();
  const { t } = useI18n();
  const [explainOpen, setExplainOpen] = createSignal(false);
  // Re-entrancy guard: a decision is an async IPC call. Without this, a
  // double-click (or a nervous user mashing a button) fires two concurrent
  // resolve() calls against the same head with potentially different verdicts
  // — last-write-wins on a destructive UI whose whole purpose is preventing
  // silent wrong defaults. Buttons are disabled while a resolve is in flight.
  const [isResolving, setIsResolving] = createSignal(false);
  let panelRef;

  // Friendly device names, falling back to plain "this / the other device".
  const localLabel = () =>
    conflicts.current()?.localDevice || t("conflict.thisDevice");
  const remoteLabel = () =>
    conflicts.current()?.remoteDevice || t("conflict.otherDevice");

  // Stepper: "1 of 3".
  const stepLabel = () =>
    t("conflict.step", {
      current: conflicts.hasPending() ? 1 : 0,
      total: conflicts.count(),
    });

  async function decide(verdict) {
    // Re-entrancy guard: one decision at a time (see isResolving comment).
    if (isResolving()) return;
    setIsResolving(true);
    // Phase 2b-4: default resolver calls the real sync.conflict.resolve IPC.
    // Callers can override via props.resolver (e.g. for tests or a future
    // batch-resolve flow). resolve() re-throws on resolver failure and keeps
    // the conflict in the queue (see ConflictResolutionContext). Surface a
    // toast so the user knows the decision didn't go through and can retry.
    //
    // TODO(stuck-queue): if the real sync.conflict.resolve IPC permanently
    // fails (daemon down, item key unrecoverable), the head never leaves the
    // queue and this modal is non-dismissable, locking the user out of the
    // vault UI. Acceptable today because the route isn't wired yet (dev-only
    // mock triggers). When wiring lands, add either a max-retry fallback to a
    // safe non-destructive state or a manual escape hatch. See
    // docs/plan-conflict-resolution-panel.md.
    // Mock head (dev trigger): the daemon has no matching pending_conflict
    // for a mock, so a real IPC would toast on every click. Use a no-op
    // resolver that just succeeds, draining the queue locally. Per-item flag
    // (not a global mode) so a mock and a real conflict can coexist without
    // the mock's no-op leaking onto the real one.
    const resolver =
      import.meta.env.DEV && conflicts.headIsMock()
        ? async () => {}
        : props.resolver ?? ((_conflict, v) => resolveConflict(v));
    try {
      await conflicts.resolve(verdict, resolver);
      setExplainOpen(false);
    } catch (e) {
      toastError(t("conflict.resolveFailed"));
    } finally {
      setIsResolving(false);
    }
  }

  return (
    <ConsolePanel
      show={conflicts.hasPending()}
      accentClass="border-amber-500"
      minHeightClass="min-h-[24rem]"
      role="alertdialog"
      ariaLabelledby="conflict-title"
      ariaDescribedby="conflict-desc"
      onEscape={() => {
        /* intentionally no-op: no dismiss without a verdict */
      }}
    >
      <div class="w-full flex flex-col md:flex-row gap-6 md:gap-10 items-stretch">
        {/* Column 1: Info and Details */}
        <div class="flex-1 min-w-0 flex flex-col gap-4">
          {/* Header */}
          <div class="flex items-center gap-3 pb-3 border-b border-[var(--color-border)]">
            <div class="shrink-0 w-8 h-8 rounded-lg bg-amber-500/10 flex items-center justify-center border border-amber-500/20">
              <IconAlert class="w-4 h-4 text-amber-500" />
            </div>
            <div class="flex-1 min-w-0">
              <h2
                id="conflict-title"
                class="text-sm font-bold uppercase tracking-wider text-[var(--color-text)] leading-none"
              >
                {t("conflict.title")}
              </h2>
              <span class="text-[10px] font-mono text-amber-500 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20 mt-1 inline-block">
                {stepLabel()}
              </span>
            </div>
          </div>

          {/* Body */}
          <p
            id="conflict-desc"
            class="text-sm text-[var(--color-text)] leading-relaxed"
          >
            {t("conflict.intro", { name: conflicts.current()?.name })}
          </p>

          {/* What diverged — masked, never shows secret values. */}
          <Show
            when={!conflicts.current()?.typeChanged}
            fallback={
              <div class="px-3 py-2.5 rounded-lg bg-amber-950/20 border border-amber-900/30 text-xs text-amber-200 leading-relaxed font-mono">
                {t("conflict.typeChanged")}
              </div>
            }
          >
            <div class="px-3 py-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
              <p class="text-[10px] font-bold uppercase tracking-wide text-[var(--color-muted)] mb-1.5 font-mono">
                {t("conflict.changedFields")}
              </p>
              <ul class="flex flex-wrap gap-1.5">
                <For each={conflicts.current()?.fields}>
                  {(f) => (
                    <li class="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/30 border border-amber-900/40 text-xs text-amber-200 font-mono">
                      <Show when={f.sensitive}>
                        <span aria-hidden="true">••••</span>
                      </Show>
                      <span>{f.label}</span>
                    </li>
                  )}
                </For>
              </ul>
            </div>
          </Show>

          {/* Expandable plain-language explanation for the curious. */}
          <div>
            <button
              type="button"
              onClick={() => setExplainOpen((v) => !v)}
              aria-expanded={explainOpen()}
              class="text-xs text-amber-500 hover:text-amber-400 font-mono underline underline-offset-2 cursor-pointer flex items-center gap-1"
            >
              <span>&gt;</span> {t("conflict.whatDoesThisMean")}
            </button>
            <Show when={explainOpen()}>
              <p class="mt-2 text-xs text-[var(--color-muted)] leading-relaxed bg-[var(--color-bg)]/40 p-3 rounded border border-[var(--color-border)]">
                {t("conflict.explanation", {
                  local: localLabel(),
                  remote: remoteLabel(),
                })}
              </p>
            </Show>
          </div>
        </div>

        {/* Column 2: Decision buttons */}
        <div class="w-full md:w-96 shrink-0 flex flex-col gap-2 justify-start pt-6 md:pt-1 md:pl-8 border-t md:border-t-0 md:border-l border-[var(--color-border)]">
          <p class="text-[10px] font-bold uppercase tracking-widest text-[var(--color-muted)] mb-1 font-mono">
            // RESOLUTION VERDICT REQUIRED
          </p>
          <DecisionButton
            icon={<IconMonitor class="w-4 h-4" />}
            title={t("conflict.keepLocal.title")}
            desc={t("conflict.keepLocal.desc", { local: localLabel() })}
            onClick={() => decide("keep_local")}
            variant="primary"
            disabled={isResolving()}
          />
          <DecisionButton
            icon={<IconSwitch class="w-4 h-4" />}
            title={t("conflict.keepRemote.title")}
            desc={t("conflict.keepRemote.desc", {
              remote: remoteLabel(),
            })}
            onClick={() => decide("keep_remote")}
            disabled={isResolving()}
          />
          {/* Non-destructive escape hatch — never loses data. */}
          <DecisionButton
            icon={<IconCopy class="w-4 h-4" />}
            title={t("conflict.keepBoth.title")}
            desc={t("conflict.keepBoth.desc")}
            onClick={() => decide("keep_both")}
            highlight
            disabled={isResolving()}
          />
        </div>
      </div>
    </ConsolePanel>
  );
}

function DecisionButton(props) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      disabled={props.disabled}
      class={`group flex items-start gap-3 px-4 py-3 rounded-xl border text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-primary)] active:scale-[0.99] ${
        props.disabled ? "opacity-60 cursor-not-allowed active:scale-100" : "cursor-pointer"
      } ${
        props.variant === "primary"
          ? "bg-[var(--color-primary)] border-transparent text-[var(--color-primary-text)] hover:bg-[var(--color-primary-hover)]"
          : props.highlight
            ? "bg-[var(--color-sidebar)] border-amber-900/40 hover:border-amber-700/60"
            : "bg-[var(--color-sidebar)] border-[var(--color-border)] hover:border-[var(--color-text)]"
      }`}
    >
      <span
        class={`shrink-0 mt-0.5 ${
          props.variant === "primary"
            ? "text-[var(--color-primary-text)]"
            : "text-[var(--color-muted)] group-hover:text-[var(--color-text)]"
        }`}
      >
        {props.icon}
      </span>
      <span class="flex-1 min-w-0">
        <span
          class={`block text-sm font-bold ${props.variant === "primary" ? "" : "text-[var(--color-text)]"}`}
        >
          {props.title}
        </span>
        <span
          class={`block text-xs mt-0.5 ${props.variant === "primary" ? "opacity-90" : "text-[var(--color-muted)]"}`}
        >
          {props.desc}
        </span>
      </span>
    </button>
  );
}
