// Phase 6: VaultSwitcher dropdown.
//
// Renders as a compact button in the sidebar header. Clicking expands a
// list of every registered vault with its in-daemon state (unlocked /
// locked / closed). Selecting a vault flips the daemon's active pointer;
// if the target is locked or closed, the caller re-runs the unlock flow
// for that slug via the `onLockedTarget` callback (so the unlock screen
// can be shown by AuthContext without this component knowing about it).
//
// This is an inline dropdown, not a modal — it does not use FocusTrap.

import { createSignal, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { useVault } from "../context/VaultContext.jsx";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { sanitizeError } from "../lib/utils.js";
import { IconChevronDown, IconLock, IconCheck, IconX } from "./Icon.jsx";

const STATE_LABEL_KEY = {
  unlocked: "vaultSwitcher.stateUnlocked",
  locked: "vaultSwitcher.stateLocked",
  closed: "vaultSwitcher.stateClosed",
};

const STATE_DOT_CLASS = {
  unlocked: "bg-green-500",
  locked: "bg-amber-500",
  closed: "bg-slate-400",
};

export default function VaultSwitcher(props) {
  const { t } = useI18n();
  const switcher = useVaultSwitcher();
  const vault = useVault();
  const [open, setOpen] = createSignal(false);

  // props.onLockedTarget(slug): called when the user picks a vault that
  // is locked or closed. The parent (App) routes to the unlock screen.

  async function pick(row) {
    setOpen(false);
    if (row.active) return;
    try {
      const outcome = await switcher.switchTo(row.slug);
      if (outcome.presence === "unlocked") {
        // Instant switch: refetch the new active vault's data.
        await vault.refreshCiphers(t);
        toastSuccess(t("vaultSwitcher.switchedTo", { name: row.display_name }));
      } else {
        // Locked or closed: hand off to the unlock flow.
        if (props.onLockedTarget) props.onLockedTarget(row.slug);
      }
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function closeVault(slug, e) {
    e.stopPropagation();
    try {
      await switcher.close(slug);
      toastSuccess(t("vaultSwitcher.closed", { name: slug }));
    } catch (e2) {
      toastError(sanitizeError(e2, t));
    }
  }

  const activeRow = () => switcher.vaults().find((r) => r.active);
  const activeName = () => activeRow()?.display_name || t("vaultSwitcher.noActive");

  return (
    <div class="relative">
      <button
        type="button"
        onClick={() => setOpen(!open())}
        class="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] hover:bg-[var(--color-sidebar)] transition-all w-full text-left cursor-pointer"
        aria-haspopup="listbox"
        aria-expanded={open()}
        title={t("vaultSwitcher.tooltip")}
      >
        <IconLock class="w-3.5 h-3.5 text-[var(--color-primary)] shrink-0" />
        <span class="flex-1 min-w-0 text-xs font-bold text-[var(--color-text)] truncate">
          {activeName()}
        </span>
        <IconChevronDown
          class={`w-3.5 h-3.5 text-[var(--color-muted)] transition-transform shrink-0 ${open() ? "rotate-180" : ""}`}
        />
      </button>

      <Show when={open()}>
        {/* Click-away backdrop */}
        <div
          class="fixed inset-0 z-40"
          onClick={() => setOpen(false)}
        />
        <div
          role="listbox"
          aria-label={t("vaultSwitcher.listLabel")}
          class="absolute left-0 right-0 mt-1 z-50 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-2xl overflow-hidden max-h-80 overflow-y-auto"
        >
          <For each={switcher.vaults()}>
            {(row) => (
              <div
                role="option"
                aria-selected={row.active}
                onClick={() => pick(row)}
                class={`flex items-center gap-2 px-3 py-2 cursor-pointer transition-colors ${
                  row.active
                    ? "bg-[var(--color-sidebar)]"
                    : "hover:bg-[var(--color-sidebar)]"
                }`}
              >
                <span
                  class={`w-2 h-2 rounded-full shrink-0 ${STATE_DOT_CLASS[row.presence] || "bg-slate-400"}`}
                  title={t(STATE_LABEL_KEY[row.presence] || "vaultSwitcher.stateClosed")}
                />
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-bold text-[var(--color-text)] truncate">
                    {row.display_name}
                  </div>
                  <div class="text-[9px] text-[var(--color-muted)] truncate font-mono">
                    {row.slug}
                  </div>
                </div>
                <span class="text-[9px] uppercase tracking-wide text-[var(--color-muted)] shrink-0">
                  {t(STATE_LABEL_KEY[row.presence] || "vaultSwitcher.stateClosed")}
                </span>
                <Show when={row.active}>
                  <IconCheck class="w-3.5 h-3.5 text-[var(--color-primary)] shrink-0" />
                </Show>
                {/* Close button: only for open (in-map) vaults, not the active one. */}
                <Show when={!row.active && row.presence !== "closed"}>
                  <button
                    type="button"
                    onClick={(e) => closeVault(row.slug, e)}
                    class="p-0.5 rounded text-[var(--color-muted)] hover:text-red-500 transition-colors shrink-0 cursor-pointer"
                    title={t("vaultSwitcher.closeVault", { name: row.display_name })}
                    aria-label={t("vaultSwitcher.closeVault", { name: row.display_name })}
                  >
                    <IconX class="w-3 h-3" />
                  </button>
                </Show>
              </div>
            )}
          </For>
          <Show when={switcher.vaults().length === 0}>
            <div class="px-3 py-4 text-xs text-[var(--color-muted)] text-center">
              {t("vaultSwitcher.empty")}
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
}
