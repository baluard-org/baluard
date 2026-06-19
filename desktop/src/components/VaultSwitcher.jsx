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

import { createSignal, Show, For, useContext } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { VaultContext } from "../context/VaultContext.jsx";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { sanitizeError } from "../lib/utils.js";
import { IconChevronDown, IconLock, IconCheck, IconX } from "./Icon.jsx";

const STATE_LABEL_KEY = {
  unlocked: "vault.vaultSwitcher.stateUnlocked",
  locked: "vault.vaultSwitcher.stateLocked",
  closed: "vault.vaultSwitcher.stateClosed",
};

const STATE_DOT_CLASS = {
  unlocked: "bg-green-500",
  locked: "bg-amber-500",
  closed: "bg-slate-400",
};

export default function VaultSwitcher(props) {
  const { t } = useI18n();
  const switcher = useVaultSwitcher();
  const vault = useContext(VaultContext);
  const [open, setOpen] = createSignal(false);
  let optionRefs = [];

  // props.onLockedTarget(slug): called when the user picks a vault that
  // is locked or closed. The parent (App) routes to the unlock screen.

  async function pick(row) {
    setOpen(false);
    if (row.active) return;
    // Branch on the row's current presence BEFORE flipping the daemon's
    // active pointer. For an already-unlocked vault we switch + refetch
    // (instant). For a locked/closed vault we hand off to the unlock flow
    // WITHOUT switching — switching first would leave the active pointer on
    // a locked vault if the user cancels, breaking slug-less requests for
    // the still-displayed vault.
    if (row.presence === "unlocked") {
      try {
        await switcher.switchTo(row.slug);
        if (vault) {
          await vault.refreshCiphers(t);
        }
        toastSuccess(t("vault.vaultSwitcher.switchedTo", { name: row.display_name }));
      } catch (e) {
        toastError(sanitizeError(e, t));
      }
    } else {
      // Locked or closed: hand off to the unlock flow (modal).
      if (props.onLockedTarget) props.onLockedTarget(row);
    }
  }

  async function closeVault(slug, e) {
    e.stopPropagation();
    try {
      await switcher.close(slug);
      toastSuccess(t("vault.vaultSwitcher.closed", { name: slug }));
    } catch (e2) {
      toastError(sanitizeError(e2, t));
    }
  }

  const activeRow = () => switcher.vaults().find((r) => r.active);
  const activeName = () => activeRow()?.display_name || t("vault.vaultSwitcher.noActive");

  // Focus management when dropdown opens
  function handleToggle() {
    const nextOpen = !open();
    setOpen(nextOpen);
    if (nextOpen) {
      optionRefs = [];
      setTimeout(() => {
        // Focus either the active vault option or the first available option
        const activeIdx = switcher.vaults().findIndex(r => r.active);
        const focusIdx = activeIdx !== -1 ? activeIdx : 0;
        if (optionRefs[focusIdx]) {
          optionRefs[focusIdx].focus();
        }
      }, 50);
    }
  }

  function handleKeyDown(index, e) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const nextIdx = (index + 1) % switcher.vaults().length;
      if (optionRefs[nextIdx]) optionRefs[nextIdx].focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const prevIdx = (index - 1 + switcher.vaults().length) % switcher.vaults().length;
      if (optionRefs[prevIdx]) optionRefs[prevIdx].focus();
    } else if (e.key === "Escape") {
      e.preventDefault();
      setOpen(false);
    }
  }

  return (
    <div
      class="relative"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          setOpen(false);
        }
      }}
    >
      <Show
        when={props.children}
        fallback={
          <button
            type="button"
            onClick={handleToggle}
            class="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] hover:bg-[var(--color-sidebar)] transition-all w-full text-left cursor-pointer"
            aria-haspopup="listbox"
            aria-expanded={open()}
            title={t("vault.vaultSwitcher.tooltip")}
          >
            <IconLock class="w-3.5 h-3.5 text-[var(--color-primary)] shrink-0" />
            <span class="flex-1 min-w-0 text-xs font-bold text-[var(--color-text)] truncate">
              {activeName()}
            </span>
            <IconChevronDown
              class={`w-3.5 h-3.5 text-[var(--color-muted)] transition-transform shrink-0 ${open() ? "rotate-180" : ""}`}
            />
          </button>
        }
      >
        <button
          type="button"
          onClick={handleToggle}
          class="flex items-center gap-3 min-w-0 flex-1 text-left cursor-pointer hover:opacity-90 transition-opacity"
          aria-haspopup="listbox"
          aria-expanded={open()}
          title={t("vault.vaultSwitcher.tooltip")}
        >
          {props.children}
        </button>
      </Show>

      <Show when={open()}>
        {/* Click-away backdrop */}
        <div
          class="fixed inset-0 z-40"
          onClick={() => setOpen(false)}
        />
        <div
          role="listbox"
          aria-label={t("vault.vaultSwitcher.listLabel")}
          class={`absolute left-0 z-50 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-2xl overflow-hidden max-h-80 overflow-y-auto ${
            props.children ? "bottom-full mb-2 w-64 -translate-y-1" : "top-full mt-1 w-full"
          }`}
        >
          <For each={switcher.vaults()}>
            {(row, index) => (
              <button
                ref={(el) => optionRefs[index()] = el}
                type="button"
                role="option"
                aria-selected={row.active}
                onClick={() => pick(row)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    pick(row);
                  } else {
                    handleKeyDown(index(), e);
                  }
                }}
                class={`w-full flex items-center text-left gap-2 px-3 py-2 cursor-pointer transition-colors border-l-2 focus:outline-none focus:bg-[var(--color-sidebar)] focus:border-[var(--color-primary)] ${
                  row.active
                    ? "bg-[var(--color-primary)]/10 border-[var(--color-primary)]"
                    : "hover:bg-[var(--color-sidebar)] border-transparent"
                }`}
              >
                <span
                  class={`w-2 h-2 rounded-full shrink-0 ${STATE_DOT_CLASS[row.presence] || "bg-slate-400"}`}
                  title={t(STATE_LABEL_KEY[row.presence] || "vault.vaultSwitcher.stateClosed")}
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
                  {t(STATE_LABEL_KEY[row.presence] || "vault.vaultSwitcher.stateClosed")}
                </span>
                <Show when={row.active}>
                  <IconCheck class="w-3.5 h-3.5 text-[var(--color-primary)] shrink-0" />
                </Show>
                {/* Close button: only for open (in-map) vaults, not the active one. */}
                <Show when={!row.active && row.presence !== "closed"}>
                  <button
                    type="button"
                    onClick={(e) => closeVault(row.slug, e)}
                    class="p-0.5 rounded text-[var(--color-muted)] hover:text-red-500 transition-colors shrink-0 cursor-pointer focus:ring-1 focus:ring-red-500"
                    title={t("vault.vaultSwitcher.closeVault", { name: row.display_name })}
                    aria-label={t("vault.vaultSwitcher.closeVault", { name: row.display_name })}
                  >
                    <IconX class="w-3 h-3" />
                  </button>
                </Show>
              </button>
            )}
          </For>
          <Show when={switcher.vaults().length === 0}>
            <div class="px-3 py-4 text-xs text-[var(--color-muted)] text-center">
              {t("vault.vaultSwitcher.empty")}
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
}
