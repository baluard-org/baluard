import { createSignal, onSettled, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError } from "../context/toastSignal.js";
import TypedConfirmModal from "./TypedConfirmModal.jsx";

/**
 * S3-9 UI: Space policy. The three §6.5 knobs landed routes-first; this
 * tab is their surface. The daemon is the validator — the tab renders
 * for everyone (desktop tab convention) and a non-admin set refuses
 * with the daemon's plain-language error.
 */
export default function SpaceTab() {
  const { t } = useI18n();
  const [authority, setAuthority] = createSignal("admins");
  const [viewerExport, setViewerExport] = createSignal(false);
  const [guestSharing, setGuestSharing] = createSignal(true);
  const [trashPolicy, setTrashPolicy] = createSignal("write_scope_can_trash");
  const [busy, setBusy] = createSignal(false);
  const [spaceTeam, setSpaceTeam] = createSignal(null);
  const [teamBusy, setTeamBusy] = createSignal(false);
  const [showFlipConfirm, setShowFlipConfirm] = createSignal(false);

  onSettled(() => {
    void loadSettings();
    void loadTeam();
  });

  async function loadSettings() {
    try {
      const s = JSON.parse(await daemon("space.settings", {}));
      setAuthority(s.space_invite_authority === "owners" ? "owners" : "admins");
      setViewerExport(s.allow_viewer_export === true);
      setGuestSharing(s.guest_enabled !== false);
      setTrashPolicy(s.trash_policy === "admins_only" ? "admins_only" : "write_scope_can_trash");
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function apply(patch) {
    if (busy()) return;
    setBusy(true);
    try {
      await daemon("space.settings_set", patch);
    } catch (e) {
      toastError(sanitizeError(e, t));
      await loadSettings(); // revert to the daemon's truth
    } finally {
      setBusy(false);
    }
  }

  function changeAuthority(next) {
    if (busy() || next === authority()) return;
    setAuthority(next);
    void apply({ space_invite_authority: next });
  }

  function changeTrashPolicy(next) {
    if (busy() || next === trashPolicy()) return;
    setTrashPolicy(next);
    void apply({ trash_policy: next });
  }

  async function loadTeam() {
    try {
      setSpaceTeam(JSON.parse(await daemon("space.status", {})));
    } catch {
      setSpaceTeam(null); // locked, refused (member device), or unavailable
    }
  }

  async function runPrepare() {
    if (teamBusy()) return;
    setTeamBusy(true);
    try {
      const r = JSON.parse(await daemon("space.prepare", {}));
      await loadTeam();
      if ((r.missing_wrap_pubkey?.length ?? 0) > 0) {
        toastError(t("space.teamMissing", { n: r.missing_wrap_pubkey.length }));
      }
    } catch (e) {
      toastError(sanitizeError(e, t));
      await loadTeam();
    } finally {
      setTeamBusy(false);
    }
  }

  async function runFlip() {
    if (teamBusy()) return;
    setTeamBusy(true);
    try {
      await daemon("space.flip", {});
      setShowFlipConfirm(false); // TypedConfirmModal does not auto-close
      await loadTeam();
    } catch (e) {
      toastError(sanitizeError(e, t));
      await loadTeam();
    } finally {
      setTeamBusy(false);
    }
  }

  function toggleViewerExport() {
    if (busy()) return;
    const next = !viewerExport();
    setViewerExport(next);
    void apply({ allow_viewer_export: next });
  }

  function toggleGuestSharing() {
    if (busy()) return;
    const next = !guestSharing();
    setGuestSharing(next);
    void apply({ guest_enabled: next });
  }

  const rowLabel = "text-xs font-bold text-[var(--color-text)]";
  const rowDesc = "text-[10px] text-[var(--color-muted)] mt-0.5";
  const chip = (active) =>
    `px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${active ? "btn-active-green" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`;
  const toggle = (on) =>
    `px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${on ? "btn-active-green" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`;

  return (
    <div class="space-y-3">
      {/* Team mode (S3-7b): the one-way upgrade. Rendered
          unconditionally — the daemon is the validator, and gating the
          state-creating control on its own state deadlocks fresh
          vaults. */}
      <div class="flex items-center justify-between">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.teamLabel")}</span>
          <span class={rowDesc}>
            {spaceTeam() == null ? "\u2026" : spaceTeam().flipped ? t("space.teamOn") : t("space.teamOff")}
          </span>
          <Show when={spaceTeam() && !spaceTeam().flipped && spaceTeam().missing_wrap_pubkey > 0}>
            <span class="text-[10px] text-[var(--color-danger)] mt-0.5">
              {t("space.teamMissing", { n: spaceTeam().missing_wrap_pubkey })}
            </span>
          </Show>
        </div>
        <Show
          when={spaceTeam()?.flipped}
          fallback={
            <div class="flex gap-2">
              <button disabled={teamBusy() || !spaceTeam()} class={chip(false)} onClick={runPrepare}>
                {t("space.teamPrepare")}
              </button>
              <button
                disabled={
                  teamBusy() || !spaceTeam()?.prepared || (spaceTeam()?.missing_wrap_pubkey ?? 0) > 0
                }
                class={chip(spaceTeam()?.prepared === true && (spaceTeam()?.missing_wrap_pubkey ?? 0) === 0)}
                onClick={() => setShowFlipConfirm(true)}
              >
                {t("space.teamUpgrade")}
              </button>
            </div>
          }
        >
          <span class="px-4 py-2 rounded-xl border text-xs font-bold btn-active-green">
            {t("space.teamOnBadge")}
          </span>
        </Show>
      </div>

      {/* Who may invite members */}
      <div class="flex items-center justify-between">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.inviteAuthorityLabel")}</span>
          <span class={rowDesc}>{t("space.inviteAuthorityDesc")}</span>
        </div>
        <div class="flex gap-2">
          <button disabled={busy()} class={chip(authority() === "admins")} onClick={() => changeAuthority("admins")}>
            {t("space.authorityAdmins")}
          </button>
          <button disabled={busy()} class={chip(authority() === "owners")} onClick={() => changeAuthority("owners")}>
            {t("space.authorityOwners")}
          </button>
        </div>
      </div>

      {/* Viewer export */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.viewerExportLabel")}</span>
          <span class={rowDesc}>{t("space.viewerExportDesc")}</span>
        </div>
        <button disabled={busy()} class={toggle(viewerExport())} onClick={toggleViewerExport}>
          {viewerExport() ? t("settings.enabled") : t("settings.disabled")}
        </button>
      </div>

      {/* Guest sharing */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.guestLabel")}</span>
          <span class={rowDesc}>{t("space.guestDesc")}</span>
        </div>
        <button disabled={busy()} class={toggle(guestSharing())} onClick={toggleGuestSharing}>
          {guestSharing() ? t("settings.enabled") : t("settings.disabled")}
        </button>
      </div>
      {/* Trash policy */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.trashPolicyLabel")}</span>
          <span class={rowDesc}>{t("space.trashPolicyDesc")}</span>
        </div>
        <div class="flex gap-2">
          <button
            disabled={busy()}
            class={chip(trashPolicy() === "write_scope_can_trash")}
            onClick={() => changeTrashPolicy("write_scope_can_trash")}
          >
            {t("space.trashWriteScope")}
          </button>
          <button
            disabled={busy()}
            class={chip(trashPolicy() === "admins_only")}
            onClick={() => changeTrashPolicy("admins_only")}
          >
            {t("space.trashAdminsOnly")}
          </button>
        </div>
      </div>

      {/* Restore policy — v1 is single-valued (admins only); rendered
          read-only so the surface shows the full state honestly. */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.restorePolicyLabel")}</span>
          <span class={rowDesc}>{t("space.restorePolicyDesc")}</span>
        </div>
        <span class="px-4 py-2 rounded-xl border text-xs font-bold text-[var(--color-muted)]">
          {t("space.restoreAdminsOnly")}
        </span>
      </div>

      <TypedConfirmModal
        show={showFlipConfirm()}
        idPrefix="space-flip"
        title={t("space.teamConfirmTitle")}
        body={t("space.teamConfirmBody")}
        confirmLabel={t("space.teamUpgrade")}
        confirmWord="team"
        onConfirm={runFlip}
        onClose={() => setShowFlipConfirm(false)}
      />
    </div>
  );
}
