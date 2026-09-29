import { createSignal, onSettled, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { copyToClipboard } from "../lib/clipboard.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import ConfirmModal from "./ConfirmModal.jsx";
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
  const [joinApproval, setJoinApproval] = createSignal("manual");
  const [quorum, setQuorum] = createSignal(1);
  const [createAuth, setCreateAuth] = createSignal("admins");
  const [pendingOps, setPendingOps] = createSignal([]);
  const [busy, setBusy] = createSignal(false);
  const [spaceTeam, setSpaceTeam] = createSignal(null);
  const [teamBusy, setTeamBusy] = createSignal(false);
  const [showFlipConfirm, setShowFlipConfirm] = createSignal(false);
  // S4-6: advisory org policies. null = nothing published.
  const [policies, setPolicies] = createSignal(null);
  const [policiesBusy, setPoliciesBusy] = createSignal(false);
  // S4-7: recovery kit. null = status not loaded yet.
  const [kitEnabled, setKitEnabled] = createSignal(null);
  const [kitBusy, setKitBusy] = createSignal(false);
  const [kitPhrase, setKitPhrase] = createSignal(null);
  const [showKitConfirm, setShowKitConfirm] = createSignal(false);

  onSettled(() => {
    void loadSettings();
    void loadTeam();
    void loadPending();
    void loadPolicies();
    void loadKit();
  });

  async function loadKit() {
    try {
      const r = JSON.parse(await daemon("space.kit_status", {}));
      setKitEnabled(r.enabled === true);
    } catch {
      setKitEnabled(null); // locked, refused, or unavailable
    }
  }

  async function runKitEnable() {
    if (kitBusy()) return;
    setKitBusy(true);
    try {
      const r = JSON.parse(await daemon("space.kit_enable", {}));
      setKitPhrase(r.phrase);
      setKitEnabled(true);
      toastSuccess(t("space.kitEnabled"));
    } catch (e) {
      toastError(sanitizeError(e, t));
      await loadKit();
    } finally {
      setKitBusy(false);
    }
  }

  async function runKitDisable() {
    if (kitBusy()) return;
    setKitBusy(true);
    try {
      await daemon("space.kit_disable", {});
      setKitEnabled(false);
      setKitPhrase(null);
      toastSuccess(t("space.kitDisabled"));
    } catch (e) {
      toastError(sanitizeError(e, t));
      await loadKit();
    } finally {
      setKitBusy(false);
    }
  }

  async function loadPolicies() {
    try {
      const r = JSON.parse(await daemon("policies.list", {}));
      setPolicies(r.policies && Object.keys(r.policies).length > 0 ? r.policies : null);
    } catch {
      setPolicies(null); // locked or nothing published
    }
  }

  function recommendedFor(key) {
    return policies()?.[key];
  }

  function policyValue(key) {
    const v = recommendedFor(key);
    if (typeof v === "boolean") return v ? t("settings.enabled") : t("settings.disabled");
    // Enum values render through their existing chip labels, never as
    // raw wire strings.
    const labels = {
      admins: "space.authorityAdmins",
      owners: "space.authorityOwners",
      editors: "space.createEditors",
      write_scope_can_trash: "space.trashWriteScope",
      admins_only: "space.trashAdminsOnly",
      manual: "space.joinManual",
      code: "space.joinCode",
    };
    return labels[v] ? t(labels[v]) : String(v);
  }

  function policyHint(key) {
    return (
      <Show when={recommendedFor(key) !== undefined}>
        <span class="text-[10px] text-[var(--color-primary)] mt-0.5">
          {t("space.policyHint", { value: policyValue(key) })}
        </span>
      </Show>
    );
  }

  async function publishPolicies() {
    if (policiesBusy()) return;
    setPoliciesBusy(true);
    try {
      await daemon("policies.set", {
        space_invite_authority: authority(),
        allow_viewer_export: viewerExport(),
        guest_enabled: guestSharing(),
        trash_policy: trashPolicy(),
        join_approval: joinApproval(),
        quorum_admin_ops: quorum(),
        collection_create_authority: createAuth(),
      });
      toastSuccess(t("space.policyDone"));
      await loadPolicies();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setPoliciesBusy(false);
    }
  }

  async function clearPolicies() {
    if (policiesBusy()) return;
    setPoliciesBusy(true);
    try {
      await daemon("policies.set", {});
      toastSuccess(t("space.policyCleared"));
      await loadPolicies();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setPoliciesBusy(false);
    }
  }

  async function loadPending() {
    try {
      const r = JSON.parse(await daemon("approvals.list", {}));
      setPendingOps(Array.isArray(r.pending) ? r.pending : []);
    } catch {
      setPendingOps([]); // locked or refused — no asks to show
    }
  }

  async function loadSettings() {
    try {
      const s = JSON.parse(await daemon("space.settings", {}));
      setAuthority(s.space_invite_authority === "owners" ? "owners" : "admins");
      setViewerExport(s.allow_viewer_export === true);
      setGuestSharing(s.guest_enabled !== false);
      setTrashPolicy(s.trash_policy === "admins_only" ? "admins_only" : "write_scope_can_trash");
      setJoinApproval(s.join_approval === "code" ? "code" : "manual");
      setQuorum(Math.min(5, Math.max(1, Number(s.quorum_admin_ops) || 1)));
      setCreateAuth(s.collection_create_authority === "editors" ? "editors" : "admins");
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

  function changeJoinApproval(next) {
    if (busy() || next === joinApproval()) return;
    setJoinApproval(next);
    void apply({ join_approval: next });
  }

  function changeQuorum(next) {
    if (busy() || next === quorum()) return;
    setQuorum(next);
    void apply({ quorum_admin_ops: next });
  }

  function changeCreateAuth(next) {
    if (busy() || next === createAuth()) return;
    setCreateAuth(next);
    void apply({ collection_create_authority: next });
  }

  function opLabel(kind) {
    const map = {
      rotate_root_key: "space.opRotate",
      member_remove: "space.opRemove",
      transfer_ownership: "space.opTransfer",
      member_reset: "space.opReset",
      space_migrate: "space.opMigrate",
      ownership_claim: "space.opClaim",
      quorum_lower: "space.opLower",
    };
    return map[kind] ? t(map[kind]) : kind;
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
          {policyHint("space_invite_authority")}
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
          {policyHint("allow_viewer_export")}
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
          {policyHint("guest_enabled")}
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
          {policyHint("trash_policy")}
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

      {/* Join approval */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.joinApprovalLabel")}</span>
          <span class={rowDesc}>{t("space.joinApprovalDesc")}</span>
          {policyHint("join_approval")}
        </div>
        <div class="flex gap-2">
          <button
            disabled={busy()}
            class={chip(joinApproval() === "manual")}
            onClick={() => changeJoinApproval("manual")}
          >
            {t("space.joinManual")}
          </button>
          <button
            disabled={busy()}
            class={chip(joinApproval() === "code")}
            onClick={() => changeJoinApproval("code")}
          >
            {t("space.joinCode")}
          </button>
        </div>
      </div>

      {/* Quorum for sensitive ops (§6.5, decided 2026-09-27) */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.quorumLabel")}</span>
          <span class={rowDesc}>{t("space.quorumDesc")}</span>
          {policyHint("quorum_admin_ops")}
        </div>
        <div class="flex flex-col items-end gap-1">
          <div class="flex gap-2">
            {[1, 2, 3].map((n) => (
              <button disabled={busy()} class={chip(quorum() === n)} onClick={() => changeQuorum(n)}>
                {n}
              </button>
            ))}
          </div>
          <span class={rowDesc}>{t("space.quorumCurrent", { n: quorum() })}</span>
        </div>
      </div>

      {/* Who may create collections */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.createAuthLabel")}</span>
          <span class={rowDesc}>{t("space.createAuthDesc")}</span>
          {policyHint("collection_create_authority")}
        </div>
        <div class="flex gap-2">
          <button disabled={busy()} class={chip(createAuth() === "admins")} onClick={() => changeCreateAuth("admins")}>
            {t("space.createAdmins")}
          </button>
          <button disabled={busy()} class={chip(createAuth() === "editors")} onClick={() => changeCreateAuth("editors")}>
            {t("space.createEditors")}
          </button>
        </div>
      </div>

      {/* S4-6: advisory org policies — publish current settings as
          recommendations; member surfaces render them as hints. The
          daemon is the validator (SyncTab precedent). */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.policyTitle")}</span>
          <span class={rowDesc}>
            {policies()
              ? t("space.policyPublished", { n: Object.keys(policies()).length })
              : t("space.policyNone")}
          </span>
        </div>
        <div class="flex gap-2">
          <Show when={policies()}>
            <button disabled={policiesBusy()} class={chip(false)} onClick={clearPolicies}>
              {t("space.policyClear")}
            </button>
          </Show>
          <button disabled={policiesBusy()} class={chip(false)} onClick={publishPolicies}>
            {t("space.policyPublish")}
          </button>
        </div>
      </div>

      {/* Pending sensitive-op asks (visible when quorum > 1) */}
      <Show when={pendingOps().length > 0}>
        <div class="mt-4 pt-4 border-t border-[var(--color-border)]">
          <span class={rowLabel}>{t("space.pendingTitle")}</span>
          <div class="flex flex-col gap-1 mt-2">
            {pendingOps().map((op) => (
              <div class="flex items-center justify-between text-[11px]">
                <span class="text-[var(--color-text)]">{opLabel(op.kind)}</span>
                <span class="flex items-center gap-2">
                  <span class="text-[var(--color-muted)]">
                    {t("space.pendingItem", { have: op.approvals?.length ?? 0, need: op.required })}
                  </span>
                  {/* §13 review F1: a pending claim is confirmed by
                      repeating the SAME ask — the row now carries the
                      ask's params, so the co-approver approves the
                      claimant named there. */}
                  <Show when={op.kind === "ownership_claim"}>
                    <button
                      onClick={async () => {
                        try {
                          await daemon("members.claim", {
                            member_id: op.params?.new_owner_id || op.initiated_by,
                          });
                          await loadPending();
                        } catch {
                          /* the row stays pending on failure */
                        }
                      }}
                      class="px-2 py-0.5 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
                    >
                      {t("people.approve")}
                    </button>
                  </Show>
                </span>
              </div>
            ))}
          </div>
        </div>
      </Show>

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

      {/* S4-7: Space Recovery Kit — the offline phrase that opens the
          Space when every admin device is lost. The daemon gates it. */}
      <div class="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
        <div class="flex flex-col flex-1 pr-4">
          <span class={rowLabel}>{t("space.kitLabel")}</span>
          <span class={rowDesc}>{t("space.kitDesc")}</span>
        </div>
        <Show
          when={kitEnabled() !== null}
          fallback={<span class="text-[11px] text-[var(--color-muted)]">…</span>}
        >
          <Show
            when={kitEnabled()}
            fallback={
              <button disabled={kitBusy()} class={chip(false)} onClick={runKitEnable}>
                {t("space.kitEnable")}
              </button>
            }
          >
            <button
              disabled={kitBusy()}
              class={chip(false)}
              onClick={() => setShowKitConfirm(true)}
            >
              {t("space.kitDisable")}
            </button>
          </Show>
        </Show>
      </div>

      <Show when={kitPhrase()}>
        <div class="mt-3 p-3 rounded-xl border border-amber-500/40 bg-amber-500/10">
          <div class="text-[11px] font-bold text-amber-500">{t("space.kitPhraseTitle")}</div>
          <div class="text-[11px] text-[var(--color-text)] mt-1">{t("space.kitPhraseWarn")}</div>
          <div class="mt-2 p-2 rounded-lg bg-[var(--color-surface)] font-mono text-[11px] break-words">
            {kitPhrase()}
          </div>
          <div class="flex items-center justify-between mt-2">
            <button
              class="text-[11px] text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
              onClick={() => copyToClipboard(kitPhrase())}
            >
              {t("space.kitCopy")}
            </button>
            <button
              class="text-[11px] font-bold text-[var(--color-text)] cursor-pointer"
              onClick={() => setKitPhrase(null)}
            >
              {t("space.kitStored")}
            </button>
          </div>
        </div>
      </Show>

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

      <ConfirmModal
        show={showKitConfirm()}
        idPrefix="space-kit-disable"
        title={t("space.kitConfirmTitle")}
        body={t("space.kitConfirmBody")}
        confirmLabel={t("space.kitDisable")}
        confirmVariant="danger"
        onConfirm={runKitDisable}
        onClose={() => setShowKitConfirm(false)}
      />
    </div>
  );
}
