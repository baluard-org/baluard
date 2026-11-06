import { createSignal, onSettled, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import CopyButton from "./CopyButton.jsx";
import TypedConfirmModal from "./TypedConfirmModal.jsx";
import ConfirmModal from "./ConfirmModal.jsx";
import FocusTrap from "./FocusTrap.jsx";

// §4.8-1: the People surface — members, invites, join queue, activity.
// Plain language only: roles are words, the join queue is "requests",
// and the activity log renders pre-rendered human sentences (S1b-1).
// No git, crypto, or sync vocabulary.

const ROLE_STYLES = {
  owner: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  admin: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  editor: "bg-green-500/15 text-green-400 border-green-500/30",
  viewer: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

const TRUST_KEYS = {
  channel: "people.trustChannel",
  verified: "people.trustVerified",
  admin: "people.trustAdmin",
  "admin-unverified": "people.trustAdminUnverified",
};

// S4-5: timeline kinds → label keys (unknown kinds render verbatim).
const TL_KINDS = {
  "vault-created": "people.tlVaultCreated",
  "member-added": "people.tlMemberAdded",
  "member-removed": "people.tlMemberRemoved",
  "member-reset": "people.tlMemberReset",
  "identity-rotated": "people.tlIdentityRotated",
  "role-changed": "people.tlRoleChanged",
  "member-role-changed": "people.tlRoleChanged",
  "ownership-transferred": "people.tlOwnershipTransferred",
  "collection-created": "people.tlCollectionCreated",
  "collection-deleted": "people.tlCollectionDeleted",
  "grant-added": "people.tlGrantAdded",
  "grant-revoked": "people.tlGrantRevoked",
  "group-created": "people.tlGroupCreated",
  "group-deleted": "people.tlGroupDeleted",
  "group-membership-changed": "people.tlGroupMembershipChanged",
  "key-rotated": "people.tlKeyRotated",
  "team-flip": "people.tlTeamFlip",
  "policies-set": "people.tlPoliciesSet",
  "recovery-kit-set": "people.tlRecoveryKitSet",
  "remote-moved": "people.tlRemoteMoved",
};

export default function PeopleTab() {
  const { t } = useI18n();

  const [members, setMembers] = createSignal([]);
  // D61: a pending ownership claim against the live owner (quorum 2
  // families). Manage-gated read; null when absent or not manageable.
  const [claimInfo, setClaimInfo] = createSignal(null);
  const [claimConfirm, setClaimConfirm] = createSignal(false);
  const [requests, setRequests] = createSignal([]);
  const [stageIntro, setStageIntro] = createSignal("");
  const [malformed, setMalformed] = createSignal(0);
  const [events, setEvents] = createSignal([]);
  const [refusals, setRefusals] = createSignal([]);
  // S4-5: the derived space timeline (newest-first). Admin-gated by the
  // daemon; failures land empty like the per-device feed.
  const [timeline, setTimeline] = createSignal([]);
  const [inviteCode, setInviteCode] = createSignal(null);
  const [inviteRole, setInviteRole] = createSignal("editor");
  const [inviteUsername, setInviteUsername] = createSignal("");
const [verifyT, setVerifyT] = createSignal(null);
const [verifyCode, setVerifyCode] = createSignal(null);
const [verifyErr, setVerifyErr] = createSignal(null);
const [verifyBusy, setVerifyBusy] = createSignal(false);
  // Member-email wave: the admin corrects a member's self-declared email
  // (the field is delta-frozen, so this route is the only writer).
  const [emailEdit, setEmailEdit] = createSignal(null); // member row | null
  let verifyDialogRef;
  let emailDialogRef;
  const [emailDraft, setEmailDraft] = createSignal("");
  const [seatError, setSeatError] = createSignal(null);
  const [busy, setBusy] = createSignal(false);
  // Role change in flight: the member id whose select is disabled.
  const [roleBusyId, setRoleBusyId] = createSignal(null);
  const [yourRole, setYourRole] = createSignal(null);
  // §4.8-3: destructive actions (remove / reset / transfer). Each opens a
  // typed-confirmation modal; the confirm word is the member's name.
  const [pendingAction, setPendingAction] = createSignal(null);
  const [removeOverride, setRemoveOverride] = createSignal(false);
  const [lastRemoveError, setLastRemoveError] = createSignal(null);
  const [resetCode, setResetCode] = createSignal(null);
  const [replaceResult, setReplaceResult] = createSignal(null);
  const [notices, setNotices] = createSignal([]);
  const [transport, setTransport] = createSignal([]);
  const [checkingAccess, setCheckingAccess] = createSignal(false);
  // S3-6 / 4.8: collection access asks (JIT inbox).
  const [asks, setAsks] = createSignal([]);
  const [askBusy, setAskBusy] = createSignal(null);
  // S4-4: the access review report. Computed on demand; nothing persists.
  const [review, setReview] = createSignal(null);
  const [reviewBusy, setReviewBusy] = createSignal(false);
  const [expanded, setExpanded] = createSignal(null);

  async function loadReview() {
    setReviewBusy(true);
    try {
      const data = JSON.parse(await daemon("access.review"));
      setReview(data);
      setExpanded(null);
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setReviewBusy(false);
    }
  }

  function exportReview() {
    const r = review();
    if (!r) return;
    const blob = new Blob([JSON.stringify(r, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `baluard-access-review-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Per-member view rows: grants for the live, exposure for the
  // tombstoned. A tombstoned member's surviving grant rows are the
  // S4-8 summary: credentials to rotate.
  function memberReviewRows(m) {
    const r = review();
    if (!r) return [];
    const tombstoned = !!(m.removed || m.reset);
    const rows = [];
    for (const col of r.collections || []) {
      const g = (col.grants || []).find((g) => g.member_id === m.id);
      if (g)
        rows.push({
          name: col.name,
          access: g.access,
          expires_at: g.expires_at,
          tombstoned,
        });
    }
    return rows;
  }

  async function loadMembers() {
    try {
      const data = JSON.parse(await daemon("members.list"));
      setMembers(Array.isArray(data.members) ? data.members : []);
      setYourRole(data.your_role || null);
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function loadRequests() {
    try {
      const data = JSON.parse(await daemon("requests.list"));
      setRequests(Array.isArray(data.requests) ? data.requests : []);
      setMalformed(data.malformed || 0);
    } catch {
      // Requests are admin-only; a non-admin device sees an error here.
      setRequests([]);
      setMalformed(0);
    }
  }

  async function loadActivity() {
    try {
      const rows = JSON.parse(await daemon("activity.events", { limit: 50 }));
      setEvents(Array.isArray(rows) ? rows : []);
      const ref = JSON.parse(await daemon("activity.refusals", { limit: 20 }));
      setRefusals(Array.isArray(ref) ? ref : []);
    } catch {
      setEvents([]);
      setRefusals([]);
    }
  }

  async function loadTimeline() {
    try {
      const data = JSON.parse(await daemon("activity.timeline", { limit: 100 }));
      setTimeline(Array.isArray(data.timeline) ? data.timeline : []);
    } catch {
      // Non-admin devices are refused; the card just stays empty.
      setTimeline([]);
    }
  }

  async function loadNotices(refreshTransport) {
    if (refreshTransport) setCheckingAccess(true);
    try {
      const data = JSON.parse(
        await daemon("notices.list", { refresh_transport: refreshTransport }),
      );
      setNotices(Array.isArray(data.notices) ? data.notices : []);
      setTransport(Array.isArray(data.transport) ? data.transport : []);
    } catch {
      setNotices([]);
      setTransport([]);
    } finally {
      if (refreshTransport) setCheckingAccess(false);
    }
  }

  async function loadAsks() {
    try {
      const data = JSON.parse(await daemon("collections.requests_list"));
      setAsks(Array.isArray(data.requests) ? data.requests : []);
    } catch {
      // Admin-only; non-admin devices land here.
      setAsks([]);
    }
  }

  async function approveAsk(r, access) {
    setAskBusy(r.request_id);
    try {
      const payload = {
        request_id: r.request_id,
        requester_member_id: r.requester_member_id,
        access,
      };
      await daemon("collections.requests_approve", payload);
      toastSuccess(t("shared.approvedToast", { name: r.requester_name }));
      await Promise.all([loadAsks(), loadMembers()]);
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setAskBusy(null);
    }
  }

  async function denyAsk(r) {
    setAskBusy(r.request_id);
    try {
      await daemon("collections.requests_deny", {
        request_id: r.request_id,
        requester_member_id: r.requester_member_id,
      });
      toastSuccess(t("shared.deniedToast", { name: r.requester_name }));
      await loadAsks();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setAskBusy(null);
    }
  }

  async function saveEmail() {
    const m = emailEdit();
    if (!m || busy()) return;
    setBusy(true);
    try {
      await daemon("members.set_email", {
        member_id: m.id,
        email: emailDraft(),
      });
      toastSuccess(t("people.emailUpdated"));
      setEmailEdit(null);
      await reloadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function openVerify(member) {
    setVerifyT(member);
    setVerifyCode(null);
    setVerifyErr(null);
    try {
      const res = JSON.parse(await daemon("contacts.list", {}));
      const row = (res.contacts || []).find(
        (c) => c.identity_signing_pubkey === member.identity_signing_pubkey,
      );
      if (row) setVerifyCode(row.verification_code);
      else setVerifyErr(t("people.verifyMissing"));
    } catch (e) {
      setVerifyErr(sanitizeError(e, t));
    }
  }

  async function confirmVerify() {
    const m = verifyT();
    if (!m) return;
    setVerifyBusy(true);
    try {
      await daemon("contacts.mark_verified", {
        identity_signing_pubkey: m.identity_signing_pubkey,
      });
      toastSuccess(t("people.verifiedToast"));
      setVerifyT(null);
      await reloadAll();
    } catch (e) {
      setVerifyErr(sanitizeError(e, t));
    } finally {
      setVerifyBusy(false);
    }
  }

  async function changeRole(member, role) {
    if (role === member.role) return; // no-op select flicker
    // Demoting an admin strips their keywraps and admin powers on the
    // next sync — typed confirm, same bar as reset/remove.
    if (member.role === "admin") {
      setPendingAction({ kind: "demote", member, role });
      return;
    }
    setRoleBusyId(member.id);
    try {
      await daemon("members.set_role", { member_id: member.id, role });
      toastSuccess(t("people.roleChanged"));
      await reloadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setRoleBusyId(null);
    }
  }

  async function loadClaim() {
    try {
      const res = JSON.parse(await daemon("members.contest_status"));
      setClaimInfo(res.pending ? res : null);
    } catch {
      // Not a managing device (or locked): no claim surface.
      setClaimInfo(null);
    }
  }

  async function reloadAll() {
    setBusy(true);
    await Promise.all([loadMembers(), loadRequests(), loadActivity(), loadTimeline(), loadNotices(false), loadAsks(), loadClaim()]);
    setBusy(false);
  }

  onSettled(() => void reloadAll());

  const memberName = (id) => {
    const m = members().find((m) => m.id === id);
    return m?.display_name || t("shared.unknownMember");
  };

  async function doCancelClaim() {
    setBusy(true);
    try {
      await daemon("members.contest_cancel");
      toastSuccess(t("people.contestCancelled"));
      await reloadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function doInvite() {
    setBusy(true);
    try {
      const res = JSON.parse(
        await daemon("members.invite", {
          role: inviteRole(),
          transport_username: inviteUsername().trim(),
        }),
      );
      setInviteCode(res.code);
      setSeatError(res.seat_error || null);
      toastSuccess(t("people.inviteCreated"));
      await loadMembers();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function doStage(e) {
    e.preventDefault();
    const code = stageIntro().trim();
    if (!code || busy()) return;
    setBusy(true);
    try {
      await daemon("requests.stage", { intro_code: code });
      setStageIntro("");
      toastSuccess(t("people.staged"));
      await reloadAll();
    } catch (err) {
      toastError(sanitizeError(err, t));
    } finally {
      setBusy(false);
    }
  }

  async function doApprove(reqId) {
    setBusy(true);
    try {
      await daemon("requests.approve", { req_id: reqId });
      toastSuccess(t("people.approved"));
      await reloadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function doDeny(reqId) {
    setBusy(true);
    try {
      await daemon("requests.deny", { req_id: reqId });
      toastSuccess(t("people.denied"));
      await loadRequests();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  function openAction(kind, member) {
    setRemoveOverride(false);
    setLastRemoveError(null);
    setPendingAction({ kind, member });
  }

  function closeAction() {
    setPendingAction(null);
    setRemoveOverride(false);
    setLastRemoveError(null);
  }

  async function doConfirmedAction() {
    const action = pendingAction();
    if (!action) return;
    const id = action.member.id;
    setBusy(true);
    try {
      if (action.kind === "remove") {
        const res = JSON.parse(
          await daemon("members.remove", {
            member_ids: [id],
            offline_override: removeOverride(),
          }),
        );
        const unstruck = res.unstruck_seats || [];
        if (unstruck.length > 0) {
          toastError(
            `${t("people.seatUnstruck")} ${unstruck.join(", ")}`,
          );
        } else {
          toastSuccess(t("people.removedToast"));
        }
      } else if (action.kind === "reset") {
        const res = JSON.parse(await daemon("members.reset", { member_id: id }));
        setResetCode(res.reset_code);
        toastSuccess(t("people.resetDone"));
      } else if (action.kind === "transfer") {
        await daemon("members.transfer", { member_id: id });
        toastSuccess(t("people.transferDone"));
      } else if (action.kind === "demote") {
        await daemon("members.set_role", { member_id: id, role: action.role });
        toastSuccess(t("people.roleChanged"));
      } else if (action.kind === "claim") {
        const selfId = members().find((r) => r.is_self)?.id;
        if (!selfId) {
          toastError(t("errors.unexpected"));
          setBusy(false);
          return;
        }
        await daemon("members.claim", { member_id: selfId });
        toastSuccess(t("people.claimDone"));
      } else if (action.kind === "replace") {
        const res = JSON.parse(
          await daemon("members.replace_device", {
            member_id: id,
            revoke_device: true,
          }),
        );
        setReplaceResult({
          code: res.invite_code || "",
          successor: res.successor || "",
          rotated: res.collections_rotated || 0,
          revokeError: res.revoke_error || null,
          rotationFailed: res.rotation_failed || [],
        });
        toastSuccess(t("people.replaceDone"));
      }
      closeAction();
      await loadMembers();
    } catch (e) {
      const msg = sanitizeError(e, t);
      if (action.kind === "remove" && msg.includes("provider seat removal failed")) {
        // The strike failed (provider down / offline). Surface the
        // override checkbox UNCHECKED — explicit consent, never pre-ticked.
        setLastRemoveError(msg);
        setRemoveOverride(false);
      } else {
        toastError(msg);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="space-y-6">
      {/* D61: a pending ownership claim against the live owner. The
          window is the notice; the owner (and only the owner) can cancel
          it before it matures. */}
      <Show when={claimInfo()}>
        <section data-testid="claim-card" class="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
          <h3 class="text-sm font-bold text-[var(--color-text)] mb-1">{t("people.contestTitle")}</h3>
          <p class="text-xs text-[var(--color-text)] mb-1">
            {t("people.contestBody")
              .replace("{claimant}", memberName(claimInfo().new_owner_id))
              .replace("{date}", new Date(claimInfo().window_until * 1000).toLocaleDateString())}
          </p>
          <p class="text-xs text-[var(--color-muted)] mb-3">{t("people.contestHint")}</p>
          <Show when={yourRole() === "owner"}>
            <button
              data-testid="claim-cancel"
              onClick={() => setClaimConfirm(true)}
              class="text-xs font-semibold px-3 py-1.5 rounded-lg border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 transition-all cursor-pointer"
            >
              {t("people.contestCancel")}
            </button>
          </Show>
        </section>
      </Show>

      {/* Reset code: one-time, hand back to the member */}
      <Show when={resetCode()}>
        <section class="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
          <h3 class="text-sm font-bold text-[var(--color-text)] mb-1">{t("people.resetCodeTitle")}</h3>
          <p class="text-xs text-[var(--color-muted)] mb-3">{t("people.resetCodeBody")}</p>
          <div class="flex items-center gap-2">
            <code class="text-xs text-[var(--color-text)] break-all flex-1 font-mono">{resetCode()}</code>
            <CopyButton value={resetCode()} />
          </div>
        </section>
      </Show>

      {/* Replace-device result: the replacement invite is one-time. */}
      <Show when={replaceResult()}>
        <section class="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
          <h3 class="text-sm font-bold text-[var(--color-text)] mb-1">{t("people.replaceResultTitle")}</h3>
          <p class="text-xs text-[var(--color-muted)] mb-3">{t("people.replaceResultBody")}</p>
          <div class="flex items-center gap-2">
            <code class="text-xs text-[var(--color-text)] break-all flex-1 font-mono">{replaceResult().code}</code>
            <CopyButton value={replaceResult().code} />
          </div>
          <p class="text-[10px] text-[var(--color-muted)] mt-2">
            {t("people.replaceSuccessor")} {replaceResult().successor} · {t("people.replaceRotated")}: {replaceResult().rotated}
          </p>
          <Show
            when={replaceResult().revokeError || replaceResult().rotationFailed.length > 0}
          >
            <div class="mt-2 text-[10px] text-amber-500">
              <p>{t("people.replaceWarn")}</p>
              <Show when={replaceResult().revokeError}>
                <p>{replaceResult().revokeError}</p>
              </Show>
              <For each={replaceResult().rotationFailed}>
                {(f) => <p>{f}</p>}
              </For>
            </div>
          </Show>
        </section>
      </Show>

      {/* Screen 6: notices — things that need the owner's attention. */}
      <Show when={notices().length > 0}>
        <section class="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
          <h3 class="text-sm font-bold text-[var(--color-text)] mb-2">{t("notices.title")}</h3>
          <ul class="space-y-1.5">
            <For each={notices()}>
              {(n) => (
                <li class="text-xs text-[var(--color-text)]">
                  {t(`notices.${n.kind}Text`)
                    .replace("{name}", n.name || "")
                    .replace("{count}", n.count != null ? String(n.count) : "")}
                </li>
              )}
            </For>
          </ul>
        </section>
      </Show>

      {/* Invite */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("people.inviteTitle")}</h3>
        <div class="flex items-center gap-2">
          <select
            value={inviteRole()}
            onChange={(e) => setInviteRole(e.currentTarget.value)}
            class="p-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] text-xs text-[var(--color-text)]"
          >
            <option value="editor">{t("people.roleEditor")}</option>
            <option value="viewer">{t("people.roleViewer")}</option>
            <option value="admin">{t("people.roleAdmin")}</option>
          </select>
          <button
            onClick={doInvite}
            disabled={busy()}
            class="px-3 py-2 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
          >
            {t("people.inviteButton")}
          </button>
        </div>
        <input
          value={inviteUsername()}
          onInput={(e) => setInviteUsername(e.currentTarget.value)}
          maxlength="128"
          class="w-full mt-2 px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
          placeholder={t("people.usernamePlaceholder")}
        />
        <Show when={inviteCode()}>
          <div class="mt-3 p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
            <p class="text-[10px] text-[var(--color-muted)] mb-1">{t("people.inviteHint")}</p>
            <div class="flex items-center gap-2">
              <code class="text-xs text-[var(--color-text)] break-all flex-1 font-mono">
                {inviteCode()}
              </code>
              <CopyButton value={inviteCode()} />
            </div>
          </div>
          <Show when={seatError()}>
            <p class="mt-2 text-[10px] text-amber-500">
              {t("people.seatErrorPrefix")} {seatError()}
            </p>
          </Show>
        </Show>
      </section>

      {/* Requests */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("people.requestsTitle")}</h3>
        <form onSubmit={doStage} class="flex gap-2 mb-3">
          <input
            type="text"
            value={stageIntro()}
            onInput={(e) => setStageIntro(e.currentTarget.value)}
            placeholder={t("people.stageIntro")}
            disabled={busy()}
            class="flex-1 px-2.5 py-1.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-xs text-[var(--color-text)] placeholder:text-[var(--color-muted)] outline-none focus:border-[var(--color-primary)]"
          />
          <button
            type="submit"
            disabled={busy() || !stageIntro().trim()}
            class="px-3 py-1.5 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] text-[10px] font-bold disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
          >
            {t("people.stageBtn")}
          </button>
        </form>
        <Show
          when={requests().length > 0}
          fallback={<p class="text-xs text-[var(--color-muted)]">{t("people.requestsEmpty")}</p>}
        >
          <ul class="space-y-2">
            <For each={requests()}>
              {(r) => (
                <li class="flex items-center gap-2 p-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                  <div class="flex-1 min-w-0">
                    <div class="text-xs font-bold text-[var(--color-text)] truncate">
                      {r.display_name}
                    </div>
                    <Show when={r.email}>
                      <div class="text-[10px] text-[var(--color-muted)] truncate">{r.email}</div>
                    </Show>
                  </div>
                  <Show
                    when={r.secret_ok}
                    fallback={
                      <span class="text-[10px] font-bold text-red-400 border border-red-400/30 rounded-full px-2 py-0.5">
                        {t("people.codeMismatch")}
                      </span>
                    }
                  >
                    <span class="text-[10px] font-bold text-green-400 border border-green-400/30 rounded-full px-2 py-0.5">
                      {t("people.codeOk")}
                    </span>
                  </Show>
                  <button
                    onClick={() => doApprove(r.req_id)}
                    disabled={busy()}
                    class="px-2.5 py-1 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] text-[10px] font-bold disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                  >
                    {t("people.approve")}
                  </button>
                  <button
                    onClick={() => doDeny(r.req_id)}
                    disabled={busy()}
                    class="px-2.5 py-1 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                  >
                    {t("people.deny")}
                  </button>
                </li>
              )}
            </For>
          </ul>
        </Show>
        <Show when={malformed() > 0}>
          <p class="mt-2 text-[10px] text-[var(--color-muted)]">
            {t("people.malformedCount").replace("{n}", malformed())}
          </p>
        </Show>
      </section>

      {/* S3-6 / 4.8: collection access asks */}
      <Show when={asks().length > 0}>
        <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
          <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("shared.asksTitle")}</h3>
          <ul class="space-y-2">
            <For each={asks()}>
              {(r) => (
                <li class="p-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-xs font-bold text-[var(--color-text)]">
                      {r.requester_name}
                    </span>
                    <span class="text-[10px] text-[var(--color-muted)]">
                      {t("shared.asksFor")} <span class="font-bold">{r.collection_name}</span>
                      {" · "}
                      {r.access === "write" ? t("shared.writeAccess") : t("shared.readAccess")}
                    </span>
                    <div class="ml-auto flex items-center gap-2">
                      <button
                        disabled={askBusy() === r.request_id}
                        onClick={() => void approveAsk(r, "read")}
                        class="text-[10px] font-bold px-2 py-1 rounded-md border border-[var(--color-border)] text-[var(--color-text)] hover:border-[var(--color-text)] disabled:opacity-50 cursor-pointer"
                      >
                        {t("shared.grantRead")}
                      </button>
                      <button
                        disabled={askBusy() === r.request_id}
                        onClick={() => void approveAsk(r, "write")}
                        class="text-[10px] font-bold px-2 py-1 rounded-md border border-green-500/30 text-green-400 hover:border-green-400 disabled:opacity-50 cursor-pointer"
                      >
                        {t("shared.grantWrite")}
                      </button>
                      <button
                        disabled={askBusy() === r.request_id}
                        onClick={() => void denyAsk(r)}
                        class="text-[10px] font-bold px-2 py-1 rounded-md border border-red-400/30 text-red-400 hover:border-red-400 disabled:opacity-50 cursor-pointer"
                      >
                        {t("shared.deny")}
                      </button>
                    </div>
                  </div>
                  <Show when={r.note}>
                    <p class="text-[10px] text-[var(--color-muted)] mt-1.5 italic">“{r.note}”</p>
                  </Show>
                </li>
              )}
            </For>
          </ul>
        </section>
      </Show>

      {/* Members */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <div class="mb-3">
          <h3 class="text-sm font-bold text-[var(--color-text)]">{t("people.membersTitle")}</h3>
          <p class="text-xs leading-relaxed text-[var(--color-muted)] mt-0.5">{t("people.sharingSubtitle")}</p>
        </div>
        <ul class="space-y-2">
          <For each={members()}>
            {(m) => (
              <li class="flex items-center gap-2 p-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]" data-testid="member-row">
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-bold text-[var(--color-text)] truncate">
                    {m.display_name}
                  </div>
                  <Show when={m.email}>
                    <div class="text-[10px] text-[var(--color-muted)] truncate">{m.email}</div>
                  </Show>
                </div>
                <Show when={m.reset || m.removed}>
                  <span class="text-[10px] font-bold text-red-400 border border-red-400/30 rounded-full px-2 py-0.5">
                    {m.removed ? t("people.stateRemoved") : t("people.stateReset")}
                  </span>
                </Show>
                <span
                  class={`text-[10px] font-bold border rounded-full px-2 py-0.5 ${
                    ROLE_STYLES[m.role] || ROLE_STYLES.viewer
                  }`}
                >
                  {t(`people.role_${m.role}`)}
                </span>
                {/* Self-trust is the owner's own anchor identity — the role
                    chip already says Owner, and the dial measures how well
                    YOU verified THEM, which does not apply to the owner
                    row. Rendering nothing avoids the "You" inversion. */}
                <Show when={m.trust !== "self"}>
                  <span class="text-[10px] text-[var(--color-muted)]">
                    {t(TRUST_KEYS[m.trust] || "people.trustChannel")}
                  </span>
                </Show>
                {/* Member-email wave: the admin corrects the frozen field. */}
                <Show when={!m.reset && !m.removed}>
                  <button
                    onClick={() => {
                      setEmailEdit(m);
                      setEmailDraft(m.email || "");
                    }}
                    disabled={busy()}
                    class="px-2 py-1 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                  >
                    {t("people.editEmail")}
                  </button>
                </Show>
                {/* §4.8-3: destructive actions — never on the viewer's own
                    row, never on tombstoned rows. Transfer belongs on the
                    TARGET row and only when the viewer is the owner (the
                    owner initiates transfers to a member). §13: an ADMIN
                    viewing the OWNER row sees exactly one action, Take
                    Over — contextual labels so nobody faces both. */}
                <Show when={!m.is_self && !m.reset && !m.removed}>
                  <Show when={yourRole() === "owner" && m.role !== "owner"}>
                    <button
                      onClick={() => openAction("transfer", m)}
                      disabled={busy()}
                      class="px-2 py-1 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                    >
                      {t("people.transfer")}
                    </button>
                  </Show>
                  <Show when={yourRole() === "admin" && m.role === "owner"}>
                    <button
                      onClick={() => openAction("claim", m)}
                      disabled={busy()}
                      class="px-2 py-1 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                    >
                      {t("people.claim")}
                    </button>
                  </Show>
                  <Show when={yourRole() === "owner" || yourRole() === "admin"}>
                    <button
                      onClick={() => openAction("replace", m)}
                      disabled={busy()}
                      class="px-2 py-1 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                    >
                      {t("people.replaceBtn")}
                    </button>
                  </Show>
                  <Show
                    when={
                      (yourRole() === "owner" || yourRole() === "admin") &&
                      m.role !== "owner" &&
                      m.identity_signing_pubkey
                    }
                  >
                    <button
                      onClick={() => openVerify(m)}
                      disabled={busy()}
                      title={t("people.verifyDesc")}
                      class="px-2 py-1 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                    >
                      {t("people.actionVerify")}
                    </button>
                  </Show>
                  <Show when={(yourRole() === "owner" || yourRole() === "admin") && m.role !== "owner"}>
                    <select
                      data-testid="role-select"
                      value={m.role}
                      disabled={busy() || roleBusyId() === m.id}
                      onChange={(e) => changeRole(m, e.currentTarget.value)}
                      class="px-1.5 py-1 rounded-lg border border-[var(--color-border)] bg-transparent text-[10px] font-bold text-[var(--color-muted)] cursor-pointer disabled:opacity-50"
                      aria-label={t("people.roleSelectLabel")}
                    >
                      <option value="editor">{t("people.roleEditor")}</option>
                      <option value="viewer">{t("people.roleViewer")}</option>
                      <option value="admin">{t("people.roleAdmin")}</option>
                    </select>
                  </Show>
                  <Show when={yourRole() === "owner" || yourRole() === "admin"}>
                    <button
                      onClick={() => openAction("reset", m)}
                      disabled={busy()}
                      class="px-2 py-1 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                    >
                      {t("people.reset")}
                    </button>
                    {/* §13 review F2: removing the OWNER row fails at the
                        core (transfer or claim first) — never render the
                        dead button. */}
                    <Show when={m.role !== "owner"}>
                      <button
                        onClick={() => openAction("remove", m)}
                        disabled={busy()}
                        class="px-2 py-1 rounded-lg border border-red-400/30 text-[10px] font-bold text-red-400 hover:bg-red-500/10 disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                      >
                        {t("people.remove")}
                      </button>
                    </Show>
                  </Show>
                </Show>
              </li>
            )}
          </For>
        </ul>
        <Show when={members().length === 0}>
          <p class="text-xs text-[var(--color-muted)]">{t("people.membersLegacy")}</p>
        </Show>
      </section>

      {/* Access review (S4-4): who can see what, computed on demand.
          Owner/Admin plus the legacy founder (yourRole null); the
          daemon stays the validator. */}
      <Show
        when={
          yourRole() === "owner" ||
          yourRole() === "admin" ||
          yourRole() === null
        }
      >
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-bold text-[var(--color-text)]">
            {t("people.reviewTitle")}
          </h3>
          <div class="flex items-center gap-2">
            <Show when={review()}>
              <button
                onClick={exportReview}
                class="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] hover:bg-[var(--color-sidebar)] text-[10px] font-bold text-[var(--color-text)] transition-all cursor-pointer shadow-sm"
              >
                {t("people.reviewExport")}
              </button>
            </Show>
            <button
              onClick={loadReview}
              disabled={reviewBusy()}
              class="px-3 py-1.5 rounded-lg bg-[var(--color-primary)]/10 border border-[var(--color-primary)]/30 hover:bg-[var(--color-primary)]/20 text-[10px] font-bold text-[var(--color-primary)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed transition-all shadow-sm"
            >
              {reviewBusy() ? t("people.reviewRunning") : t("people.reviewRun")}
            </button>
          </div>
        </div>
        <Show
          when={review()}
          fallback={
            <p class="text-xs text-[var(--color-muted)]">
              {t("people.reviewHint")}
            </p>
          }
        >
          <Show when={(review().exposure || []).length > 0}>
            <div class="mb-3 p-3 rounded-lg bg-red-500/5 border border-red-400/30">
              <p class="text-[10px] font-bold text-red-400 uppercase mb-1">
                {t("people.reviewExposureTitle")}
              </p>
              <For each={review().exposure}>
                {(ex) => (
                  <p class="text-xs text-[var(--color-text)]">
                    {(ex.collections || []).length > 0
                      ? t("people.reviewExposureItems", {
                          name: ex.display_name,
                          count: ex.collections.length,
                          names: ex.collections.map((c) => c.name).join(", "),
                        })
                      : t("people.reviewExposureNone", {
                          name: ex.display_name,
                        })}
                  </p>
                )}
              </For>
            </div>
          </Show>
          <ul class="space-y-1.5">
            <For each={review().members || []}>
              {(m) => {
                const rows = () => memberReviewRows(m);
                const tombstoned = !!(m.removed || m.reset);
                return (
                  <li class="rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                    <button
                      onClick={() =>
                        setExpanded(expanded() === m.id ? null : m.id)
                      }
                      class="w-full flex items-center gap-2 p-2.5 text-left"
                    >
                      <div class="flex-1 min-w-0">
                        <div
                          class={`text-xs font-bold truncate ${
                            tombstoned
                              ? "text-[var(--color-muted)] line-through"
                              : "text-[var(--color-text)]"
                          }`}
                        >
                          {m.display_name}
                        </div>
                        <Show when={m.email}>
                          <div class="text-[10px] text-[var(--color-muted)] truncate">{m.email}</div>
                        </Show>
                      </div>
                      <span class="text-[10px] text-[var(--color-muted)]">
                        {t("people.reviewCollections", {
                          count: rows().length,
                        })}
                      </span>
                      <span class="text-[10px] text-[var(--color-muted)]">
                        {expanded() === m.id ? "▾" : "▸"}
                      </span>
                    </button>
                    <Show when={expanded() === m.id}>
                      <div class="px-3 pb-2.5 space-y-1">
                        <Show
                          when={rows().length > 0}
                          fallback={
                            <p class="text-xs text-[var(--color-muted)]">
                              {tombstoned
                                ? t("people.reviewKeptBytes")
                                : t("people.reviewNoAccess")}
                            </p>
                          }
                        >
                          <For each={rows()}>
                            {(row) => (
                              <div class="flex items-center gap-2 text-xs">
                                <span class="text-[var(--color-text)] flex-1 truncate">
                                  {row.name}
                                </span>
                                <span class="text-[10px] font-bold text-[var(--color-muted)] uppercase">
                                  {row.access}
                                </span>
                                <span class="text-[10px] text-[var(--color-muted)]">
                                  {row.expires_at
                                    ? t("people.reviewExpires")
                                    : t("people.reviewNoExpiry")}
                                </span>
                              </div>
                            )}
                          </For>
                        </Show>
                      </div>
                    </Show>
                  </li>
                );
              }}
            </For>
          </ul>
          <p class="mt-2 text-[10px] text-[var(--color-muted)]">
            {t("people.reviewGenerated", {
              time: new Date((review().generated_at || 0) * 1000).toLocaleString(),
            })}
          </p>
        </Show>
      </section>
      </Show>

      {/* Activity */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-bold text-[var(--color-text)]">{t("people.activityTitle")}</h3>
          <div class="flex items-center gap-2">
            <button
              onClick={() => loadNotices(true)}
              disabled={busy() || checkingAccess()}
              class="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] hover:bg-[var(--color-sidebar)] text-[10px] font-bold text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed transition-all shadow-sm"
            >
              {checkingAccess() ? t("notices.checkingAccess") : t("notices.checkAccess")}
            </button>
            <button
              onClick={reloadAll}
              disabled={busy()}
              class="px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] hover:bg-[var(--color-sidebar)] text-[10px] font-bold text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed transition-all shadow-sm"
            >
              {t("people.refresh")}
            </button>
          </div>
        </div>
        <Show when={transport().length > 0}>
          <div class="mb-3 p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
            <p class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-1.5">
              {t("notices.transportTitle")}
            </p>
            <ul class="space-y-1">
              <For each={transport()}>
                {(row) => (
                  <li class="text-xs text-[var(--color-text)] flex gap-2 items-center">
                    <span class="font-mono text-[var(--color-muted)]">{row.username}</span>
                    <span
                      class={`text-[10px] font-bold border rounded-full px-2 py-0.5 ${
                        row.status === "active"
                          ? "text-green-400 border-green-400/30"
                          : "text-amber-500 border-amber-500/30"
                      }`}
                    >
                      {t(`notices.status_${row.status.split(":")[0]}`)}
                    </span>
                    <Show when={row.reinvited}>
                      <span class="text-[10px] font-bold border rounded-full px-2 py-0.5 text-blue-400 border-blue-400/30">
                        {t("notices.reinvited")}
                      </span>
                    </Show>
                  </li>
                )}
              </For>
            </ul>
          </div>
        </Show>
        <Show
          when={events().length > 0}
          fallback={<p class="text-xs text-[var(--color-muted)]">{t("people.activityEmpty")}</p>}
        >
          <ul class="space-y-1.5">
            <For each={events()}>
              {(e) => (
                <li class="text-xs text-[var(--color-text)] flex gap-2">
                  <span class="text-[10px] text-[var(--color-muted)] font-mono shrink-0">
                    {new Date(e.at * 1000).toLocaleString()}
                  </span>
                  <span class="flex-1">{e.detail}</span>
                </li>
              )}
            </For>
          </ul>
        </Show>
        <Show when={refusals().length > 0}>
          <div class="mt-3 pt-3 border-t border-[var(--color-border)]">
            <h4 class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-1.5">
              {t("people.refusalsTitle")}
            </h4>
            <ul class="space-y-1">
              <For each={refusals()}>
                {(line) => <li class="text-[10px] text-red-400 font-mono break-all">{line}</li>}
              </For>
            </ul>
          </div>
        </Show>
      </section>

      {/* S4-5: space timeline (derived from signed history) */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("people.timelineTitle")}</h3>
        <Show
          when={timeline().length > 0}
          fallback={<p class="text-xs text-[var(--color-muted)]">{t("people.timelineEmpty")}</p>}
        >
          <ul class="space-y-2">
            <For each={timeline()}>
              {(e) => (
                <li class="text-xs text-[var(--color-text)] flex gap-2 items-baseline">
                  <span class="text-[10px] text-[var(--color-muted)] font-mono shrink-0">
                    {new Date(e.at * 1000).toLocaleString()}
                  </span>
                  <span class="font-bold shrink-0">{e.actor}</span>
                  <span class="text-[10px] font-bold border rounded-full px-2 py-0.5 text-[var(--color-primary)] border-[var(--color-primary)]/30 shrink-0">
                    {t(TL_KINDS[e.kind] || e.kind)}
                  </span>
                  <span class="flex-1">{e.detail}</span>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </section>

      {/* §4.8-3: destructive action confirmations */}
      <Show when={pendingAction()}>
        <TypedConfirmModal
          show
          title={t(`people.${pendingAction().kind}Title`)}
          body={t(`people.${pendingAction().kind}Body`).replace(
            "{name}",
            pendingAction().member.display_name,
          )}
          confirmWord={pendingAction().member.display_name}
          confirmLabel={t(`people.${pendingAction().kind}Confirm`)}
          danger={pendingAction().kind !== "transfer" && pendingAction().kind !== "claim"}
          extra={
            <Show when={pendingAction().kind === "remove" && lastRemoveError()}>
              <div class="mb-3 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30">
                <p class="text-[10px] text-amber-500 mb-2">{lastRemoveError()}</p>
                <label class="flex items-center gap-2 text-[10px] text-[var(--color-text)] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={removeOverride()}
                    onChange={(e) => setRemoveOverride(e.currentTarget.checked)}
                  />
                  {t("people.overrideLabel")}
                </label>
              </div>
            </Show>
          }
          onConfirm={doConfirmedAction}
          onClose={closeAction}
        />
      </Show>

      {/* Level 2 contact check: compare codes out-of-band, then confirm. */}
      <Show when={verifyT()}>
        <div class="fixed inset-0 z-[120] bg-black/60 flex items-center justify-center p-4">
          <FocusTrap containerRef={() => verifyDialogRef} onEscape={() => setVerifyT(null)} />
          <div
            ref={(el) => (verifyDialogRef = el)}
            role="dialog"
            aria-modal="true"
            aria-labelledby="verify-code-title"
            class="w-full max-w-sm rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
            <h3 class="text-sm font-bold mb-2">
              {t("people.verifyTitle").replace("{name}", verifyT().display_name)}
            </h3>
            <p class="text-[10px] text-[var(--color-muted)] mb-3">{t("people.verifyDesc")}</p>
            <Show
              when={verifyCode()}
              fallback={
                <Show when={verifyErr()}>
                  <p class="text-[10px] text-red-400">{verifyErr()}</p>
                </Show>
              }
            >
              <p class="font-mono text-base tracking-widest mb-3">{verifyCode()}</p>
            </Show>
            <div class="flex justify-end gap-2">
              <button
                onClick={() => setVerifyT(null)}
                class="px-3 py-1.5 rounded-lg border border-[var(--color-border)] text-xs font-bold cursor-pointer"
              >
                {t("common.cancel")}
              </button>
              <button
                onClick={confirmVerify}
                disabled={verifyBusy() || !verifyCode()}
                class="px-3 py-1.5 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
              >
                {t("people.verifyConfirm")}
              </button>
            </div>
          </div>
        </div>
      </Show>

      {/* Member-email wave: the admin edits the frozen email. A simple
          dialog — no typed confirm needed for advisory data. */}
      <Show when={emailEdit()}>
        <div class="fixed inset-0 z-[100] flex items-center justify-center bg-black/50">
          <FocusTrap containerRef={() => emailDialogRef} onEscape={() => setEmailEdit(null)} />
          <div
            ref={(el) => (emailDialogRef = el)}
            role="dialog"
            aria-modal="true"
            aria-labelledby="email-edit-title"
            class="w-[380px] max-w-[90vw] p-4 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)]"
          >
            <h3 id="email-edit-title" class="text-sm font-bold text-[var(--color-text)] mb-1">
              {t("people.editEmail")}
            </h3>
            <p class="text-[10px] text-[var(--color-muted)] mb-3">
              {t("people.editEmailHint", { name: emailEdit().display_name })}
            </p>
            <input
              value={emailDraft()}
              onInput={(e) => setEmailDraft(e.currentTarget.value)}
              maxlength="254"
              class="w-full px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
              placeholder="name@example.com"
            />
            <div class="flex justify-end gap-2 mt-3">
              <button
                onClick={() => setEmailEdit(null)}
                class="px-3 py-2 rounded-lg border border-[var(--color-border)] text-xs font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
              >
                {t("common.cancel")}
              </button>
              <button
                onClick={saveEmail}
                disabled={busy()}
                class="px-3 py-2 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
              >
                {t("people.emailSave")}
              </button>
            </div>
          </div>
        </div>
      </Show>

      <ConfirmModal
        show={claimConfirm()}
        idPrefix="claim-cancel"
        title={t("people.contestCancelTitle")}
        body={t("people.contestCancelBody")}
        confirmLabel={t("people.contestCancel")}
        confirmVariant="danger"
        onConfirm={doCancelClaim}
        onClose={() => setClaimConfirm(false)}
      />
    </div>
  );
}
