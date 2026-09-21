import { createSignal, onMount, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import CopyButton from "./CopyButton.jsx";
import TypedConfirmModal from "./TypedConfirmModal.jsx";

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

export default function PeopleTab() {
  const { t } = useI18n();

  const [members, setMembers] = createSignal([]);
  const [requests, setRequests] = createSignal([]);
  const [malformed, setMalformed] = createSignal(0);
  const [events, setEvents] = createSignal([]);
  const [refusals, setRefusals] = createSignal([]);
  const [inviteCode, setInviteCode] = createSignal(null);
  const [inviteRole, setInviteRole] = createSignal("editor");
  const [inviteUsername, setInviteUsername] = createSignal("");
  const [seatError, setSeatError] = createSignal(null);
  const [busy, setBusy] = createSignal(false);
  const [yourRole, setYourRole] = createSignal(null);
  // §4.8-3: destructive actions (remove / reset / transfer). Each opens a
  // typed-confirmation modal; the confirm word is the member's name.
  const [pendingAction, setPendingAction] = createSignal(null);
  const [removeOverride, setRemoveOverride] = createSignal(false);
  const [lastRemoveError, setLastRemoveError] = createSignal(null);
  const [resetCode, setResetCode] = createSignal(null);
  const [notices, setNotices] = createSignal([]);
  const [transport, setTransport] = createSignal([]);
  const [checkingAccess, setCheckingAccess] = createSignal(false);

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

  async function reloadAll() {
    setBusy(true);
    await Promise.all([loadMembers(), loadRequests(), loadActivity(), loadNotices(false)]);
    setBusy(false);
  }

  onMount(reloadAll);

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
            class="px-3 py-2 rounded-lg bg-[var(--color-primary)] text-white text-xs font-bold disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
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
        <Show
          when={requests().length > 0}
          fallback={<p class="text-xs text-[var(--color-muted)]">{t("people.requestsEmpty")}</p>}
        >
          <ul class="space-y-2">
            <For each={requests()}>
              {(r) => (
                <li class="flex items-center gap-2 p-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                  <span class="text-xs font-bold text-[var(--color-text)] flex-1 truncate">
                    {r.display_name}
                  </span>
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
                    class="px-2.5 py-1 rounded-lg bg-green-600 text-white text-[10px] font-bold disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
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

      {/* Members */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("people.membersTitle")}</h3>
        <ul class="space-y-2">
          <For each={members()}>
            {(m) => (
              <li class="flex items-center gap-2 p-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                <span class="text-xs font-bold text-[var(--color-text)] flex-1 truncate">
                  {m.display_name}
                </span>
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
                {/* §4.8-3: destructive actions — never on the viewer's own
                    row, never on tombstoned rows. Transfer belongs on the
                    TARGET row and only when the viewer is the owner (the
                    owner initiates transfers to a member). */}
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
                  <Show when={yourRole() === "owner" || yourRole() === "admin"}>
                    <button
                      onClick={() => openAction("reset", m)}
                      disabled={busy()}
                      class="px-2 py-1 rounded-lg border border-[var(--color-border)] text-[10px] font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                    >
                      {t("people.reset")}
                    </button>
                    <button
                      onClick={() => openAction("remove", m)}
                      disabled={busy()}
                      class="px-2 py-1 rounded-lg border border-red-400/30 text-[10px] font-bold text-red-400 hover:bg-red-500/10 disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
                    >
                      {t("people.remove")}
                    </button>
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

      {/* Activity */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-bold text-[var(--color-text)]">{t("people.activityTitle")}</h3>
          <div class="flex items-center gap-3">
            <button
              onClick={() => loadNotices(true)}
              disabled={busy() || checkingAccess()}
              class="text-[10px] font-bold text-[var(--color-primary)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              {checkingAccess() ? t("notices.checkingAccess") : t("notices.checkAccess")}
            </button>
            <button
              onClick={reloadAll}
              disabled={busy()}
              class="text-[10px] font-bold text-[var(--color-primary)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
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
          danger={pendingAction().kind !== "transfer"}
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
    </div>
  );
}
