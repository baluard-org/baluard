import { createSignal, onMount, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import CopyButton from "./CopyButton.jsx";

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

  async function loadMembers() {
    try {
      const rows = JSON.parse(await daemon("members.list"));
      setMembers(Array.isArray(rows) ? rows : []);
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

  async function reloadAll() {
    setBusy(true);
    await Promise.all([loadMembers(), loadRequests(), loadActivity()]);
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

  return (
    <div class="space-y-6">
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
          <button
            onClick={reloadAll}
            disabled={busy()}
            class="text-[10px] font-bold text-[var(--color-primary)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
          >
            {t("people.refresh")}
          </button>
        </div>
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
    </div>
  );
}
