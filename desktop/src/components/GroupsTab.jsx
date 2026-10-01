import { createSignal, onSettled, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import { Button } from "./Primitives.jsx";
import ConfirmModal from "./ConfirmModal.jsx";

// S4-2: the admin Groups surface — a named list of people a collection
// can be granted to at once. Plain language: a group is a department;
// grant the department and everyone in it gets access. Leaving the
// group quietly re-keys it (what the leaver could open, they keep;
// nothing new opens for them).

export default function GroupsTab() {
  const { t } = useI18n();

  const [groups, setGroups] = createSignal([]);
  const [members, setMembers] = createSignal([]);
  const [newName, setNewName] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [openFor, setOpenFor] = createSignal(null); // group id open for member editing
  const [addMember, setAddMember] = createSignal("");
  const [renameFor, setRenameFor] = createSignal(null);
  const [deleteTarget, setDeleteTarget] = createSignal(null);

  async function loadAll() {
    try {
      const g = JSON.parse(await daemon("groups.list"));
      setGroups(Array.isArray(g.groups) ? g.groups : []);
    } catch {
      setGroups([]);
    }
    try {
      const m = JSON.parse(await daemon("members.list"));
      setMembers(Array.isArray(m.members) ? m.members : []);
    } catch {
      setMembers([]);
    }
  }

  onSettled(() => void loadAll());

  function memberName(id) {
    return members().find((m) => m.id === id)?.display_name || id.slice(0, 8);
  }

  async function run(fn) {
    if (busy()) return;
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  const createGroup = () =>
    run(async () => {
      const name = newName().trim();
      if (!name) return;
      await daemon("groups.create", { name });
      toastSuccess(t("groups.createdToast", { name }));
      setNewName("");
      await loadAll();
    });

  const renameGroup = () =>
    run(async () => {
      const target = renameFor();
      if (!target) return;
      await daemon("groups.rename", { id: target.id, name: target.name.trim() });
      setRenameFor(null);
      await loadAll();
    });

  const deleteGroup = () =>
    run(async () => {
      const target = deleteTarget();
      if (!target) return;
      await daemon("groups.delete", { id: target.id });
      toastSuccess(t("groups.deletedToast", { name: target.name }));
      setDeleteTarget(null);
      await loadAll();
    });

  const addMemberTo = (g) =>
    run(async () => {
      if (!addMember()) return;
      await daemon("groups.member_add", { id: g.id, member_id: addMember() });
      setAddMember("");
      await loadAll();
    });

  const removeMember = (g, memberId) =>
    run(async () => {
      await daemon("groups.member_remove", { id: g.id, member_id: memberId });
      await loadAll();
    });

  return (
    <div class="space-y-4">
      <p class="text-xs text-[var(--color-muted)]">{t("groups.subtitle")}</p>

      {/* Create */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-2">{t("groups.createTitle")}</h3>
        <div class="flex gap-2">
          <input
            value={newName()}
            onInput={(e) => setNewName(e.currentTarget.value)}
            placeholder={t("groups.namePlaceholder")}
            class="flex-1 text-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-2 py-1.5 text-[var(--color-text)] placeholder-[var(--color-muted)] outline-none focus:border-[var(--color-primary)]"
          />
          <Button onClick={() => void createGroup()} disabled={busy()}>
            {t("groups.createButton")}
          </Button>
        </div>
      </section>

      {/* List */}
      <Show when={groups().length > 0}>
        <section>
          <ul class="space-y-2">
            <For each={groups()}>
              {(g) => (
                <li class="p-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-xs font-bold text-[var(--color-text)] flex-1 truncate">{g.name}</span>
                    <span class="text-[10px] font-mono text-[var(--color-muted)]">
                      {g.members.length} {t("groups.memberCount")}
                    </span>
                    <button
                      onClick={() => setOpenFor(openFor() === g.id ? null : g.id)}
                      class="text-[10px] font-bold px-2 py-1 rounded-md border border-[var(--color-border)] text-[var(--color-text)] hover:border-[var(--color-text)] cursor-pointer"
                    >
                      {t("groups.manageMembers")}
                    </button>
                    <button
                      onClick={() => setRenameFor({ id: g.id, name: g.name })}
                      class="text-[10px] font-bold px-2 py-1 rounded-md border border-[var(--color-border)] text-[var(--color-muted)] hover:border-[var(--color-text)] hover:text-[var(--color-text)] cursor-pointer"
                    >
                      {t("groups.rename")}
                    </button>
                    <button
                      onClick={() => setDeleteTarget(g)}
                      class="text-[10px] font-bold px-2 py-1 rounded-md border border-red-400/30 text-red-400 hover:border-red-400 cursor-pointer"
                    >
                      {t("groups.delete")}
                    </button>
                  </div>
                  <Show when={openFor() === g.id}>
                    <div class="mt-3 pt-3 border-t border-[var(--color-border)] space-y-2">
                      <For each={g.members}>
                        {(mid) => (
                          <div class="flex items-center gap-2 text-xs">
                            <span class="flex-1 truncate text-[var(--color-text)]">{memberName(mid)}</span>
                            <button
                              disabled={busy()}
                              onClick={() => void removeMember(g, mid)}
                              class="text-[10px] font-bold text-red-400 hover:text-red-300 disabled:opacity-50 cursor-pointer"
                            >
                              {t("groups.remove")}
                            </button>
                          </div>
                        )}
                      </For>
                      <div class="flex gap-2 items-center pt-1">
                        <select
                          class="text-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-2 py-1.5 text-[var(--color-text)] cursor-pointer"
                          value={addMember()}
                          onChange={(e) => setAddMember(e.currentTarget.value)}
                        >
                          <option value="">{t("collections.pickMember")}</option>
                          <For each={members().filter((m) => !m.removed && !m.reset && !g.members.includes(m.id))}>
                            {(m) => (
                              <option value={m.id}>
                                {m.email ? `${m.display_name} · ${m.email}` : m.display_name}
                              </option>
                            )}
                          </For>
                        </select>
                        <Button onClick={() => void addMemberTo(g)} disabled={busy()}>
                          {t("groups.add")}
                        </Button>
                      </div>
                      <p class="text-[10px] text-[var(--color-muted)]">{t("groups.removeNote")}</p>
                    </div>
                  </Show>
                </li>
              )}
            </For>
          </ul>
        </section>
      </Show>

      {/* Rename inline row */}
      <Show when={renameFor()}>
        {(target) => (
          <ConfirmModal
            show
            idPrefix="group-rename"
            title={t("groups.renameTitle")}
            body={
              <input
                value={target().name}
                onInput={(e) => setRenameFor({ ...target(), name: e.currentTarget.value })}
                class="w-full text-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-2 py-1.5 text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
              />
            }
            confirmLabel={t("groups.rename")}
            onConfirm={() => void renameGroup()}
            onClose={() => setRenameFor(null)}
          />
        )}
      </Show>

      {/* Delete confirm */}
      <Show when={deleteTarget()}>
        <ConfirmModal
          show
          idPrefix="group-delete"
          title={t("groups.deleteTitle")}
          body={t("groups.deleteBody", { name: deleteTarget().name })}
          confirmLabel={t("groups.delete")}
          confirmClass="bg-[var(--color-danger)] text-white"
          onConfirm={() => void deleteGroup()}
          onClose={() => setDeleteTarget(null)}
        />
      </Show>
    </div>
  );
}
