import { createSignal, onSettled, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { useVault } from "../context/VaultContext.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastSuccess, toastError } from "../context/toastSignal.js";
import { Button, Input } from "./Primitives.jsx";
import ConfirmModal from "./ConfirmModal.jsx";

// S3-7c / 4.8: the admin Collections surface — create shared
// collections, manage who has access, publish the name catalog members
// use to ask for access. Plain language: grants are "access", the
// catalog is the list people see when asking.

const ACCESS_STYLES = {
  read: "bg-gray-500/15 text-gray-400 border-gray-500/30",
  write: "bg-green-500/15 text-green-400 border-green-500/30",
  manage: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

export default function CollectionsTab() {
  const { t } = useI18n();
  const vault = useVault();

  const [newName, setNewName] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [grantsFor, setGrantsFor] = createSignal(null); // collection row open for grant editing
  const [grantMember, setGrantMember] = createSignal("");
  const [grantAccess, setGrantAccess] = createSignal("read");
  const [grantDays, setGrantDays] = createSignal("");
  const [deleteTarget, setDeleteTarget] = createSignal(null);
  const [clearAsk, setClearAsk] = createSignal(false);
  const [members, setMembers] = createSignal([]);
  const [groups, setGroups] = createSignal([]);
  // S4-2: a grant can name a person or a group.
  const [grantKind, setGrantKind] = createSignal("member");

  async function loadMembers() {
    try {
      const data = JSON.parse(await daemon("members.list"));
      setMembers(Array.isArray(data.members) ? data.members : []);
    } catch {
      setMembers([]);
    }
  }

  async function loadGroups() {
    try {
      const data = JSON.parse(await daemon("groups.list"));
      setGroups(Array.isArray(data.groups) ? data.groups : []);
    } catch {
      setGroups([]);
    }
  }

  onSettled(() => {
    void vault.refreshCollections();
    void loadMembers();
    void loadGroups();
  });

  // Display name for a grant row: kind-aware member/group resolution.
  function grantTargetName(g) {
    if (g.kind === "group") {
      return groups().find((x) => x.id === g.id)?.name || g.id.slice(0, 8);
    }
    return members().find((m) => m.id === g.id)?.display_name || g.id.slice(0, 8);
  }

  async function createCollection() {
    const name = newName().trim();
    if (!name) return;
    setBusy(true);
    try {
      await daemon("collections.create", { name });
      toastSuccess(t("collections.createdToast", { name }));
      setNewName("");
      await vault.refreshCollections();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function renameCollection(col) {
    const name = prompt(t("collections.renamePrompt"), col.name);
    if (!name || name.trim() === col.name) return;
    try {
      await daemon("collections.rename", { id: col.id, name: name.trim() });
      await vault.refreshCollections();
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function deleteCollection() {
    const target = deleteTarget();
    if (!target) return;
    setBusy(true);
    try {
      await daemon("collections.delete", { id: target.id });
      toastSuccess(t("collections.deletedToast", { name: target.name }));
      setDeleteTarget(null);
      await vault.refreshCollections();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function grant(col) {
    const targetId = grantMember();
    if (!targetId) {
      toastError(t("collections.pickMember"));
      return;
    }
    setBusy(true);
    try {
      const payload = {
        id: col.id,
        kind: grantKind(),
        target_id: targetId,
        access: grantAccess(),
      };
      const days = parseInt(grantDays(), 10);
      if (Number.isFinite(days) && days > 0) {
        payload.expires_at = Math.floor(Date.now() / 1000) + days * 86400;
      }
      await daemon("collections.grant", payload);
      toastSuccess(t("collections.grantedToast"));
      setGrantMember("");
      setGrantDays("");
      await vault.refreshCollections();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(col, g) {
    setBusy(true);
    try {
      await daemon("collections.revoke", { id: col.id, kind: g.kind, target_id: g.id });
      await vault.refreshCollections();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function publishCatalog() {
    setBusy(true);
    try {
      const entries = vault.collections().map((c) => ({ collection_id: c.id, name: c.name }));
      await daemon("collections.catalog_set", { entries });
      toastSuccess(t("collections.catalogPublished"));
      await vault.refreshCollections();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function clearCatalog() {
    setBusy(true);
    try {
      // §4.8-5: an empty publish is the opt-out — members asking for
      // access fall back to pasting an id.
      await daemon("collections.catalog_set", { entries: [] });
      toastSuccess(t("collections.catalogCleared"));
      setClearAsk(false);
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="space-y-6">
      {/* Create */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("collections.createTitle")}</h3>
        <p class="text-xs text-[var(--color-muted)] mb-3">{t("collections.createSubtitle")}</p>
        <div class="flex gap-2">
          <Input
            placeholder={t("collections.namePlaceholder")}
            value={newName()}
            onInput={(e) => setNewName(e.currentTarget.value)}
            onKeyDown={(e) => e.key === "Enter" && void createCollection()}
          />
          <Button variant="primary" onClick={() => void createCollection()} disabled={busy() || !newName().trim()}>
            {t("collections.createButton")}
          </Button>
        </div>
      </section>

      {/* List + grants */}
      <Show when={vault.collections().length > 0}>
        <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
          <h3 class="text-sm font-bold text-[var(--color-text)] mb-3">{t("collections.listTitle")}</h3>
          <ul class="space-y-2">
            <For each={vault.collections()}>
              {(col) => (
                <li class="p-2.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-xs font-bold text-[var(--color-text)] flex-1 truncate">{col.name}</span>
                    <span class="text-[10px] font-mono text-[var(--color-muted)]">
                      {(col.grants || []).length} {t("collections.grantCount")}
                    </span>
                    <button
                      onClick={() => setGrantsFor(grantsFor() === col.id ? null : col.id)}
                      class="text-[10px] font-bold px-2 py-1 rounded-md border border-[var(--color-border)] text-[var(--color-text)] hover:border-[var(--color-text)] cursor-pointer"
                    >
                      {t("collections.manageAccess")}
                    </button>
                    <button
                      onClick={() => void renameCollection(col)}
                      class="text-[10px] font-bold px-2 py-1 rounded-md border border-[var(--color-border)] text-[var(--color-muted)] hover:border-[var(--color-text)] hover:text-[var(--color-text)] cursor-pointer"
                    >
                      {t("collections.rename")}
                    </button>
                    <button
                      onClick={() => setDeleteTarget(col)}
                      class="text-[10px] font-bold px-2 py-1 rounded-md border border-red-400/30 text-red-400 hover:border-red-400 cursor-pointer"
                    >
                      {t("collections.delete")}
                    </button>
                  </div>
                  <Show when={grantsFor() === col.id}>
                    <div class="mt-3 pt-3 border-t border-[var(--color-border)] space-y-2">
                      <For each={col.grants || []}>
                        {(g) => (
                          <div class="flex items-center gap-2 text-xs">
                            <span class="flex-1 truncate text-[var(--color-text)]">
                              {grantTargetName(g)}
                              <Show when={g.kind === "group"}>
                                <span class="ml-1 text-[10px] font-bold text-[var(--color-muted)]">({t("groups.badge")})</span>
                              </Show>
                            </span>
                            <span class={`text-[10px] font-bold border rounded-full px-2 py-0.5 ${ACCESS_STYLES[g.access] || ""}`}>
                              {g.access === "manage"
                                ? t("shared.manageAccess")
                                : g.access === "write"
                                ? t("shared.writeAccess")
                                : t("shared.readAccess")}
                            </span>
                            <Show when={g.expires_at}>
                              <span class="text-[10px] text-[var(--color-muted)]">
                                {new Date(g.expires_at * 1000).toLocaleDateString()}
                              </span>
                            </Show>
                            <button
                              disabled={busy()}
                              onClick={() => void revoke(col, g)}
                              class="text-[10px] font-bold text-red-400 hover:text-red-300 disabled:opacity-50 cursor-pointer"
                            >
                              {t("collections.revoke")}
                            </button>
                          </div>
                        )}
                      </For>
                      <div class="flex gap-2 items-center flex-wrap pt-1">
                        <select
                          class="text-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-2 py-1.5 text-[var(--color-text)] cursor-pointer"
                          value={grantKind()}
                          onChange={(e) => {
                            setGrantKind(e.currentTarget.value);
                            setGrantMember("");
                          }}
                        >
                          <option value="member">{t("groups.person")}</option>
                          <option value="group">{t("groups.badge")}</option>
                        </select>
                        <Show
                          when={grantKind() === "group"}
                          fallback={
                            <select
                              class="text-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-2 py-1.5 text-[var(--color-text)] cursor-pointer"
                              value={grantMember()}
                              onChange={(e) => setGrantMember(e.currentTarget.value)}
                            >
                              <option value="">{t("collections.pickMember")}</option>
                              <For each={members().filter((m) => !m.removed && !m.reset)}>
                                {(m) => <option value={m.id}>{m.display_name}</option>}
                              </For>
                            </select>
                          }
                        >
                          <select
                            class="text-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-2 py-1.5 text-[var(--color-text)] cursor-pointer"
                            value={grantMember()}
                            onChange={(e) => setGrantMember(e.currentTarget.value)}
                          >
                            <option value="">{t("groups.pick")}</option>
                            <For each={groups()}>
                              {(g) => <option value={g.id}>{g.name}</option>}
                            </For>
                          </select>
                        </Show>
                        <select
                          class="text-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-2 py-1.5 text-[var(--color-text)] cursor-pointer"
                          value={grantAccess()}
                          onChange={(e) => setGrantAccess(e.currentTarget.value)}
                        >
                          <option value="read">{t("shared.readAccess")}</option>
                          <option value="write">{t("shared.writeAccess")}</option>
                          <option value="manage">{t("shared.manageAccess")}</option>
                        </select>
                        <input
                          type="number"
                          min="1"
                          placeholder={t("collections.expiryPlaceholder")}
                          class="w-24 text-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] px-2 py-1.5 text-[var(--color-text)] placeholder-[var(--color-muted)] outline-none focus:border-[var(--color-primary)]"
                          value={grantDays()}
                          onInput={(e) => setGrantDays(e.currentTarget.value)}
                        />
                        <Button onClick={() => void grant(col)} disabled={busy()}>
                          {t("collections.grantButton")}
                        </Button>
                      </div>
                    </div>
                  </Show>
                </li>
              )}
            </For>
          </ul>
        </section>
      </Show>

      {/* Catalog publish */}
      <section class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)]">
        <h3 class="text-sm font-bold text-[var(--color-text)] mb-1">{t("collections.catalogTitle")}</h3>
        <p class="text-xs text-[var(--color-muted)] mb-3">{t("collections.catalogSubtitle")}</p>
        <div class="flex gap-2">
          <Button onClick={() => void publishCatalog()} disabled={busy() || vault.collections().length === 0}>
            {t("collections.catalogButton")}
          </Button>
          <Button onClick={() => setClearAsk(true)} disabled={busy()}>
            {t("collections.catalogClear")}
          </Button>
        </div>
      </section>

      {/* Catalog clear confirm */}
      <Show when={clearAsk()}>
        <ConfirmModal
          show
          idPrefix="catalog-clear"
          title={t("collections.catalogClear")}
          body={t("collections.catalogClearConfirm")}
          confirmLabel={t("collections.catalogClear")}
          confirmClass="bg-[var(--color-danger)] text-white"
          onConfirm={() => void clearCatalog()}
          onClose={() => setClearAsk(false)}
        />
      </Show>

      {/* Delete confirm */}
      <Show when={deleteTarget()}>
        <ConfirmModal
          show
          idPrefix="collection-delete"
          title={t("collections.deleteTitle")}
          body={t("collections.deleteBody").replace("{name}", deleteTarget().name)}
          confirmLabel={t("collections.delete")}
          confirmClass="bg-[var(--color-danger)] text-white"
          onConfirm={() => void deleteCollection()}
          onClose={() => setDeleteTarget(null)}
        />
      </Show>
    </div>
  );
}
