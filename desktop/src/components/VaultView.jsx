import { createSignal, createMemo, createEffect, onMount, onCleanup, Show, For, Switch, Match } from "solid-js";
import { Transition } from "solid-transition-group";
import { useAuth } from "../context/AuthContext.jsx";
import { useVault } from "../context/VaultContext.jsx";
import { toastError } from "../context/toastSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { buildFolderCreatePayload } from "../lib/payload.js";
import { selectSource, filterByCategory, filterByFolder, filterByTag, searchCiphers } from "../lib/filters.js";
import { sanitizeError } from "../lib/utils.js";
import { EMPTY_CIPHER } from "../context/VaultContext.jsx";
import { IconGrid, IconHeart, IconLock, IconCard, IconIdentity, IconNote, IconKey, IconBank, IconLicense, IconPassport, IconArchive, IconTrash, IconFingerprint, IconPlus, IconX, IconSearch, IconFolder, IconCog, IconShield, IconChevronDown, IconBolt, IconInbox } from "./Icon.jsx";
import CipherRow from "./CipherRow.jsx";
import CipherDetail from "./CipherDetail.jsx";
import AddEditCipherForm from "./AddEditCipherForm.jsx";
import { invalidateFaviconCache } from "./CipherAvatar.jsx";
import DeleteConfirmModal from "./DeleteConfirmModal.jsx";
import ArchiveConfirmModal from "./ArchiveConfirmModal.jsx";
import FocusTrap from "./FocusTrap.jsx";
import GeneratorModal from "./GeneratorModal.jsx";
import RepromptModal from "./RepromptModal.jsx";
import SettingsModal from "./SettingsModal.jsx";
import { FolderTree } from "./FolderTree.jsx";
import VaultSwitcher from "./VaultSwitcher.jsx";
import SwitchUnlockModal from "./SwitchUnlockModal.jsx";
import { useVaultSwitcher } from "../context/VaultSwitcherContext.jsx";
import { IconSwitch } from "./Icon.jsx";

export default function VaultView() {
  const auth = useAuth();
  const vault = useVault();
  const switcher = useVaultSwitcher();
  const { t } = useI18n();

  // Local state (was global signals)
  const [viewCipher, setViewCipher] = createSignal(null);
  const [newCipher, setNewCipher] = createSignal({ ...EMPTY_CIPHER });
  const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);
  const [showArchiveConfirm, setShowArchiveConfirm] = createSignal(false);
  let emptyTrashRef;
  let deleteTagRef;
  const [showGenerator, setShowGenerator] = createSignal(false);
  const [showAddMenu, setShowAddMenu] = createSignal(false);
  const [showEmptyTrashConfirm, setShowEmptyTrashConfirm] = createSignal(false);
  const [showNewFolder, setShowNewFolder] = createSignal(false);
  const [deleteTagName, setDeleteTagName] = createSignal(null);
  // Phase 6: vault picked from the switcher that needs unlocking. When set,
  // SwitchUnlockModal renders over the current view. Cleared on success/cancel.
  const [switchUnlockTarget, setSwitchUnlockTarget] = createSignal(null);

  // Init: load ciphers on first mount
  onMount(async () => {
    await vault.refreshCiphers(t);
  });

  // Reset vault-scoped view state when the active vault changes (instant
  // switch OR switch-unlock modal). An open detail/edit pane, a half-filled
  // add form, or a stale folder/tag/search filter from the previous vault
  // must not survive a vault change. `lastSwitchSlug` guards the initial
  // run so first mount doesn't reset.
  let lastSwitchSlug = switcher.activeSlug();
  createEffect(() => {
    const slug = switcher.activeSlug();
    if (slug === lastSwitchSlug) return;
    lastSwitchSlug = slug;
    setViewCipher(null);
    setNewCipher({ ...EMPTY_CIPHER });
    vault.resetNavigation();
  });

  // Close add menu on outside click
  let addMenuRef;
  onMount(() => {
    const handler = (e) => {
      if (addMenuRef && !addMenuRef.contains(e.target)) setShowAddMenu(false);
    };
    document.addEventListener("click", handler);
    onCleanup(() => document.removeEventListener("click", handler));
  });

  // Categories
  const categories = [
    { id: "allItems", name: "All items", icon: <IconGrid class="w-4 h-4 shrink-0" /> },
    { id: "favorites", name: "Favorites", icon: <IconHeart class="w-4 h-4 shrink-0" /> },
    { id: "login", name: "Login", icon: <IconLock class="w-4 h-4 shrink-0" /> },
    { id: "passkeys", name: "Passkeys", icon: <IconFingerprint class="w-4 h-4 shrink-0" /> },
    { id: "card", name: "Card", icon: <IconCard class="w-4 h-4 shrink-0" /> },
    { id: "identity", name: "Identity", icon: <IconIdentity class="w-4 h-4 shrink-0" /> },
    { id: "secureNote", name: "Secure note", icon: <IconNote class="w-4 h-4 shrink-0" /> },
    { id: "sshKey", name: "SSH key", icon: <IconKey class="w-4 h-4 shrink-0" /> },
    { id: "bankAccount", name: "Bank account", icon: <IconBank class="w-4 h-4 shrink-0" /> },
    { id: "driversLicense", name: "Driver license", icon: <IconLicense class="w-4 h-4 shrink-0" /> },
    { id: "passport", name: "Passport & ID", icon: <IconPassport class="w-4 h-4 shrink-0" /> },
    { id: "archive", name: "Archive", icon: <IconArchive class="w-4 h-4 shrink-0" /> },
    { id: "trash", name: "Trash", icon: <IconTrash class="w-4 h-4 shrink-0" /> },
  ];

  // Client-side filtering & search (composed from lib/filters.js)
  const filteredCiphers = createMemo(() => {
    const cat = vault.selectedCategory();
    let list = selectSource(cat, vault.ciphers(), vault.trashCiphers(), vault.archivedCiphers());
    list = filterByCategory(list, cat);
    list = filterByFolder(list, vault.folders(), vault.selectedFolder());
    list = filterByTag(list, vault.selectedTag());
    list = searchCiphers(list, vault.searchQuery());
    return list;
  });

  function startAdd(type = "login") {
    setNewCipher({ ...EMPTY_CIPHER, cipherType: type, folder_id: vault.selectedFolder() || null });
    vault.setActivePane("add");
    setShowAddMenu(false);
  }

  return (
    <div class="flex h-full overflow-hidden">
      <DeleteConfirmModal
        viewCipher={viewCipher()}
        showDeleteConfirm={showDeleteConfirm()}
        setShowDeleteConfirm={setShowDeleteConfirm}
        selectedCategory={vault.selectedCategory()}
        onDelete={async (id) => {
          const ok = await vault.deleteCipher(id, t);
          if (ok) { setViewCipher(null); }
        }}
      />
      <ArchiveConfirmModal
        show={showArchiveConfirm()}
        setShow={setShowArchiveConfirm}
        onConfirm={async () => {
          const ok = await vault.archiveCipher(viewCipher()?.id, t);
          if (ok) { setViewCipher(null); }
        }}
      />
      <Show when={deleteTagName()}>
        <div
          ref={deleteTagRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-tag-title"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => setDeleteTagName(null)}
        >
          <FocusTrap containerRef={deleteTagRef} onEscape={() => setDeleteTagName(null)} />
          <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl" onClick={e => e.stopPropagation()}>
            <h3 id="delete-tag-title" class="text-lg font-bold text-[var(--color-text)] mb-2">{t("entry.deleteTagTitle")}</h3>
            <p class="text-sm text-[var(--color-muted)] mb-6">{t("entry.deleteTagConfirm", { tag: deleteTagName() })}</p>
            <div class="flex gap-3">
              <button
                onClick={() => setDeleteTagName(null)}
                class="flex-1 py-2.5 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] font-semibold transition-all cursor-pointer"
              >{t("entry.cancel")}</button>
              <button
                onClick={async () => {
                  const name = deleteTagName();
                  setDeleteTagName(null);
                  await vault.deleteTag(name, t);
                }}
                class="flex-1 py-2.5 rounded-xl bg-red-950/40 text-red-400 border border-red-900/30 hover:bg-red-950/60 font-semibold transition-all cursor-pointer"
              >{t("entry.delete")}</button>
            </div>
          </div>
        </div>
      </Show>
      <Show when={showEmptyTrashConfirm()}>
        <div
          ref={emptyTrashRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="empty-trash-title"
          class="fixed inset-0 bg-black/60 flex items-center justify-center z-[100]"
          onClick={() => setShowEmptyTrashConfirm(false)}
        >
          <FocusTrap containerRef={emptyTrashRef} onEscape={() => setShowEmptyTrashConfirm(false)} />
          <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl" onClick={e => e.stopPropagation()}>
            <h3 id="empty-trash-title" class="text-lg font-bold text-[var(--color-text)] mb-2">{t("vault.emptyTrash")}</h3>
            <p class="text-sm text-[var(--color-muted)] mb-6">{t("vault.emptyTrashConfirm")}</p>
            <div class="flex gap-3">
              <button
                onClick={() => setShowEmptyTrashConfirm(false)}
                class="flex-1 py-2.5 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] font-semibold transition-all cursor-pointer"
              >{t("entry.cancel")}</button>
              <button
                onClick={async () => {
                  setShowEmptyTrashConfirm(false);
                  try {
                    await daemon("vault.trash.purge", "0");
                    await vault.refreshCiphers(t);
                  } catch (e) { toastError(sanitizeError(e, t)); }
                }}
                class="flex-1 py-2.5 rounded-xl bg-red-950/40 text-red-400 border border-red-900/30 hover:bg-red-950/60 font-semibold transition-all cursor-pointer"
              >{t("vault.emptyTrash")}</button>
            </div>
          </div>
        </div>
      </Show>
      <GeneratorModal showGenerator={showGenerator()} setShowGenerator={setShowGenerator} />
      <RepromptModal />
      <SettingsModal />

      {/* Column 1: Left Navigation Sidebar */}
      <div class="w-[260px] bg-[var(--color-sidebar)] border-r border-[var(--color-border)] flex flex-col justify-between shrink-0 select-none">
        <div>
          {/* Header Brand */}
          <div class="p-6 pb-4 border-b border-[var(--color-border)] flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-center shadow">
                <IconLock class="w-4.5 h-4.5 text-[var(--color-primary)]" />
              </div>
              <span class="text-lg font-bold tracking-tight text-[var(--color-text)]">{t("app.name")}</span>
            </div>
            <span class="flex h-2.5 w-2.5 relative">
              <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" title={t("vault.statusUnlocked")}></span>
            </span>
          </div>



          {/* Navigation Scroll Area */}
          <div class="p-3 space-y-4 overflow-y-auto max-h-[calc(100vh-160px)]">
            {/* Categories */}
            <div>
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)]">
                {t("vault.categoriesTitle")}
              </div>
              <div class="space-y-0.5 mt-1">
                <For each={categories}>
                  {(cat) => (
                    <button
                      onClick={() => { vault.setSelectedCategory(cat.name); vault.setSelectedFolder(null); vault.setSelectedTag(null); }}
                      class={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center justify-between text-left cursor-pointer ${
                        vault.selectedCategory() === cat.name
                          ? "bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-text)] shadow-sm"
                          : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"
                      }`}
                    >
                      <div class="flex items-center gap-3">
                        {cat.icon}
                        <span>{t("categories." + cat.id)}</span>
                      </div>
                      <Show when={cat.name === "All items"}>
                        <span class="text-[10px] bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded-md font-mono text-[var(--color-muted)]">
                          {vault.ciphers().length}
                        </span>
                      </Show>
                      <Show when={cat.name === "Trash"}>
                        <span class="text-[10px] bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded-md font-mono text-[var(--color-muted)]">
                          {vault.trashCiphers().length}
                        </span>
                      </Show>
                      <Show when={cat.name === "Archive"}>
                        <span class="text-[10px] bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded-md font-mono text-[var(--color-muted)]">
                          {vault.archivedCiphers().length}
                        </span>
                      </Show>
                    </button>
                  )}
                </For>
              </div>
            </div>

            {/* Folders */}
            <div class="mt-3 pt-3 border-t border-[var(--color-border)]">
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)] flex items-center justify-between">
                <span>{t("vault.foldersTitle")}</span>
                <button
                  onClick={() => setShowNewFolder(!showNewFolder())}
                  class="p-1 rounded-md border border-[var(--color-border)] bg-[var(--color-card)] text-[var(--color-primary)] hover:text-[var(--color-primary-hover)] hover:bg-[var(--color-sidebar)] transition-all cursor-pointer flex items-center justify-center"
                  title={t("vault.newFolder")}
                >
                  <IconPlus class="w-3 h-3" />
                </button>
              </div>
              <div class="space-y-0.5 mt-1">
                <Show when={showNewFolder()}>
                  <div class="flex items-center gap-1 py-1.5 rounded-xl" style={{ "padding-left": "14px", "padding-right": "6px" }}>
                    <IconFolder class="w-3.5 h-3.5 shrink-0 text-[var(--color-primary)] opacity-50" />
                    <input
                      class="flex-1 min-w-0 bg-transparent border-b border-[var(--color-primary)] text-xs text-[var(--color-text)] outline-none placeholder:text-[var(--color-muted)] pb-px"
                      placeholder={t("vault.folderNamePlaceholder")}
                      autofocus
                      onKeyDown={async (e) => {
                        if (e.key === "Enter") {
                          const name = e.target.value.trim();
                          if (!name) return;
                          try {
                            await daemon("folder.create", JSON.stringify(buildFolderCreatePayload(name)));
                            await vault.refreshCiphers(t);
                          } catch (err) { toastError(sanitizeError(err, t)); }
                          setShowNewFolder(false);
                        } else if (e.key === "Escape") {
                          setShowNewFolder(false);
                        }
                      }}
                      onBlur={() => setShowNewFolder(false)}
                    />
                  </div>
                </Show>
                <Show when={vault.folders() && vault.folders().length > 0}>
                  <FolderTree folders={vault.folders() || []} selectedFolder={vault.selectedFolder} setSelectedFolder={vault.setSelectedFolder} />
                </Show>
                <button
                  onClick={() => vault.setSelectedFolder(null)}
                  class={`flex items-center gap-1 py-1.5 rounded-xl text-xs font-bold cursor-pointer ${!vault.selectedFolder() ? "bg-[var(--color-sidebar)] text-[var(--color-text)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"}`}
                  style={{ "padding-left": "14px", "padding-right": "6px" }}
                >
                  <IconFolder class="w-3.5 h-3.5 shrink-0" />
                  <span>{t("entry.noFolder")}</span>
                </button>
                <Show when={vault.tags() && vault.tags().length > 0}>
                   <div class="mt-3 pt-3 border-t border-[var(--color-border)]">
                     <div class="flex items-center justify-between mb-2" style={{ "padding-left": "14px", "padding-right": "14px" }}>
                       <h3 class="text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)]">{t("entry.tagsHeader")}</h3>
                       <Show when={vault.selectedTag()}>
                         <button
                           onClick={() => vault.setSelectedTag(null)}
                           class="px-2 py-0.5 text-[9px] font-bold normal-case border border-[var(--color-border)] bg-[var(--color-card)] rounded-md text-[var(--color-primary)] hover:text-[var(--color-primary-hover)] hover:bg-[var(--color-sidebar)] transition-all cursor-pointer"
                         >
                           {t("entry.clearTagFilter")}
                         </button>
                       </Show>
                     </div>
                     <div class="flex flex-wrap gap-1" style={{ "padding-left": "6px", "padding-right": "6px" }}>
                       <For each={vault.tags() || []}>
                         {tag => (
                           <div class="group relative">
                             <button
                               onClick={() => { vault.setSelectedTag(vault.selectedTag() === tag ? null : tag); }}
                               class={`px-2 py-1 rounded-full text-xs font-semibold cursor-pointer transition-colors ${vault.selectedTag() === tag ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]" : "bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
                             >
                               {tag}
                             </button>
                             <button
                               onClick={(e) => { e.stopPropagation(); setDeleteTagName(tag); }}
                               class="absolute -top-1.5 -right-1.5 w-4 h-4 rounded-full bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-muted)] hover:text-red-400 hover:border-red-400 flex items-center justify-center text-[9px] leading-none opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer"
                               title={t("entry.delete")}
                             >×</button>
                           </div>
                         )}
                       </For>
                     </div>
                   </div>
                 </Show>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar Footer */}
        <div class="p-4 border-t border-[var(--color-border)] flex items-center justify-between gap-3 bg-[var(--color-sidebar)]">
          <div class="flex items-center gap-3 min-w-0 flex-1">
            <VaultSwitcher onLockedTarget={(row) => {
              setSwitchUnlockTarget({ slug: row.slug, display_name: row.display_name });
            }}>
              <div class="relative shrink-0">
                <Show when={vault.avatarB64()} fallback={
                  <div class="w-9 h-9 rounded-full bg-gradient-to-tr from-[var(--color-accent)] to-[var(--color-primary)] flex items-center justify-center text-[var(--color-sidebar)] font-extrabold text-xs shadow-md">
                    {(vault.displayName() || "?").slice(0, 2).toUpperCase()}
                  </div>
                }>
                  <img
                    src={`data:image/${vault.avatarExt() === "jpg" ? "jpeg" : vault.avatarExt()};base64,${vault.avatarB64()}`}
                    alt=""
                    class="w-9 h-9 rounded-full object-cover shadow-md"
                  />
                </Show>
                <Show when={switcher.vaults().length > 1}>
                  <span class="absolute -bottom-1 -right-1 flex h-4.5 w-4.5 items-center justify-center rounded-full bg-[var(--color-primary)] text-[var(--color-primary-text)] shadow-md border border-[var(--color-sidebar)]">
                    <IconSwitch class="w-2.5 h-2.5" />
                  </span>
                </Show>
              </div>
              <div class="min-w-0 flex-1">
                <div class="text-xs font-bold text-[var(--color-text)] truncate leading-none">{vault.displayName() || t("settings.profile")}</div>
                <div class="text-[9px] text-[var(--color-muted)] truncate mt-1">{vault.profileSubtitle() || ""}</div>
              </div>
            </VaultSwitcher>
          </div>
          <div class="flex items-center gap-1.5 shrink-0">
            <button
              onClick={() => vault.setShowSettingsModal(true)}
              title={t("settings.openSettings")}
              class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
            >
              <IconCog class="w-4 h-4" />
            </button>
            <button
              onClick={() => auth.lock(t)}
              title={t("vault.lock")}
              class="p-2 rounded-xl border border-[var(--color-border)] hover:border-red-900/50 hover:bg-red-950/20 text-[var(--color-muted)] hover:text-red-400 transition-all cursor-pointer bg-[var(--color-card)]"
            >
              <IconLock class="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Column 2: Vault Items List Pane */}
      <div class="w-[360px] bg-[var(--color-list)] border-r border-[var(--color-border)] flex flex-col justify-between shrink-0 select-none">
        <div class="flex-1 flex flex-col min-h-0">

          {/* Header Action Bar */}
          <div class="p-6 pb-4 flex items-center justify-between gap-4 shrink-0">
            <div>
              <h2 class="text-xl font-bold tracking-tight text-[var(--color-text)]">
                {t("categories." + (categories.find(c => c.name === vault.selectedCategory())?.id || "allItems"))}
              </h2>
              <div class="text-xs text-[var(--color-muted)] mt-0.5">
                {t("vault.entryCount", { count: filteredCiphers().length })}
              </div>
            </div>

            <Show when={vault.selectedCategory() === "Trash"} fallback={
              <div class="relative" ref={addMenuRef}>
                <button
                  onClick={(e) => { e.stopPropagation(); setShowAddMenu(!showAddMenu()); }}
                  class="px-4 py-2 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all shadow-md active:scale-[0.98] cursor-pointer flex items-center gap-1"
                >
                  {t("vault.newButton")}
                  <IconChevronDown class={`w-3 h-3 transition-transform ${showAddMenu() ? "rotate-180" : ""}`} />
                </button>
                <Show when={showAddMenu()}>
                <div class="absolute right-0 top-full mt-1 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl py-1 w-40 z-50">
                  <button onClick={() => startAdd("login")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">{t("types.login")}</button>
                  <button onClick={() => startAdd("secureNote")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">{t("types.secureNote")}</button>
                  <button onClick={() => startAdd("card")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">{t("types.card")}</button>
                  <button onClick={() => startAdd("identity")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">{t("types.identity")}</button>
                  <button onClick={() => startAdd("sshKey")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">{t("types.sshKey")}</button>
                  <div class="border-t border-[var(--color-border)] my-1"></div>
                  <button onClick={() => startAdd("bankAccount")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">{t("types.bankAccount")}</button>
                  <button onClick={() => startAdd("driversLicense")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">{t("types.driversLicense")}</button>
                  <button onClick={() => startAdd("passport")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">{t("types.passport")}</button>
                </div>
                </Show>
              </div>
            }>
              <button
                onClick={async () => {
                  if (!filteredCiphers().length) return;
                  setShowEmptyTrashConfirm(true);
                }}
                class="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-bold transition-all shadow-md active:scale-[0.98] cursor-pointer flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
                disabled={!filteredCiphers().length}
              >
                <IconTrash class="w-3.5 h-3.5" />
                {t("vault.emptyTrash")}
              </button>
            </Show>
            <Show when={vault.selectedCategory() !== "Trash"}>
              <button
                onClick={() => setShowGenerator(true)}
                class="p-2 rounded-xl bg-[var(--color-sidebar)] hover:bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] text-sm transition-all cursor-pointer"
                title={t("generator.title")}
              >
                <IconBolt class="w-4 h-4" />
              </button>
            </Show>
          </div>

          {/* Search Input bar */}
          <div class="px-6 pb-4 shrink-0">
            <div class="relative">
              <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[var(--color-muted)]">
                <IconSearch class="w-4 h-4" />
              </span>
              <input
                type="text"
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck="false"
                placeholder={t("vault.searchPlaceholder")}
                value={vault.searchQuery()}
                onInput={(e) => vault.setSearchQuery(e.target.value)}
                class="w-full pl-9 pr-4 py-2.5 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-text)] placeholder-slate-500 outline-none focus:border-[var(--color-primary)] transition-all"
              />
              <Show when={vault.searchQuery()}>
                <button
                  onClick={() => vault.setSearchQuery("")}
                  class="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--color-muted)] hover:text-[var(--color-text)]"
                >
                  ✕
                </button>
              </Show>
            </div>
          </div>

          {/* Table headers */}
          <div class="px-6 py-2 border-b border-[var(--color-border)] text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)] flex items-center shrink-0">
            <span>{t("vault.headerName")}</span>
          </div>

          {/* Scrollable list items */}
          <div class="flex-1 overflow-y-auto p-3 space-y-1">
            <Show when={filteredCiphers().length === 0}>
              <div class="text-sm text-[var(--color-muted)] text-center py-12 px-4">
                <IconInbox class="w-8 h-8 text-[var(--color-muted)] opacity-60 mx-auto mb-2" />
                {t("vault.emptyList")}
              </div>
            </Show>

            <For each={filteredCiphers()}>
              {(cipher) => <CipherRow cipher={cipher} onSelect={(c) => { setViewCipher(c); vault.setActivePane("detail"); }} active={viewCipher()?.id === cipher.id} />}
            </For>
          </div>
        </div>
      </div>

      {/* Column 3: Main Details / Edit Panel */}
      <div class="flex-1 bg-[var(--color-detail)] flex flex-col min-w-0 relative">

        <Transition name="slide" mode="out-in">
          <Switch>
            <Match when={vault.activePane() === "detail" && viewCipher()}>
              <CipherDetail
                cipher={viewCipher()}
                onEdit={(cipherData) => { setNewCipher(cipherData); vault.setActivePane("edit"); }}
                onClose={() => vault.setActivePane("welcome")}
                setViewCipher={setViewCipher}
                setActivePane={vault.setActivePane}
                selectedCategory={vault.selectedCategory()}
                                onArchive={() => setShowArchiveConfirm(true)}
                onDelete={(id) => setShowDeleteConfirm(true)}
              />
            </Match>
            <Match when={vault.activePane() === "add"}>
              <AddEditCipherForm
                isEdit={false}
                newCipher={newCipher}
                setNewCipher={setNewCipher}
                folders={vault.folders()}
                tags={vault.tags()}
                onSave={async () => {
                  const id = await vault.addCipher(newCipher(), t);
                  if (id) {
                    const added = await vault.getCipher(id, t);
                    if (added) {
                      const u = added.uris?.[0];
                      const domain = u ? (typeof u === "string" ? u : u.uri) : null;
                      if (domain) invalidateFaviconCache(domain);
                      setViewCipher(added); vault.setActivePane("detail");
                    }
                    setNewCipher({ ...EMPTY_CIPHER });
                  }
                }}
                onCancel={() => vault.setActivePane("welcome")}
              />
            </Match>
            <Match when={vault.activePane() === "edit"}>
              <AddEditCipherForm
                isEdit={true}
                newCipher={newCipher}
                setNewCipher={setNewCipher}
                folders={vault.folders()}
                tags={vault.tags()}
                onSave={async () => {
                  const updated = await vault.updateCipher(viewCipher().id, newCipher(), t);
                  if (updated) {
                    // Invalidate favicon cache so new URI triggers fresh fetch
                    const u = updated.uris?.[0];
                    const domain = u ? (typeof u === "string" ? u : u.uri) : null;
                    if (domain) invalidateFaviconCache(domain);
                    setViewCipher(updated); vault.setActivePane("detail");
                  }
                }}
                onCancel={() => vault.setActivePane("detail")}
              />
            </Match>
            <Match when={vault.activePane() === "welcome"}>
              <div class="flex-1 flex flex-col items-center justify-center text-[var(--color-muted)] p-8">
                <div class="w-20 h-20 rounded-3xl bg-[var(--color-sidebar)] border border-[var(--color-border)] flex items-center justify-center text-slate-500 mb-6 shadow-inner">
                  <IconLock class="w-10 h-10 text-[var(--color-primary)] opacity-85" />
                </div>
                <p class="text-xs text-[var(--color-muted)] mt-2 max-w-xs text-center leading-relaxed font-semibold">
                  {t("entry.selectPrompt")}
                </p>
              </div>
            </Match>
          </Switch>
        </Transition>
      </div>

      {/* Phase 6: unlock a locked vault picked from the switcher, in place. */}
      <SwitchUnlockModal
        target={switchUnlockTarget()}
        onClose={() => setSwitchUnlockTarget(null)}
        onUnlocked={async () => {
          await vault.refreshCiphers(t);
          // Refresh the switcher so activeSlug updates to the newly-active
          // vault — that fires the createEffect above which resets the view.
          await switcher.refresh();
        }}
      />
    </div>
  );
}
