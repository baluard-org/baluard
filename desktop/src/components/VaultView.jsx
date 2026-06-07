import { createSignal, createMemo, onMount, onCleanup, Show, For, Switch, Match } from "solid-js";
import { Transition } from "solid-transition-group";
import { useAuth } from "../context/AuthContext.jsx";
import { useVault } from "../context/VaultContext.jsx";
import { error } from "../context/errorSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { buildFolderCreatePayload } from "../lib/payload.js";
import { selectSource, filterByCategory, filterByFolder, searchCiphers } from "../lib/filters.js";
import { EMPTY_CIPHER } from "../context/VaultContext.jsx";
import { IconGrid, IconHeart, IconLock, IconCard, IconIdentity, IconNote, IconKey, IconBank, IconLicense, IconPassport, IconArchive, IconTrash, IconPlus, IconX, IconSearch, IconFolder, IconCog, IconShield, IconChevronDown, IconBolt, IconInbox, IconAlert } from "./Icon.jsx";
import CipherRow from "./CipherRow.jsx";
import CipherDetail from "./CipherDetail.jsx";
import AddEditCipherForm from "./AddEditCipherForm.jsx";
import { invalidateFaviconCache } from "./CipherAvatar.jsx";
import DeleteConfirmModal from "./DeleteConfirmModal.jsx";
import GeneratorModal from "./GeneratorModal.jsx";
import RepromptModal from "./RepromptModal.jsx";
import SettingsModal from "./SettingsModal.jsx";
import { FolderTree } from "./FolderTree.jsx";

export default function VaultView() {
  const auth = useAuth();
  const vault = useVault();
  const { t } = useI18n();

  // Local state (was global signals)
  const [viewCipher, setViewCipher] = createSignal(null);
  const [newCipher, setNewCipher] = createSignal({ ...EMPTY_CIPHER });
  const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);
  const [showGenerator, setShowGenerator] = createSignal(false);
  const [showAddMenu, setShowAddMenu] = createSignal(false);

  // Init: load ciphers on first mount
  onMount(async () => {
    await vault.refreshCiphers(t);
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
    { name: "All items", icon: <IconGrid class="w-4 h-4 shrink-0" /> },
    { name: "Favorites", icon: <IconHeart class="w-4 h-4 shrink-0" /> },
    { name: "Login", icon: <IconLock class="w-4 h-4 shrink-0" /> },
    { name: "Card", icon: <IconCard class="w-4 h-4 shrink-0" /> },
    { name: "Identity", icon: <IconIdentity class="w-4 h-4 shrink-0" /> },
    { name: "Secure note", icon: <IconNote class="w-4 h-4 shrink-0" /> },
    { name: "SSH key", icon: <IconKey class="w-4 h-4 shrink-0" /> },
    { name: "Bank account", icon: <IconBank class="w-4 h-4 shrink-0" /> },
    { name: "Driver license", icon: <IconLicense class="w-4 h-4 shrink-0" /> },
    { name: "Passport & ID", icon: <IconPassport class="w-4 h-4 shrink-0" /> },
    { name: "Archive", icon: <IconArchive class="w-4 h-4 shrink-0" /> },
    { name: "Trash", icon: <IconTrash class="w-4 h-4 shrink-0" /> },
  ];

  // Client-side filtering & search (composed from lib/filters.js)
  const filteredCiphers = createMemo(() => {
    const cat = vault.selectedCategory();
    let list = selectSource(cat, vault.ciphers(), vault.trashCiphers(), vault.archivedCiphers());
    list = filterByCategory(list, cat);
    list = filterByFolder(list, vault.folders(), vault.selectedFolder());
    list = searchCiphers(list, vault.searchQuery());
    return list;
  });

  function startAdd(type = "login") {
    setNewCipher({ ...EMPTY_CIPHER, cipherType: type });
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
            {/* Vault List dropdown */}
            <div>
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)] flex items-center justify-between">
                <span>Vaults</span>
                <IconChevronDown class="w-3 h-3 text-[var(--color-muted)]" />
              </div>
              <div class="space-y-0.5 mt-1">
                <button class="w-full px-3 py-2 rounded-xl text-xs font-bold text-[var(--color-text)] bg-transparent hover:bg-slate-800/10 hover:text-[var(--color-text)] transition-colors flex items-center gap-2.5 text-left cursor-pointer">
                  <span class="w-2 h-2 rounded-full bg-[var(--color-primary)]"></span>
                  My vault
                </button>
                <button class="w-full px-3 py-2 rounded-xl text-xs font-bold text-[var(--color-muted)] bg-transparent hover:bg-slate-800/10 hover:text-[var(--color-text)] transition-colors flex items-center gap-2.5 text-left cursor-pointer">
                  <span class="w-2 h-2 rounded-full bg-[var(--color-accent)]"></span>
                  Family
                </button>
              </div>
            </div>

            {/* Categories */}
            <div>
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)]">
                Categories
              </div>
              <div class="space-y-0.5 mt-1">
                <For each={categories}>
                  {(cat) => (
                    <button
                      onClick={() => { vault.setSelectedCategory(cat.name); vault.setSelectedFolder(null); }}
                      class={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center justify-between text-left cursor-pointer ${
                        vault.selectedCategory() === cat.name
                          ? "bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-text)] shadow-sm"
                          : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"
                      }`}
                    >
                      <div class="flex items-center gap-3">
                        {cat.icon}
                        <span>{cat.name}</span>
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
            <div>
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)] flex items-center justify-between">
                <span>Folders</span>
                <button
                  onClick={async () => {
                    const name = prompt("Folder name:");
                    if (name) {
                      try {
                        await daemon("folder.create", JSON.stringify(buildFolderCreatePayload(name)));
                        await vault.refreshCiphers(t);
                      } catch (e) { alert(e.message); }
                    }
                  }}
                  class="text-[var(--color-primary)] hover:text-[var(--color-primary-hover)] cursor-pointer"
                  title="New folder"
                >
                  <IconPlus class="w-3.5 h-3.5" />
                </button>
              </div>
              <div class="space-y-0.5 mt-1">
                <Show when={vault.folders() && vault.folders().length > 0}>
                  <FolderTree folders={vault.folders() || []} selectedFolder={vault.selectedFolder} setSelectedFolder={vault.setSelectedFolder} />
                </Show>
                <button
                  onClick={() => vault.setSelectedFolder(null)}
                  class={`w-full px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-3 text-left cursor-pointer ${!vault.selectedFolder() ? "bg-[var(--color-sidebar)] text-[var(--color-text)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"}`}
                >
                  <IconFolder class="w-4 h-4 text-[var(--color-muted)]" />
                  No Folder
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar Footer */}
        <div class="p-4 border-t border-[var(--color-border)] flex items-center justify-between gap-3 bg-[var(--color-sidebar)]">
          <div class="flex items-center gap-3 min-w-0 flex-1">
            <div class="w-9 h-9 rounded-full bg-gradient-to-tr from-[var(--color-accent)] to-[var(--color-primary)] flex items-center justify-center text-[var(--color-sidebar)] font-extrabold text-xs shadow-md shrink-0">
              ES
            </div>
            <div class="min-w-0 flex-1">
              <div class="text-xs font-bold text-[var(--color-text)] truncate leading-none">EstebanForge</div>
              <div class="text-[9px] text-[var(--color-muted)] truncate mt-1">Lead Architect</div>
            </div>
          </div>
          <div class="flex items-center gap-1.5 shrink-0">
            <button
              onClick={() => vault.setShowSettingsModal(true)}
              title="Open Settings"
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
              <h2 class="text-xl font-bold tracking-tight text-[var(--color-text)]">{vault.selectedCategory()}</h2>
              <div class="text-xs text-[var(--color-muted)] mt-0.5">
                {t("vault.entryCount", { count: filteredCiphers().length })}
              </div>
            </div>

            <div class="relative" ref={addMenuRef}>
              <button
                onClick={(e) => { e.stopPropagation(); setShowAddMenu(!showAddMenu()); }}
                class="px-4 py-2 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all shadow-md active:scale-[0.98] cursor-pointer flex items-center gap-1"
              >
                + New
                <IconChevronDown class={`w-3 h-3 transition-transform ${showAddMenu() ? "rotate-180" : ""}`} />
              </button>
              <Show when={showAddMenu()}>
              <div class="absolute right-0 top-full mt-1 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl py-1 w-40 z-50">
                <button onClick={() => startAdd("login")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">Login</button>
                <button onClick={() => startAdd("secureNote")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">Secure Note</button>
                <button onClick={() => startAdd("card")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">Card</button>
                <button onClick={() => startAdd("identity")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">Identity</button>
                <button onClick={() => startAdd("sshKey")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">SSH Key</button>
                <div class="border-t border-[var(--color-border)] my-1"></div>
                <button onClick={() => startAdd("bankAccount")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">Bank Account</button>
                <button onClick={() => startAdd("driversLicense")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">Driver License</button>
                <button onClick={() => startAdd("passport")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">Passport & ID</button>
              </div>
              </Show>
            </div>
            <button
              onClick={() => setShowGenerator(true)}
              class="p-2 rounded-xl bg-[var(--color-sidebar)] hover:bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] text-sm transition-all cursor-pointer"
              title="Password Generator"
            >
              <IconBolt class="w-4 h-4" />
            </button>
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
                placeholder="Search vault..."
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
          <div class="px-6 py-2 border-b border-[var(--color-border)] text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)] flex items-center justify-between shrink-0">
            <span>Name</span>
            <span>Options</span>
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
        <Show when={error()}>
          <div class="absolute top-4 left-4 right-4 z-10 p-3 rounded-xl bg-red-950/40 border border-red-900/50 text-red-300 text-sm flex items-center gap-2 animate-fade-in-up shadow-lg">
            <IconAlert class="w-5 h-5 shrink-0 text-red-400" />
            {error()}
          </div>
        </Show>

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
                onDelete={(id) => setShowDeleteConfirm(true)}
              />
            </Match>
            <Match when={vault.activePane() === "add"}>
              <AddEditCipherForm
                isEdit={false}
                newCipher={newCipher}
                setNewCipher={setNewCipher}
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
    </div>
  );
}
