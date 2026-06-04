import { createSignal, onMount, onCleanup, Show, For } from "solid-js";
import { useApp } from "../context/AppContext.jsx";
import { useActions } from "../hooks/useActions.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { buildFolderCreatePayload } from "../lib/payload.js";
import CipherRow from "./CipherRow.jsx";
import CipherDetail from "./CipherDetail.jsx";
import AddEditCipherForm from "./AddEditCipherForm.jsx";
import DeleteConfirmModal from "./DeleteConfirmModal.jsx";
import GeneratorModal from "./GeneratorModal.jsx";
import RepromptModal from "./RepromptModal.jsx";
import SettingsModal from "./SettingsModal.jsx";
import { FolderTree } from "./FolderTree.jsx";

export default function VaultView() {
  const { ciphers, trashCiphers, archivedCiphers, vaultInfo, error, selectedCategory, setSelectedCategory, selectedFolder, setSelectedFolder, folders, searchQuery, setSearchQuery, activePane, setActivePane, viewCipher, setNewCipher, theme, setTheme, showGenerator, setShowGenerator, showSettingsModal, setShowSettingsModal } = useApp();
  const { lock, refreshCiphers } = useActions();
  const { t } = useI18n();

  const [showAddMenu, setShowAddMenu] = createSignal(false);

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
    { name: "All items", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg> },
    { name: "Favorites", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" /></svg> },
    { name: "Login", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg> },
    { name: "Card", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg> },
    { name: "Identity", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg> },
    { name: "Secure note", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg> },
    { name: "SSH key", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m0 0a2 2 0 01-2 2m2-2h2a2 2 0 002-2V5a2 2 0 00-2-2h-2a2 2 0 00-2 2v2m0 0h-2m-2 0A5 5 0 113 12a5 5 0 0110 0v1a2 2 0 002 2h2a2 2 0 002-2v-1a2 2 0 00-2-2h-2" /></svg> },
    { name: "Bank account", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3" /></svg> },
    { name: "Driver license", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0h4" /></svg> },
    { name: "Passport & ID", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> },
    { name: "Archive", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" /></svg> },
    { name: "Trash", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg> }
  ];

  // Client-side filtering & search
  const filteredCiphers = () => {
    const cat = selectedCategory();
    let list = cat === "Trash" ? (trashCiphers() || []) : cat === "Archive" ? (archivedCiphers() || []) : (ciphers() || []);
    const query = searchQuery().toLowerCase();

    // Category filtering (using cipher.type from backend)
    if (cat === "Favorites") {
      list = list.filter(c => c.favorite || c._meta?.favorite);
    } else if (cat === "Login") {
      list = list.filter(c => (c.type || c._meta?.type) === "login");
    } else if (cat === "Card") {
      list = list.filter(c => (c.type || c._meta?.type) === "card");
    } else if (cat === "Identity") {
      list = list.filter(c => (c.type || c._meta?.type) === "identity");
    } else if (cat === "Secure note") {
      list = list.filter(c => (c.type || c._meta?.type) === "secureNote");
    } else if (cat === "SSH key") {
      list = list.filter(c => (c.type || c._meta?.type) === "sshKey");
    } else if (cat === "Bank account") {
      list = list.filter(c => (c.type || c._meta?.type) === "bankAccount");
    } else if (cat === "Driver license") {
      list = list.filter(c => (c.type || c._meta?.type) === "driversLicense");
    } else if (cat === "Passport & ID") {
      list = list.filter(c => (c.type || c._meta?.type) === "passport");
    }

    // Folder filtering (include subfolder ciphers)
    const folder = selectedFolder();
    if (folder) {
      const allFolders = folders() || [];
      const descendantIds = new Set();
      const queue = [folder];
      while (queue.length > 0) {
        const current = queue.shift();
        descendantIds.add(current);
        allFolders.forEach(f => { if (f.parent_id === current) queue.push(f.id); });
      }
      list = list.filter(c => descendantIds.has(c.folder_id || c._meta?.folder_id));
    }

    // Search query filtering
    if (query) {
      list = list.filter(c => 
        c.name?.toLowerCase().includes(query) ||
        c.username?.toLowerCase().includes(query) ||
        (c.uris && c.uris.some(u => (typeof u === 'string' ? u : u.uri || '').toLowerCase().includes(query))) ||
        c.notes?.toLowerCase().includes(query)
      );
    }
    return list;
  };

  function startAdd(type = "login") {
    setNewCipher({ name: "", username: "", password: "", uris: [], notes: "", cipherType: type, favorite: false, reprompt: false, attachments: [], folder_id: null, custom_fields: [], totp_uri: "" });
    setActivePane("add");
    setShowAddMenu(false);
  }

  return (
    <div class="flex h-full overflow-hidden">
      <DeleteConfirmModal />
      <GeneratorModal />
      <RepromptModal />
      <SettingsModal />
      
      {/* Column 1: Left Navigation Sidebar */}
      <div class="w-[260px] bg-[var(--color-sidebar)] border-r border-[var(--color-border)] flex flex-col justify-between shrink-0 select-none">
        <div>
          {/* Header Brand */}
          <div class="p-6 pb-4 border-b border-[var(--color-border)] flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-center shadow">
                <svg class="w-4.5 h-4.5 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
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
                <svg class="w-3 h-3 text-[var(--color-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19 9l-7 7-7-7"/></svg>
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
                      onClick={() => { setSelectedCategory(cat.name); setSelectedFolder(null); }}
                      class={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center justify-between text-left cursor-pointer ${
                        selectedCategory() === cat.name
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
                          {ciphers().length}
                        </span>
                      </Show>
                      <Show when={cat.name === "Trash"}>
                        <span class="text-[10px] bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded-md font-mono text-[var(--color-muted)]">
                          {trashCiphers().length}
                        </span>
                      </Show>
                      <Show when={cat.name === "Archive"}>
                        <span class="text-[10px] bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded-md font-mono text-[var(--color-muted)]">
                          {archivedCiphers().length}
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
                        await refreshCiphers();
                      } catch (e) { alert(e.message); }
                    }
                  }}
                  class="text-[var(--color-primary)] hover:text-[var(--color-primary-hover)] cursor-pointer"
                  title="New folder"
                >
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                </button>
              </div>
              <div class="space-y-0.5 mt-1">
                {/* Folder tree */}
                <Show when={folders() && folders().length > 0}>
                  <FolderTree folders={folders() || []} selectedFolder={selectedFolder} setSelectedFolder={setSelectedFolder} />
                </Show>
                <button
                  onClick={() => setSelectedFolder(null)}
                  class={`w-full px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-3 text-left cursor-pointer ${!selectedFolder() ? "bg-[var(--color-sidebar)] text-[var(--color-text)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"}`}
                >
                  <svg class="w-4 h-4 text-[var(--color-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                  No Folder
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar Footer Lock & Settings */}
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
              onClick={() => setShowSettingsModal(true)}
              title="Open Settings"
              class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
            </button>
            <button
              onClick={() => lock(t)}
              title={t("vault.lock")}
              class="p-2 rounded-xl border border-[var(--color-border)] hover:border-red-900/50 hover:bg-red-950/20 text-[var(--color-muted)] hover:text-red-400 transition-all cursor-pointer bg-[var(--color-card)]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
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
              <h2 class="text-xl font-bold tracking-tight text-[var(--color-text)]">{selectedCategory()}</h2>
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
                <svg class={`w-3 h-3 transition-transform ${showAddMenu() ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
              </button>
              <Show when={showAddMenu()}>
              <div class="absolute right-0 top-full mt-1 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl py-1 w-40 z-50">
                <button onClick={() => startAdd("login")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                  Login
                </button>
                <button onClick={() => startAdd("secureNote")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                  Secure Note
                </button>
                <button onClick={() => startAdd("card")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>
                  Card
                </button>
                <button onClick={() => startAdd("identity")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
                  Identity
                </button>
                <button onClick={() => startAdd("sshKey")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m0 0a2 2 0 01-2 2m2-2h2a2 2 0 002-2V5a2 2 0 00-2-2h-2a2 2 0 00-2 2v2m0 0h-2m-2 0A5 5 0 113 12a5 5 0 0110 0v1a2 2 0 002 2h2a2 2 0 002-2v-1a2 2 0 00-2-2h-2" /></svg>
                  SSH Key
                </button>
                <div class="border-t border-[var(--color-border)] my-1"></div>
                <button onClick={() => startAdd("bankAccount")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3" /></svg>
                  Bank Account
                </button>
                <button onClick={() => startAdd("driversLicense")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0h4" /></svg>
                  Driver License
                </button>
                <button onClick={() => startAdd("passport")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                  Passport & ID
                </button>
              </div>
              </Show>
            </div>
            <button
              onClick={() => setShowGenerator(true)}
              class="p-2 rounded-xl bg-[var(--color-sidebar)] hover:bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] text-sm transition-all cursor-pointer"
              title="Password Generator"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
            </button>
          </div>

          {/* Search Input bar */}
          <div class="px-6 pb-4 shrink-0">
            <div class="relative">
              <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[var(--color-muted)]">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              </span>
              <input
                type="text"
                placeholder="Search vault..."
                value={searchQuery()}
                onInput={(e) => setSearchQuery(e.target.value)}
                class="w-full pl-9 pr-4 py-2.5 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-text)] placeholder-slate-500 outline-none focus:border-[var(--color-primary)] transition-all"
              />
              <Show when={searchQuery()}>
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  class="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
                  title="Clear search"
                >
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
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
                <svg class="w-8 h-8 text-[var(--color-muted)] opacity-60 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0a2 2 0 01-2 2H6a2 2 0 01-2-2m16 0V9a2 2 0 00-2-2H6a2 2 0 00-2 2v4m16 0H4"/></svg>
                {t("vault.emptyList")}
              </div>
            </Show>
            
            <For each={filteredCiphers()}>
              {(cipher) => <CipherRow cipher={cipher} />}
            </For>
          </div>
        </div>
      </div>

      {/* ── Column 3: Main Details / Edit Panel ── */}
      <div class="flex-1 bg-[var(--color-detail)] flex flex-col min-w-0">
        <Show when={error()}>
          <div class="m-6 p-3 rounded-xl bg-red-950/40 border border-red-900/50 text-red-300 text-sm shrink-0 flex items-center gap-2">
            <svg class="w-5 h-5 shrink-0 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            {error()}
          </div>
        </Show>

        <Show when={activePane() === "detail" && viewCipher()}>
          <CipherDetail />
        </Show>
        <Show when={activePane() === "add"}>
          <AddEditCipherForm isEdit={false} />
        </Show>
        <Show when={activePane() === "edit"}>
          <AddEditCipherForm isEdit={true} />
        </Show>
        <Show when={activePane() === "welcome"}>
          <div class="flex-1 flex flex-col items-center justify-center text-[var(--color-muted)] p-8">
            <div class="w-20 h-20 rounded-3xl bg-[var(--color-sidebar)] border border-[var(--color-border)] flex items-center justify-center text-slate-500 mb-6 shadow-inner">
              <svg class="w-10 h-10 text-[var(--color-primary)] opacity-85" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            </div>
            <p class="text-xs text-[var(--color-muted)] mt-2 max-w-xs text-center leading-relaxed font-semibold">
              {t("entry.selectPrompt")}
            </p>
          </div>
        </Show>
      </div>
    </div>
  );
}

