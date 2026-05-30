import { createSignal, onMount, Show, For, createContext, useContext, createEffect } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "./i18n/index.jsx";

// ── Error sanitization ──
const ERROR_PATTERNS = [
  { pattern: /Cannot connect/i, key: "errors.daemonNotRunning" },
  { pattern: /Vault not/i, key: "errors.vaultNotUnlocked" },
  { pattern: /timeout/i, key: "errors.timeout" },
  { pattern: /Frame too large/i, key: "errors.responseTooLarge" },
  { pattern: /Invalid session token/i, key: "errors.sessionExpired" },
  { pattern: /identity mismatch/i, key: "errors.integrityFailed" },
  { pattern: /invalid password|incorrect password|password incorrect/i, key: "errors.invalidPassword" },
  { pattern: /corrupt(ed|ion)?/i, key: "errors.corrupted" },
  { pattern: /already exists/i, key: "errors.alreadyExists" },
];

function sanitizeError(raw, t) {
  const str = typeof raw === "string" ? raw : (raw?.message || String(raw || ""));
  for (const { pattern, key } of ERROR_PATTERNS) {
    if (pattern.test(str)) return t(key);
  }
  if (import.meta.env.DEV) return `DEBUG: ${str}`;
  return t("errors.unexpected");
}

// Helper to generate password
function generateSecurePassword(length = 16, useUpper = true, useNumbers = true, useSymbols = true) {
  const lowercase = "abcdefghijklmnopqrstuvwxyz";
  const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
  
  let pool = lowercase;
  if (useUpper) pool += uppercase;
  if (useNumbers) pool += numbers;
  if (useSymbols) pool += symbols;
  
  let result = "";
  for (let i = 0; i < length; i++) {
    result += pool.charAt(Math.floor(Math.random() * pool.length));
  }
  return result;
}

// ── App-wide state context ──
const AppContext = createContext();

function AppProvider(props) {
  const [status, setStatus] = createSignal("locked");
  const [ciphers, setCiphers] = createSignal([]);
  const [error, setError] = createSignal("");
  const [vaultInfo, setVaultInfo] = createSignal(null);
  
  // Theme & layout preferences
  const [theme, setTheme] = createSignal("dark");
  
  // Navigation & filter states
  const [selectedCategory, setSelectedCategory] = createSignal("All items");
  const [searchQuery, setSearchQuery] = createSignal("");
  
  // View/Form states
  const [activePane, setActivePane] = createSignal("welcome"); // 'welcome', 'detail', 'add', 'edit'
  const [viewCipher, setViewCipher] = createSignal(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);
  
  // New / Edited entry buffers
  const [newCipher, setNewCipher] = createSignal({
    name: "", username: "", password: "", uri: "", notes: "",
  });
  
  const [recoveryPhrase, setRecoveryPhrase] = createSignal("");
  const [createPassword, setCreatePassword] = createSignal("");

  // Sync theme class on body
  createEffect(() => {
    if (theme() === "light") {
      document.body.classList.add("light-theme");
    } else {
      document.body.classList.remove("light-theme");
    }
  });

  const store = {
    status, setStatus,
    ciphers, setCiphers,
    error, setError,
    vaultInfo, setVaultInfo,
    theme, setTheme,
    selectedCategory, setSelectedCategory,
    searchQuery, setSearchQuery,
    activePane, setActivePane,
    viewCipher, setViewCipher,
    showDeleteConfirm, setShowDeleteConfirm,
    newCipher, setNewCipher,
    recoveryPhrase, setRecoveryPhrase,
    createPassword, setCreatePassword,
  };

  return (
    <AppContext.Provider value={store}>
      {props.children}
    </AppContext.Provider>
  );
}

function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}

// ── Daemon proxy ──
async function daemon(action, payload = "") {
  const res = await invoke("daemon_request", { action, payload });
  if (!res.success) {
    throw new Error(res.error);
  }
  return res.payload;
}

// ── Actions ──
function useActions() {
  const app = useApp();
  let loginPasswordRef;

  async function unlock(t) {
    const password = loginPasswordRef?.value;
    if (!password) return;
    app.setStatus("unlocking");
    app.setError("");
    try {
      await daemon("vault.open");
      await daemon("vault.unlock", password);
      if (loginPasswordRef) loginPasswordRef.value = "";
      app.setStatus("unlocked");
      await refreshCiphers();
      const info = JSON.parse(await daemon("vault.info"));
      app.setVaultInfo(info);
    } catch (e) {
      app.setError(sanitizeError(e, t));
      app.setStatus("locked");
    }
  }

  async function lock(t) {
    try {
      await daemon("vault.lock");
      app.setStatus("locked");
      app.setCiphers([]);
      app.setVaultInfo(null);
      app.setViewCipher(null);
      app.setActivePane("welcome");
      app.setShowDeleteConfirm(false);
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function createVault(t) {
    const pw = app.createPassword();
    const confirm = document.getElementById("create-confirm")?.value;
    if (!pw || pw.length < 8) { app.setError(t("create.errorMinLength")); return; }
    if (pw !== confirm) { app.setError(t("create.errorMismatch")); return; }
    app.setStatus("creating");
    app.setError("");
    try {
      const result = JSON.parse(await daemon("vault.create", JSON.stringify({
        password: pw, profile: "desktop_std",
      })));
      app.setRecoveryPhrase(result.recovery_phrase);
      app.setStatus("recovery");
    } catch (e) {
      app.setError(sanitizeError(e, t));
      app.setStatus("init");
    }
  }

  async function refreshCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.list"));
      const ids = data.cipher_ids || [];
      
      // Decrypt and load full details in parallel so client-side lists, details & search are lightning-fast
      const fullCiphers = await Promise.all(
        ids.map(async (id) => {
          try {
            const detailStr = await daemon("vault.get", JSON.stringify({ id, decrypt: true }));
            return JSON.parse(detailStr);
          } catch (e) {
            return { id, name: "Decryption Error", username: "", uris: [] };
          }
        })
      );
      
      app.setCiphers(fullCiphers);
    } catch (e) {
      // Non-critical
    }
  }

  async function addCipher(t) {
    const c = app.newCipher();
    if (!c.name) {
      app.setError(t("entry.namePlaceholder") + " required");
      return;
    }
    try {
      await daemon("vault.add", JSON.stringify({
        name: c.name,
        username: c.username || null,
        password: c.password || null,
        uris: c.uri ? [c.uri] : [],
        notes: c.notes || null,
        totp_uri: null,
        folder_id: null,
        custom_fields: [],
      }));
      app.setNewCipher({ name: "", username: "", password: "", uri: "", notes: "" });
      app.setActivePane("welcome");
      await refreshCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function updateCipher(id, t) {
    const c = app.newCipher();
    if (!c.name) {
      app.setError(t("entry.namePlaceholder") + " required");
      return;
    }
    try {
      // 1. Delete original cipher
      await daemon("vault.delete", id);
      // 2. Add as updated cipher
      const newId = await daemon("vault.add", JSON.stringify({
        name: c.name,
        username: c.username || null,
        password: c.password || null,
        uris: c.uri ? [c.uri] : [],
        notes: c.notes || null,
        totp_uri: null,
        folder_id: null,
        custom_fields: [],
      }));
      app.setActivePane("welcome");
      await refreshCiphers();
      
      // Select the updated item
      const updatedData = JSON.parse(await daemon("vault.get", JSON.stringify({ id: newId, decrypt: true })));
      app.setViewCipher(updatedData);
      app.setActivePane("detail");
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function getCipher(id, t) {
    try {
      const data = JSON.parse(await daemon("vault.get", JSON.stringify({ id, decrypt: true })));
      app.setViewCipher(data);
      app.setActivePane("detail");
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function deleteCipher(id, t) {
    try {
      await daemon("vault.delete", id);
      app.setViewCipher(null);
      app.setActivePane("welcome");
      app.setShowDeleteConfirm(false);
      await refreshCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  function onKeyUnlock(e) {
    if (e.key === "Enter") unlock(useI18n().t);
  }

  return { loginPasswordRef, setLoginPasswordRef: (r) => { loginPasswordRef = r; }, unlock, lock, createVault, refreshCiphers, addCipher, updateCipher, getCipher, deleteCipher, onKeyUnlock };
}

// ── Shared UI Utilities ──
function getCuratedColor(name) {
  const colors = [
    "bg-emerald-600", "bg-teal-600", "bg-cyan-600", "bg-purple-600", "bg-violet-600",
    "bg-indigo-600", "bg-blue-600", "bg-rose-600", "bg-pink-600", "bg-lime-600"
  ];
  if (!name) return colors[0];
  const charCodeSum = name.split("").reduce((sum, c) => sum + c.charCodeAt(0), 0);
  return colors[charCodeSum % colors.length];
}

function getDomainInitials(name) {
  if (!name) return "?";
  let cleanName = name.replace(/^(https?:\/\/)?(www\.)?/, "");
  return cleanName.charAt(0).toUpperCase();
}

function ThemeToggleFloating() {
  const { theme, setTheme } = useApp();
  return (
    <div class="absolute top-4 right-4 z-50">
      <button
        onClick={() => setTheme(theme() === "dark" ? "light" : "dark")}
        class="p-2.5 rounded-xl bg-[var(--color-sidebar)] hover:bg-[var(--color-card)] border border-[var(--color-border)] text-slate-400 hover:text-white transition-all cursor-pointer shadow-md"
        title="Toggle Theme"
      >
        <Show when={theme() === "dark"} fallback={
          <svg class="w-4.5 h-4.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m12.728 12.728l.707.707M12 8a4 4 0 100 8 4 4 0 000-8z"/></svg>
        }>
          <svg class="w-4.5 h-4.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </Show>
      </button>
    </div>
  );
}

function DeleteConfirmModal() {
  const { viewCipher, setShowDeleteConfirm, showDeleteConfirm } = useApp();
  const { deleteCipher } = useActions();
  const { t } = useI18n();

  let cancelBtnRef;
  let deleteBtnRef;

  createEffect(() => {
    if (showDeleteConfirm()) {
      setTimeout(() => cancelBtnRef?.focus(), 50);
    }
  });

  function handleKeyDown(e) {
    if (e.key === "Escape") {
      setShowDeleteConfirm(false);
    } else if (e.key === "ArrowLeft" || e.key === "ArrowRight" || e.key === "Tab") {
      e.preventDefault();
      if (document.activeElement === cancelBtnRef) {
        deleteBtnRef?.focus();
      } else {
        cancelBtnRef?.focus();
      }
    }
  }

  return (
    <Show when={showDeleteConfirm()}>
      <div 
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
        onKeyDown={handleKeyDown}
      >
        <div class="w-full max-w-sm p-6 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative animate-scale-in text-center">
          <div class="w-12 h-12 rounded-full bg-red-950/20 text-red-500 border border-red-900/30 flex items-center justify-center mx-auto mb-4">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          </div>
          
          <h3 class="text-lg font-bold text-[var(--color-text)]">Delete Entry?</h3>
          <p class="text-xs text-[var(--color-muted)] mt-2 leading-relaxed px-2">
            Are you sure you want to delete <strong class="text-[var(--color-text)] font-semibold select-all">{viewCipher()?.name}</strong>? This action cannot be undone.
          </p>

          <div class="mt-6 flex gap-3">
            <button
              ref={cancelBtnRef}
              onClick={() => setShowDeleteConfirm(false)}
              class="flex-1 py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold transition-all text-xs outline-none focus:ring-2 focus:ring-[var(--color-primary)] cursor-pointer"
            >
              Cancel
            </button>
            <button
              ref={deleteBtnRef}
              onClick={() => deleteCipher(viewCipher().id, t)}
              class="flex-1 py-3 px-4 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold transition-all text-xs outline-none focus:ring-2 focus:ring-red-400 cursor-pointer"
            >
              Delete
            </button>
          </div>
        </div>
      </div>
    </Show>
  );
}

// ── Views ──

function LoginScreen() {
  const app = useApp();
  const { unlock, setLoginPasswordRef } = useActions();
  const { t } = useI18n();
  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      
      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">
        {/* Glow accents */}
        <div class="absolute -top-10 -left-10 w-40 h-40 bg-[var(--color-primary)] rounded-full blur-3xl opacity-10 pointer-events-none"></div>
        <div class="absolute -bottom-10 -right-10 w-40 h-40 bg-[var(--color-accent)] rounded-full blur-3xl opacity-10 pointer-events-none"></div>

        <div class="text-center mb-8">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-[var(--color-sidebar)] to-[var(--color-border)] border border-[var(--color-border)] flex items-center justify-center shadow-lg">
            <svg class="w-8 h-8 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("login.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("login.subtitle")}</p>
        </div>

        <Show when={app.error()}>
          <div class="mb-4 p-3 rounded-xl bg-red-950/40 border border-red-900/50 text-red-300 text-sm flex items-center gap-2">
            <svg class="w-5 h-5 shrink-0 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            {app.error()}
          </div>
        </Show>

        <form onSubmit={(e) => { e.preventDefault(); unlock(t); }} class="space-y-4">
          <div>
            <input
              ref={setLoginPasswordRef}
              type="password"
              placeholder={t("login.passwordPlaceholder")}
              class="w-full px-4 py-3.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)] transition-all-fast"
              autofocus
            />
          </div>

          <button
            type="submit"
            disabled={app.status() === "unlocking"}
            class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg shadow-black/10 active:scale-[0.99] disabled:opacity-50 cursor-pointer"
          >
            {app.status() === "unlocking" ? t("login.unlocking") : t("login.unlock")}
          </button>
        </form>

        <div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
          <button
            onClick={() => app.setStatus("init")}
            class="text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("login.createNew")}
          </button>
        </div>
      </div>
    </div>
  );
}

function CipherRow(props) {
  const { getCipher } = useActions();
  const { viewCipher, activePane } = useApp();
  const { t } = useI18n();

  const isSelected = () => viewCipher()?.id === props.cipher.id && activePane() === "detail";

  return (
    <div
      class={`flex items-center justify-between p-3.5 rounded-xl cursor-pointer transition-all-fast group ${
        isSelected() 
          ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] shadow-md" 
          : "bg-transparent hover:bg-slate-800/20 border border-transparent hover:border-[var(--color-border)] text-[var(--color-text)]"
      }`}
      onClick={() => getCipher(props.cipher.id, t)}
    >
      <div class="flex items-center gap-3.5 min-w-0 flex-1">
        <div class={`w-10 h-10 rounded-xl flex items-center justify-center text-white font-bold shrink-0 shadow-md ${
          isSelected() ? "bg-[var(--color-primary-text)]/20" : getCuratedColor(props.cipher.name)
        }`}>
          {getDomainInitials(props.cipher.name)}
        </div>
        <div class="min-w-0 flex-1">
          <div class={`text-sm font-semibold truncate ${isSelected() ? "text-[var(--color-primary-text)]" : "text-[var(--color-text)]"}`}>
            {props.cipher.name || "Untitled"}
          </div>
          <div class={`text-xs truncate mt-0.5 ${isSelected() ? "text-[var(--color-primary-text)]/75" : "text-[var(--color-muted)]"}`}>
            {props.cipher.username || (props.cipher.uris?.[0] || "No username")}
          </div>
        </div>
      </div>
      
      {/* Quick Actions */}
      <div class="flex items-center gap-1.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity ml-2">
        <Show when={props.cipher.uris?.[0]}>
          <a
            href={props.cipher.uris[0].startsWith("http") ? props.cipher.uris[0] : `https://${props.cipher.uris[0]}`}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            title="Launch website"
            class={`p-1.5 rounded-lg transition-colors ${
              isSelected() ? "hover:bg-black/10 text-[var(--color-primary-text)]" : "hover:bg-[var(--color-sidebar)] text-[var(--color-muted)] hover:text-[var(--color-text)]"
            }`}
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        </Show>
        <button
          onClick={(e) => {
            e.stopPropagation();
            navigator.clipboard.writeText(props.cipher.password || "");
          }}
          title="Copy password"
          class={`p-1.5 rounded-lg transition-colors cursor-pointer ${
            isSelected() ? "hover:bg-black/10 text-[var(--color-primary-text)]" : "hover:bg-[var(--color-sidebar)] text-[var(--color-muted)] hover:text-[var(--color-text)]"
          }`}
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
          </svg>
        </button>
      </div>
    </div>
  );
}

function CopyableField(props) {
  const [copied, setCopied] = createSignal(false);
  
  function handleCopy() {
    navigator.clipboard.writeText(props.value || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] hover:border-[var(--color-primary)] transition-colors flex items-center justify-between group">
      <div class="min-w-0 flex-1">
        <label class="text-[10px] text-[var(--color-muted)] block uppercase tracking-wider font-extrabold">{props.label}</label>
        <Show when={props.isPassword} fallback={
          <div class="text-sm text-[var(--color-text)] font-semibold truncate mt-0.5 select-all">{props.value || "—"}</div>
        }>
          <div class="text-sm font-mono text-[var(--color-text)] tracking-widest mt-0.5 select-all truncate">
            {props.showPassword ? props.value : "••••••••••••••••"}
          </div>
        </Show>
      </div>
      <div class="flex items-center gap-1 shrink-0 ml-2">
        <Show when={props.isPassword}>
          <button
            onClick={props.onToggleShow}
            class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer"
            title={props.showPassword ? "Hide" : "Show"}
          >
            <Show when={props.showPassword} fallback={
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
            }>
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
            </Show>
          </button>
        </Show>
        <button
          onClick={handleCopy}
          class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer relative"
          title="Copy to clipboard"
        >
          <Show when={copied()} fallback={
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
          }>
            <span class="text-[9px] text-[var(--color-success)] font-extrabold uppercase tracking-wider">Copied</span>
          </Show>
        </button>
      </div>
    </div>
  );
}

function CipherDetail() {
  const { viewCipher, setViewCipher, setActivePane, setNewCipher, setShowDeleteConfirm } = useApp();
  const { t } = useI18n();

  const [revealPass, setRevealPass] = createSignal(false);

  function startEdit() {
    const c = viewCipher();
    if (!c) return;
    setNewCipher({
      name: c.name || "",
      username: c.username || "",
      password: c.password || "",
      uri: c.uris?.[0] || "",
      notes: c.notes || "",
    });
    setActivePane("edit");
  }

  return (
    <div class="h-full flex flex-col justify-between">
      <div class="flex-1 overflow-y-auto p-8 space-y-6">
        {/* Title Header */}
        <div class="flex items-start gap-5 pb-6 border-b border-[var(--color-border)]">
          <div class={`w-16 h-16 rounded-2xl flex items-center justify-center text-white text-3xl font-extrabold shadow-lg ${getCuratedColor(viewCipher()?.name)}`}>
            {getDomainInitials(viewCipher()?.name)}
          </div>
          <div class="min-w-0 flex-1">
            <h3 class="text-2xl font-bold text-[var(--color-text)] truncate leading-tight select-all">{viewCipher()?.name || "Untitled"}</h3>
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] mt-2">
              <span class="w-1.5 h-1.5 bg-[var(--color-primary)] rounded-full"></span>
              Login Item
            </span>
          </div>
          <button
            onClick={() => setActivePane("welcome")}
            class="p-2 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-xl transition-colors cursor-pointer"
            title="Close details"
          >
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>

        {/* Credentials group */}
        <div class="space-y-4">
          <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Login credentials</h4>
          
          <CopyableField label={t("entry.user")} value={viewCipher()?.username} />
          
          <CopyableField 
            label={t("entry.pass")} 
            value={viewCipher()?.password} 
            isPassword={true}
            showPassword={revealPass()}
            onToggleShow={() => setRevealPass(!revealPass())}
          />
        </div>

        {/* Website URI group */}
        <Show when={viewCipher()?.uris?.length}>
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Website</h4>
            <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-between group hover:border-[var(--color-primary)] transition-all">
              <div class="min-w-0 flex-1">
                <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block">Website URL</label>
                <a
                  href={viewCipher()?.uris[0].startsWith("http") ? viewCipher()?.uris[0] : `https://${viewCipher()?.uris[0]}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-sm text-[var(--color-accent)] hover:underline font-semibold mt-0.5 inline-block"
                >
                  {viewCipher()?.uris[0]}
                </a>
              </div>
              <a
                href={viewCipher()?.uris[0].startsWith("http") ? viewCipher()?.uris[0] : `https://${viewCipher()?.uris[0]}`}
                target="_blank"
                rel="noopener noreferrer"
                class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors"
                title="Launch website"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
              </a>
            </div>
          </div>
        </Show>

        {/* Notes group */}
        <Show when={viewCipher()?.notes}>
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">{t("entry.notes")}</h4>
            <div class="p-4 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] leading-relaxed font-semibold whitespace-pre-wrap select-text">
              {viewCipher()?.notes}
            </div>
          </div>
        </Show>
      </div>

      {/* Footer Details Action bar */}
      <div class="p-6 bg-[var(--color-sidebar)] border-t border-[var(--color-border)] flex items-center justify-between gap-4">
        <button
          onClick={startEdit}
          class="flex-1 py-3 px-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
          Edit
        </button>
        <button
          onClick={() => setShowDeleteConfirm(true)}
          class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
          {t("entry.delete")}
        </button>
      </div>
    </div>
  );
}

function AddEditCipherForm(props) {
  const { newCipher, setNewCipher, setActivePane, viewCipher } = useApp();
  const { addCipher, updateCipher } = useActions();
  const { t } = useI18n();

  // Generator states
  const [genLen, setGenLen] = createSignal(16);
  const [showGen, setShowGen] = createSignal(false);
  const [genUpper, setGenUpper] = createSignal(true);
  const [genNums, setGenNums] = createSignal(true);
  const [genSyms, setGenSyms] = createSignal(true);

  function handleGenerate() {
    const pw = generateSecurePassword(genLen(), genUpper(), genNums(), genSyms());
    setNewCipher({ ...newCipher(), password: pw });
  }

  function handleSave() {
    if (props.isEdit) {
      updateCipher(viewCipher().id, t);
    } else {
      addCipher(t);
    }
  }

  return (
    <div class="h-full flex flex-col justify-between">
      <div class="flex-1 overflow-y-auto p-8 space-y-6">
        <div class="flex items-center justify-between pb-6 border-b border-[var(--color-border)]">
          <h3 class="text-xl font-bold text-[var(--color-text)] flex items-center gap-2">
            <span class="w-3 h-3 rounded-full bg-[var(--color-primary)]"></span>
            {props.isEdit ? "Edit Entry" : t("entry.addTitle")}
          </h3>
          <button 
            onClick={() => setActivePane(props.isEdit ? "detail" : "welcome")} 
            class="p-2 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-xl transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        <div class="space-y-4">
          <div>
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Item Name</label>
            <input 
              placeholder={t("entry.namePlaceholder")} 
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
              value={newCipher().name} 
              onInput={e => setNewCipher({ ...newCipher(), name: e.target.value })} 
            />
          </div>

          <div>
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">{t("entry.user")}</label>
            <input 
              placeholder={t("entry.usernamePlaceholder")} 
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
              value={newCipher().username} 
              onInput={e => setNewCipher({ ...newCipher(), username: e.target.value })} 
            />
          </div>

          {/* Password generator */}
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("entry.pass")}</label>
              <button
                onClick={() => { setShowGen(!showGen()); if (!newCipher().password) handleGenerate(); }}
                class="text-xs font-bold text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
              >
                {showGen() ? "Close Generator" : "Generate Password"}
              </button>
            </div>
            <div class="relative">
              <input 
                placeholder={t("entry.passwordPlaceholder")} 
                type="text" 
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                value={newCipher().password} 
                onInput={e => setNewCipher({ ...newCipher(), password: e.target.value })} 
              />
            </div>

            <Show when={showGen()}>
              <div class="mt-3 p-4 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-4">
                <div class="flex items-center justify-between text-xs text-[var(--color-text)]">
                  <span>Length: <strong class="text-[var(--color-primary)] text-sm">{genLen()}</strong></span>
                  <input
                    type="range"
                    min="8"
                    max="64"
                    value={genLen()}
                    onInput={(e) => { setGenLen(parseInt(e.target.value)); handleGenerate(); }}
                    class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer"
                  />
                </div>
                
                <div class="grid grid-cols-3 gap-2">
                  <button
                    onClick={() => { setGenUpper(!genUpper()); handleGenerate(); }}
                    class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${
                      genUpper() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"
                    }`}
                  >
                    A-Z
                  </button>
                  <button
                    onClick={() => { setGenNums(!genNums()); handleGenerate(); }}
                    class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${
                      genNums() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"
                    }`}
                  >
                    0-9
                  </button>
                  <button
                    onClick={() => { setGenSyms(!genSyms()); handleGenerate(); }}
                    class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${
                      genSyms() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"
                    }`}
                  >
                    !@#
                  </button>
                </div>
                <button
                  onClick={handleGenerate}
                  class="w-full py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] hover:bg-[var(--color-sidebar)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer"
                >
                  Generate New
                </button>
              </div>
            </Show>
          </div>

          <div>
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">{t("entry.uri")}</label>
            <input 
              placeholder={t("entry.uriPlaceholder")} 
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
              value={newCipher().uri} 
              onInput={e => setNewCipher({ ...newCipher(), uri: e.target.value })} 
            />
          </div>

          <div>
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">{t("entry.notes")}</label>
            <textarea 
              placeholder={t("entry.notesPlaceholder")} 
              rows="4"
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all resize-none"
              value={newCipher().notes} 
              onInput={e => setNewCipher({ ...newCipher(), notes: e.target.value })} 
            />
          </div>
        </div>
      </div>

      <div class="p-6 bg-[var(--color-sidebar)] border-t border-[var(--color-border)] flex gap-4">
        <button
          onClick={handleSave}
          class="flex-1 py-3 px-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-extrabold transition-all cursor-pointer shadow-lg active:scale-[0.99]"
        >
          Save
        </button>
        <button
          onClick={() => setActivePane(props.isEdit ? "detail" : "welcome")}
          class="flex-1 py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold transition-all cursor-pointer active:scale-[0.99]"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function VaultView() {
  const { ciphers, vaultInfo, error, selectedCategory, setSelectedCategory, searchQuery, setSearchQuery, activePane, setActivePane, viewCipher, setNewCipher, theme, setTheme } = useApp();
  const { lock } = useActions();
  const { t } = useI18n();

  // Categories
  const categories = [
    { name: "All items", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg> },
    { name: "Favorites", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" /></svg> },
    { name: "Login", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg> },
    { name: "Card", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg> },
    { name: "Identity", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg> },
    { name: "Secure note", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg> },
    { name: "SSH key", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m0 0a2 2 0 01-2 2m2-2h2a2 2 0 002-2V5a2 2 0 00-2-2h-2a2 2 0 00-2 2v2m0 0h-2m-2 0A5 5 0 113 12a5 5 0 0110 0v1a2 2 0 002 2h2a2 2 0 002-2v-1a2 2 0 00-2-2h-2" /></svg> }
  ];

  // Client-side filtering & search
  const filteredCiphers = () => {
    let list = ciphers() || [];
    const cat = selectedCategory();
    const query = searchQuery().toLowerCase();

    // Category filtering
    if (cat === "Favorites") {
      list = list.slice(0, Math.min(list.length, 2));
    } else if (cat === "Login") {
      list = list.filter(c => c.username || c.password);
    } else if (cat === "Card") {
      list = list.filter(c => c.name?.toLowerCase().includes("card") || c.notes?.toLowerCase().includes("card"));
    } else if (cat === "Identity") {
      list = list.filter(c => c.name?.toLowerCase().includes("id") || c.notes?.toLowerCase().includes("identity"));
    } else if (cat === "Secure note") {
      list = list.filter(c => !c.username && !c.password && c.notes);
    } else if (cat === "SSH key") {
      list = list.filter(c => c.name?.toLowerCase().includes("ssh") || c.name?.toLowerCase().includes("key"));
    }

    // Search query filtering
    if (query) {
      list = list.filter(c => 
        c.name?.toLowerCase().includes(query) ||
        c.username?.toLowerCase().includes(query) ||
        (c.uris && c.uris.some(u => u.toLowerCase().includes(query))) ||
        c.notes?.toLowerCase().includes(query)
      );
    }
    return list;
  };

  function startAdd() {
    setNewCipher({ name: "", username: "", password: "", uri: "", notes: "" });
    setActivePane("add");
  }

  return (
    <div class="flex h-full overflow-hidden select-none">
      <DeleteConfirmModal />
      
      {/* ── Column 1: Left Navigation Sidebar ── */}
      <div class="w-[260px] bg-[var(--color-sidebar)] border-r border-[var(--color-border)] flex flex-col justify-between shrink-0">
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
                      onClick={() => setSelectedCategory(cat.name)}
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
                    </button>
                  )}
                </For>
              </div>
            </div>
            
            {/* Folders */}
            <div>
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)]">
                Folders
              </div>
              <div class="space-y-0.5 mt-1">
                <button class="w-full px-3.5 py-2 rounded-xl text-xs font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10 flex items-center gap-3 text-left cursor-pointer">
                  <svg class="w-4 h-4 text-[var(--color-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                  Others
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar Footer Lock & Theme Toggle */}
        <div class="p-4 border-t border-[var(--color-border)] flex items-center justify-between gap-3 bg-[var(--color-sidebar)]">
          <div class="flex items-center gap-3 min-w-0">
            <div class="w-9 h-9 rounded-full bg-gradient-to-tr from-[var(--color-accent)] to-[var(--color-primary)] flex items-center justify-center text-[var(--color-sidebar)] font-extrabold text-xs shadow-md">
              ES
            </div>
            <div class="min-w-0 flex-1">
              <div class="text-xs font-bold text-[var(--color-text)] truncate leading-none">EstebanForge</div>
              <div class="text-[9px] text-[var(--color-muted)] truncate mt-1">Lead Architect</div>
            </div>
          </div>
          <div class="flex items-center gap-1.5 shrink-0">
            <button
              onClick={() => setTheme(theme() === "dark" ? "light" : "dark")}
              title={theme() === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
              class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
            >
              <Show when={theme() === "dark"} fallback={
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m12.728 12.728l.707.707M12 8a4 4 0 100 8 4 4 0 000-8z"/></svg>
              }>
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
              </Show>
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

      {/* ── Column 2: Vault Items List Pane ── */}
      <div class="w-[360px] bg-[var(--color-list)] border-r border-[var(--color-border)] flex flex-col justify-between shrink-0">
        <div class="flex-1 flex flex-col min-h-0">
          
          {/* Header Action Bar */}
          <div class="p-6 pb-4 flex items-center justify-between gap-4 shrink-0">
            <div>
              <h2 class="text-xl font-bold tracking-tight text-[var(--color-text)]">{selectedCategory()}</h2>
              <div class="text-xs text-[var(--color-muted)] mt-0.5">
                {t("vault.entryCount", { count: filteredCiphers().length })}
              </div>
            </div>
            
            <button
              onClick={startAdd}
              class="px-4 py-2 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all shadow-md active:scale-[0.98] cursor-pointer"
            >
              + New
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
                  onClick={() => setSearchQuery("")}
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
            <h3 class="text-lg font-bold text-[var(--color-text)]">Vault is secure</h3>
            <p class="text-xs text-[var(--color-muted)] mt-2 max-w-xs text-center leading-relaxed font-semibold">
              {t("entry.selectPrompt")}
            </p>
          </div>
        </Show>
      </div>
    </div>
  );
}

// ── Create / Recovery Views ──

function CreateVaultScreen() {
  const app = useApp();
  const { createVault } = useActions();
  const { t } = useI18n();
  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">
        
        <div class="text-center mb-8">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-[var(--color-sidebar)] to-[var(--color-border)] border border-[var(--color-border)] flex items-center justify-center shadow-lg">
            <svg class="w-8 h-8 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("create.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("create.subtitle")}</p>
        </div>

        <Show when={app.error()}>
          <div class="mb-4 p-3 rounded-xl bg-red-950/40 border border-red-900/50 text-red-300 text-sm flex items-center gap-2">
            <svg class="w-5 h-5 shrink-0 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            {app.error()}
          </div>
        </Show>

        <form onSubmit={(e) => { e.preventDefault(); createVault(t); }} class="space-y-4">
          <input
            id="create-password"
            type="password"
            placeholder={t("create.passwordPlaceholder")}
            onInput={e => app.setCreatePassword(e.target.value)}
            class="w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
          />
          <input
            id="create-confirm"
            type="password"
            placeholder={t("create.confirmPlaceholder")}
            class="w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
          />
          <button
            type="submit"
            disabled={app.status() === "creating"}
            class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg active:scale-[0.99] disabled:opacity-50 cursor-pointer"
          >
            {app.status() === "creating" ? t("create.creating") : t("create.submit")}
          </button>
        </form>

        <div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
          <button
            onClick={() => app.setStatus("locked")}
            class="text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("create.alreadyHaveVault")}
          </button>
        </div>
      </div>
    </div>
  );
}

function RecoveryScreen() {
  const app = useApp();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();
  const [copied, setCopied] = createSignal(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(app.recoveryPhrase());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">
        
        <div class="text-center mb-6">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-emerald-600 to-teal-500 flex items-center justify-center shadow-lg">
            <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("recovery.title")}</h1>
          <p class="text-sm text-red-400 mt-2 font-semibold">{t("recovery.warning")}</p>
        </div>

        <div class="relative group p-5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] font-mono text-sm leading-relaxed text-[var(--color-text)] break-words select-all mb-6 text-center select-all shadow-inner pr-12">
          {app.recoveryPhrase()}
          <button
            onClick={handleCopy}
            class="absolute top-2 right-2 p-1.5 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-detail)] transition-all cursor-pointer shadow-sm flex items-center gap-1 text-xs"
            title="Copy to clipboard"
          >
            <Show when={copied()} fallback={
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 002 2h2a2 2 0 002-2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
            }>
              <span class="text-emerald-500 font-sans font-medium text-xs">Copied!</span>
              <svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
            </Show>
          </button>
        </div>

        <form onSubmit={async (e) => {
          e.preventDefault();
          app.setStatus("unlocking");
          const pw = app.createPassword();
          if (pw) {
            try {
              await daemon("vault.unlock", pw);
              app.setStatus("unlocked");
              app.setCreatePassword("");
              await refreshCiphers();
            } catch (err) { app.setError(sanitizeError(err, t)); app.setStatus("locked"); }
          } else { app.setStatus("locked"); }
        }} class="space-y-4">
          <button
            type="submit"
            class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg cursor-pointer"
          >
            {t("recovery.confirm")}
          </button>
        </form>
      </div>
    </div>
  );
}

// ── Root App ──
export default function App() {
  return (
    <AppProvider>
      <AppInner />
    </AppProvider>
  );
}

function AppInner() {
  const { setStatus, setError, setVaultInfo, status } = useApp();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();

  onMount(async () => {
    try {
      await daemon("vault.open");
    } catch (e) {
      if (ERROR_PATTERNS.some(({ pattern }) => pattern.test(e.message))) {
        if (/Cannot connect/i.test(e.message)) {
          setError("");
          return;
        }
      }
      setStatus("init");
      return;
    }
    try {
      const info = JSON.parse(await daemon("vault.info"));
      if (info.unlocked) {
        setStatus("unlocked");
        setVaultInfo(info);
        await refreshCiphers();
      }
    } catch {}
  });

  return (
    <Show when={status() === "unlocked"} fallback={
      <Show when={status() === "init" || status() === "creating"} fallback={
        <Show when={status() === "recovery"} fallback={<LoginScreen />}>
          <RecoveryScreen />
        </Show>
      }>
        <CreateVaultScreen />
      </Show>
    }>
      <VaultView />
    </Show>
  );
}
