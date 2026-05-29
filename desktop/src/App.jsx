import { createSignal, onMount, Show, For, createContext, useContext } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "./i18n/index.jsx";

// ── Error sanitization (M5) ──
// Maps raw daemon errors to i18n keys.
// Unknown patterns are fully redacted (no partial leakage).
const ERROR_PATTERNS = [
  { pattern: /Cannot connect/i, key: "errors.daemonNotRunning" },
  { pattern: /Vault not/i, key: "errors.vaultNotUnlocked" },
  { pattern: /timeout/i, key: "errors.timeout" },
  { pattern: /Frame too large/i, key: "errors.responseTooLarge" },
  { pattern: /Invalid session token/i, key: "errors.sessionExpired" },
  { pattern: /identity mismatch/i, key: "errors.integrityFailed" },
  { pattern: /corrupt(ed|ion)?/i, key: "errors.corrupted" },
  { pattern: /already exists/i, key: "errors.alreadyExists" },
];

function sanitizeError(raw, t) {
  for (const { pattern, key } of ERROR_PATTERNS) {
    if (pattern.test(raw)) return t(key);
  }
  if (import.meta.env.DEV) return `DEBUG: ${raw}`;
  return t("errors.unexpected");
}

// ── App-wide state context (M4) ──

const AppContext = createContext();

function AppProvider(props) {
  const [status, setStatus] = createSignal("locked");
  const [ciphers, setCiphers] = createSignal([]);
  const [error, setError] = createSignal("");
  const [vaultInfo, setVaultInfo] = createSignal(null);
  const [showAdd, setShowAdd] = createSignal(false);
  const [viewCipher, setViewCipher] = createSignal(null);
  const [newCipher, setNewCipher] = createSignal({
    name: "", username: "", password: "", uri: "", notes: "",
  });
  const [recoveryPhrase, setRecoveryPhrase] = createSignal("");
  const [createPassword, setCreatePassword] = createSignal("");

  const store = {
    status, setStatus,
    ciphers, setCiphers,
    error, setError,
    vaultInfo, setVaultInfo,
    showAdd, setShowAdd,
    viewCipher, setViewCipher,
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

  async function unlock() {
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
      app.setError(e.message);
      app.setStatus("locked");
    }
  }

  async function lock() {
    try {
      await daemon("vault.lock");
      app.setStatus("locked");
      app.setCiphers([]);
      app.setVaultInfo(null);
      app.setViewCipher(null);
      app.setShowAdd(false);
    } catch (e) {
      app.setError(e.message);
    }
  }

  async function createVault() {
    const { t } = useI18n();
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
      app.setError(e.message);
      app.setStatus("init");
    }
  }

  async function refreshCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.list"));
      app.setCiphers(data.cipher_ids || []);
    } catch (e) {
      app.setError(e.message);
    }
  }

  async function addCipher() {
    const c = app.newCipher();
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
      app.setShowAdd(false);
      await refreshCiphers();
    } catch (e) {
      app.setError(e.message);
    }
  }

  async function getCipher(id) {
    try {
      const data = JSON.parse(await daemon("vault.get", JSON.stringify({ id, decrypt: true })));
      app.setViewCipher(data);
    } catch (e) {
      app.setError(e.message);
    }
  }

  async function deleteCipher(id) {
    try {
      await daemon("vault.delete", id);
      app.setViewCipher(null);
      await refreshCiphers();
    } catch (e) {
      app.setError(e.message);
    }
  }

  function onKeyUnlock(e) {
    if (e.key === "Enter") unlock();
  }

  return { loginPasswordRef, setLoginPasswordRef: (r) => { loginPasswordRef = r; }, unlock, lock, createVault, refreshCiphers, addCipher, getCipher, deleteCipher, onKeyUnlock };
}

// ── Views ──

function LoginScreen() {
  const { error, status } = useApp();
  const { onKeyUnlock, unlock, setLoginPasswordRef } = useActions();
  const { t } = useI18n();
  return (
    <div class="flex items-center justify-center h-full">
      <div class="w-80 p-6 rounded-xl bg-[var(--color-surface)] border border-[var(--color-border)]">
        <div class="text-center mb-6">
          <div class="text-3xl mb-2">🔒</div>
          <h1 class="text-xl font-semibold">{t("login.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("login.subtitle")}</p>
        </div>
        <Show when={error()}>
          <div class="mb-3 p-2 rounded bg-red-900/30 text-red-400 text-sm">{error()}</div>
        </Show>
        <input
          ref={setLoginPasswordRef}
          type="password"
          placeholder={t("login.passwordPlaceholder")}
          class="w-full p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] mb-3"
          onKeyDown={onKeyUnlock}
          autofocus
        />
        <button
          onClick={unlock}
          disabled={status() === "unlocking"}
          class="w-full p-3 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white font-medium transition-colors disabled:opacity-50"
        >
          {status() === "unlocking" ? t("login.unlocking") : t("login.unlock")}
        </button>
        <button
          onClick={() => useApp().setStatus("init")}
          class="w-full mt-2 p-2 text-sm text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors"
        >
          {t("login.createNew")}
        </button>
      </div>
    </div>
  );
}

function CipherRow(props) {
  const { getCipher } = useActions();
  return (
    <div
      class="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface)] border border-[var(--color-border)] cursor-pointer hover:border-[var(--color-primary)] transition-colors"
      onClick={() => getCipher(props.id)}
    >
      <div class="flex items-center gap-3">
        <span class="text-lg">🔑</span>
        <span class="text-sm font-mono text-[var(--color-muted)]">{props.name || props.id.slice(0, 8)}</span>
      </div>
    </div>
  );
}

function CipherDetail() {
  const { viewCipher, setViewCipher } = useApp();
  const { deleteCipher } = useActions();
  const { t } = useI18n();
  return (
    <div class="p-4 rounded-xl bg-[var(--color-surface)] border border-[var(--color-border)]">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold">{viewCipher()?.name || t("entry.addTitle")}</h3>
        <button
          onClick={() => setViewCipher(null)}
          class="text-[var(--color-muted)] hover:text-[var(--color-text)] text-xl"
        >
          ✕
        </button>
      </div>
      <div class="space-y-2 text-sm">
        <Show when={viewCipher()?.username}><div><span class="text-[var(--color-muted)]">{t("entry.user")}:</span> {viewCipher().username}</div></Show>
        <Show when={viewCipher()?.password}><div><span class="text-[var(--color-muted)]">{t("entry.pass")}:</span> {viewCipher().password}</div></Show>
        <Show when={viewCipher()?.uris?.length}><div><span class="text-[var(--color-muted)]">{t("entry.uri")}:</span> {viewCipher().uris[0]}</div></Show>
        <Show when={viewCipher()?.notes}><div><span class="text-[var(--color-muted)]">{t("entry.notes")}:</span> {viewCipher().notes}</div></Show>
      </div>
      <button
        onClick={() => deleteCipher(viewCipher().id)}
        class="mt-4 px-4 py-2 rounded-lg bg-red-900/30 text-red-400 hover:bg-red-900/50 text-sm transition-colors"
      >
        {t("entry.delete")}
      </button>
    </div>
  );
}

function AddCipherForm() {
  const { newCipher, setNewCipher, setShowAdd } = useApp();
  const { addCipher } = useActions();
  const { t } = useI18n();
  return (
    <div class="p-4 rounded-xl bg-[var(--color-surface)] border border-[var(--color-border)]">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold">{t("entry.addTitle")}</h3>
        <button onClick={() => setShowAdd(false)} class="text-[var(--color-muted)] hover:text-[var(--color-text)] text-xl">✕</button>
      </div>
      <div class="space-y-2">
        <input placeholder={t("entry.namePlaceholder")} class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().name} onInput={e => setNewCipher({ ...newCipher(), name: e.target.value })} />
        <input placeholder={t("entry.usernamePlaceholder")} class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().username} onInput={e => setNewCipher({ ...newCipher(), username: e.target.value })} />
        <input placeholder={t("entry.passwordPlaceholder")} type="password" class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().password} onInput={e => setNewCipher({ ...newCipher(), password: e.target.value })} />
        <input placeholder={t("entry.uriPlaceholder")} class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().uri} onInput={e => setNewCipher({ ...newCipher(), uri: e.target.value })} />
        <input placeholder={t("entry.notesPlaceholder")} class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().notes} onInput={e => setNewCipher({ ...newCipher(), notes: e.target.value })} />
      </div>
      <button
        onClick={addCipher}
        class="mt-3 w-full p-2 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white text-sm font-medium transition-colors"
      >
        {t("entry.add")}
      </button>
    </div>
  );
}

function VaultView() {
  const { ciphers, vaultInfo, error, showAdd, viewCipher, setShowAdd } = useApp();
  const { lock } = useActions();
  const { t } = useI18n();
  return (
    <div class="flex h-full">
      {/* Sidebar */}
      <div class="w-64 border-r border-[var(--color-border)] flex flex-col">
        <div class="p-4 border-b border-[var(--color-border)]">
          <div class="flex items-center justify-between">
            <span class="text-lg font-semibold">{t("app.name")}</span>
            <span class="text-xs text-[var(--color-success)]">● {t("vault.statusUnlocked")}</span>
          </div>
          <Show when={vaultInfo()}>
            <div class="text-xs text-[var(--color-muted)] mt-1">
              {t(ciphers().length === 1 ? "vault.entryCount" : "vault.entryCount_plural", { count: ciphers().length })}
            </div>
          </Show>
        </div>

        <div class="flex-1 overflow-y-auto p-3 space-y-2">
          <Show when={ciphers().length === 0}>
            <div class="text-sm text-[var(--color-muted)] text-center py-4">{t("vault.emptyList")}</div>
          </Show>
          <For each={ciphers()}>
            {(id) => <CipherRow id={id} />}
          </For>
        </div>

        <div class="p-3 border-t border-[var(--color-border)] space-y-2">
          <button
            onClick={() => setShowAdd(true)}
            class="w-full p-2 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white text-sm font-medium transition-colors"
          >
            {t("vault.addEntry")}
          </button>
          <button
            onClick={lock}
            class="w-full p-2 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-sm hover:border-red-500 transition-colors"
          >
            {t("vault.lock")}
          </button>
        </div>
      </div>

      {/* Main content */}
      <div class="flex-1 p-6 overflow-y-auto">
        <Show when={error()}>
          <div class="mb-4 p-3 rounded-lg bg-red-900/30 text-red-400 text-sm">{error()}</div>
        </Show>
        <Show when={showAdd()}>
          <AddCipherForm />
        </Show>
        <Show when={viewCipher() && !showAdd()}>
          <CipherDetail />
        </Show>
        <Show when={!viewCipher() && !showAdd()}>
          <div class="flex items-center justify-center h-full text-[var(--color-muted)]">
            {t("entry.selectPrompt")}
          </div>
        </Show>
      </div>
    </div>
  );
}

// ── Create / Recovery Views ──

function CreateVaultScreen() {
  const { error, status, setStatus, setCreatePassword } = useApp();
  const { createVault } = useActions();
  const { t } = useI18n();
  return (
    <div class="flex items-center justify-center h-full">
      <div class="w-96 p-6 rounded-xl bg-[var(--color-surface)] border border-[var(--color-border)]">
        <div class="text-center mb-6">
          <div class="text-3xl mb-2">🔐</div>
          <h1 class="text-xl font-semibold">{t("create.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("create.subtitle")}</p>
        </div>
        <Show when={error()}>
          <div class="mb-3 p-2 rounded bg-red-900/30 text-red-400 text-sm">{error()}</div>
        </Show>
        <input id="create-password" type="password" placeholder={t("create.passwordPlaceholder")}
          onInput={e => setCreatePassword(e.target.value)}
          class="w-full p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] mb-3" />
        <input id="create-confirm" type="password" placeholder={t("create.confirmPlaceholder")}
          class="w-full p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] mb-3" />
        <button onClick={createVault} disabled={status() === "creating"}
          class="w-full p-3 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white font-medium transition-colors disabled:opacity-50">
          {status() === "creating" ? t("create.creating") : t("create.submit")}
        </button>
        <button onClick={() => setStatus("locked")}
          class="w-full mt-2 p-2 text-sm text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors">
          {t("create.alreadyHaveVault")}
        </button>
      </div>
    </div>
  );
}

function RecoveryScreen() {
  const { recoveryPhrase, createPassword, setStatus, setError, setCreatePassword } = useApp();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();
  return (
    <div class="flex items-center justify-center h-full">
      <div class="w-96 p-6 rounded-xl bg-[var(--color-surface)] border border-[var(--color-border)]">
        <div class="text-center mb-4">
          <div class="text-3xl mb-2">📋</div>
          <h1 class="text-xl font-semibold">{t("recovery.title")}</h1>
          <p class="text-sm text-red-400 mt-1 font-medium">{t("recovery.warning")}</p>
        </div>
        <div class="p-4 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] font-mono text-sm leading-relaxed break-words select-all mb-4">
          {recoveryPhrase()}
        </div>
        <button onClick={async () => {
          setStatus("unlocking");
          const pw = createPassword();
          if (pw) {
            try {
              await daemon("vault.unlock", pw);
              setStatus("unlocked");
              setCreatePassword("");
              await refreshCiphers();
            } catch (e) { setError(e.message); setStatus("locked"); }
          } else { setStatus("locked"); }
        }}
          class="w-full p-3 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white font-medium transition-colors">
          {t("recovery.confirm")}
        </button>
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
      if (e.message.includes("not running")) {
        setError("");
        return;
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
