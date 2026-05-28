import { createSignal, onMount, Show, For } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

// ── State ──
const [status, setStatus] = createSignal("locked");
const [ciphers, setCiphers] = createSignal([]);
const [error, setError] = createSignal("");
const [vaultInfo, setVaultInfo] = createSignal(null);
const [showAdd, setShowAdd] = createSignal(false);
const [viewCipher, setViewCipher] = createSignal(null);
const [newCipher, setNewCipher] = createSignal({
  name: "", username: "", password: "", uri: "", notes: "",
});

// ── Daemon proxy ──
async function daemon(action, payload = "") {
  const res = await invoke("daemon_request", { action, payload });
  if (!res.success) {
    const msg = res.error.includes("Cannot connect") ? "Daemon is not running" :
                res.error.includes("Vault not") ? "Vault is not unlocked" :
                res.error.includes("timeout") ? "Request timed out" :
                res.error.length > 100 ? res.error.slice(0, 100) + "..." : res.error;
    throw new Error(msg);
  }
  return res.payload;
}

// ── Actions ──
async function unlock() {
  const el = document.getElementById("master-password");
  const password = el?.value;
  if (!password) return;
  setStatus("unlocking");
  setError("");
  try {
    await daemon("vault.open");
    await daemon("vault.unlock", password);
    el.value = "";
    setStatus("unlocked");
    await refreshCiphers();
    const info = JSON.parse(await daemon("vault.info"));
    setVaultInfo(info);
  } catch (e) {
    setError(e.message);
    setStatus("locked");
  }
}

async function lock() {
  try {
    await daemon("vault.lock");
    setStatus("locked");
    setCiphers([]);
    setVaultInfo(null);
    setViewCipher(null);
    setShowAdd(false);
  } catch (e) {
    setError(e.message);
  }
}

async function refreshCiphers() {
  try {
    const data = JSON.parse(await daemon("vault.list"));
    setCiphers(data.cipher_ids || []);
  } catch (e) {
    setError(e.message);
  }
}

async function addCipher() {
  const c = newCipher();
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
    setNewCipher({ name: "", username: "", password: "", uri: "", notes: "" });
    setShowAdd(false);
    await refreshCiphers();
  } catch (e) {
    setError(e.message);
  }
}

async function getCipher(id) {
  try {
    const data = JSON.parse(await daemon("vault.get", JSON.stringify({ id, decrypt: true })));
    setViewCipher(data);
  } catch (e) {
    setError(e.message);
  }
}

async function deleteCipher(id) {
  try {
    await daemon("vault.delete", id);
    setViewCipher(null);
    await refreshCiphers();
  } catch (e) {
    setError(e.message);
  }
}

function onKeyUnlock(e) {
  if (e.key === "Enter") unlock();
}

// ── Views ──
function LoginScreen() {
  return (
    <div class="flex items-center justify-center h-full">
      <div class="w-80 p-6 rounded-xl bg-[var(--color-surface)] border border-[var(--color-border)]">
        <div class="text-center mb-6">
          <div class="text-3xl mb-2">🔒</div>
          <h1 class="text-xl font-semibold">IDtty</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">Enter master password</p>
        </div>
        <Show when={error()}>
          <div class="mb-3 p-2 rounded bg-red-900/30 text-red-400 text-sm">{error()}</div>
        </Show>
        <input
          id="master-password"
          type="password"
          placeholder="Master password"
          class="w-full p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] mb-3"
          onKeyDown={onKeyUnlock}
          autofocus
        />
        <button
          onClick={unlock}
          disabled={status() === "unlocking"}
          class="w-full p-3 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white font-medium transition-colors disabled:opacity-50"
        >
          {status() === "unlocking" ? "Unlocking..." : "Unlock"}
        </button>
      </div>
    </div>
  );
}

function CipherRow(props) {
  return (
    <div
      class="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface)] border border-[var(--color-border)] cursor-pointer hover:border-[var(--color-primary)] transition-colors"
      onClick={() => getCipher(props.id)}
    >
      <div class="flex items-center gap-3">
        <span class="text-lg">🔑</span>
        <span class="text-sm font-mono text-[var(--color-muted)]">{props.id.slice(0, 8)}</span>
      </div>
    </div>
  );
}

function CipherDetail() {
  const c = viewCipher();
  return (
    <div class="p-4 rounded-xl bg-[var(--color-surface)] border border-[var(--color-border)]">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold">{c.name || "Cipher"}</h3>
        <button
          onClick={() => setViewCipher(null)}
          class="text-[var(--color-muted)] hover:text-[var(--color-text)] text-xl"
        >
          ✕
        </button>
      </div>
      <div class="space-y-2 text-sm">
        <Show when={c.username}><div><span class="text-[var(--color-muted)]">User:</span> {c.username}</div></Show>
        <Show when={c.password}><div><span class="text-[var(--color-muted)]">Pass:</span> {c.password}</div></Show>
        <Show when={c.uris?.length}><div><span class="text-[var(--color-muted)]">URI:</span> {c.uris[0]}</div></Show>
        <Show when={c.notes}><div><span class="text-[var(--color-muted)]">Notes:</span> {c.notes}</div></Show>
      </div>
      <button
        onClick={() => deleteCipher(viewCipher().id)}
        class="mt-4 px-4 py-2 rounded-lg bg-red-900/30 text-red-400 hover:bg-red-900/50 text-sm transition-colors"
      >
        Delete
      </button>
    </div>
  );
}

function AddCipherForm() {
  return (
    <div class="p-4 rounded-xl bg-[var(--color-surface)] border border-[var(--color-border)]">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold">Add Cipher</h3>
        <button onClick={() => setShowAdd(false)} class="text-[var(--color-muted)] hover:text-[var(--color-text)] text-xl">✕</button>
      </div>
      <div class="space-y-2">
        <input placeholder="Name" class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().name} onInput={e => setNewCipher({ ...newCipher(), name: e.target.value })} />
        <input placeholder="Username" class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().username} onInput={e => setNewCipher({ ...newCipher(), username: e.target.value })} />
        <input placeholder="Password" type="password" class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().password} onInput={e => setNewCipher({ ...newCipher(), password: e.target.value })} />
        <input placeholder="URI" class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().uri} onInput={e => setNewCipher({ ...newCipher(), uri: e.target.value })} />
        <input placeholder="Notes" class="w-full p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border)] text-sm outline-none focus:border-[var(--color-primary)]"
          value={newCipher().notes} onInput={e => setNewCipher({ ...newCipher(), notes: e.target.value })} />
      </div>
      <button
        onClick={addCipher}
        class="mt-3 w-full p-2 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white text-sm font-medium transition-colors"
      >
        Add
      </button>
    </div>
  );
}

function VaultView() {
  return (
    <div class="flex h-full">
      {/* Sidebar */}
      <div class="w-64 border-r border-[var(--color-border)] flex flex-col">
        <div class="p-4 border-b border-[var(--color-border)]">
          <div class="flex items-center justify-between">
            <span class="text-lg font-semibold">IDtty</span>
            <span class="text-xs text-[var(--color-success)]">● Unlocked</span>
          </div>
          <Show when={vaultInfo()}>
            <div class="text-xs text-[var(--color-muted)] mt-1">
              {ciphers().length} cipher{ciphers().length !== 1 ? "s" : ""}
            </div>
          </Show>
        </div>

        <div class="flex-1 overflow-y-auto p-3 space-y-2">
          <For each={ciphers()}>
            {(id) => <CipherRow id={id} />}
          </For>
        </div>

        <div class="p-3 border-t border-[var(--color-border)] space-y-2">
          <button
            onClick={() => setShowAdd(true)}
            class="w-full p-2 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white text-sm font-medium transition-colors"
          >
            + Add Cipher
          </button>
          <button
            onClick={lock}
            class="w-full p-2 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-sm hover:border-red-500 transition-colors"
          >
            Lock Vault
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
            Select a cipher or add a new one
          </div>
        </Show>
      </div>
    </div>
  );
}

// ── Root App ──
export default function App() {
  onMount(async () => {
    try { await daemon("vault.open"); } catch {}
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
    <Show when={status() === "unlocked"} fallback={<LoginScreen />}>
      <VaultView />
    </Show>
  );
}
