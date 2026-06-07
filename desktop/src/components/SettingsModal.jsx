import { createSignal, createEffect, Show, For } from "solid-js";
import { Transition } from "solid-transition-group";
import { useVault } from "../context/VaultContext.jsx";
import { theme, setTheme } from "../context/themeSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildImportPayload, buildExportPayload, buildBiometricEnablePayload } from "../lib/payload.js";
import { IconX, IconMoon, IconSunFull, IconDownload } from "./Icon.jsx";
import DeviceFleetPanel from "./DeviceFleetPanel.jsx";

export default function SettingsModal() {
  const vault = useVault();
  const { t } = useI18n();

  const [activeTab, setActiveTab] = createSignal("general"); // "general" or "data"
  
  // Auto-lock state
  const [lockMinutes, setLockMinutes] = createSignal(15);
  const [saved, setSaved] = createSignal(false);

  // Biometric state
  const [biometricEnabled, setBiometricEnabled] = createSignal(false);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);

  // Favicon state
  const [fetchFavicons, setFetchFavicons] = createSignal(true);

  // Import/Export state
  const [importing, setImporting] = createSignal(false);
  const [importSource, setImportSource] = createSignal("");
  const [exporting, setExporting] = createSignal(false);
  const [message, setMessage] = createSignal(null);

  const formats = [
    { id: "bw-json", label: "Bitwarden JSON" },
    { id: "bw-csv", label: "Bitwarden CSV" },
    { id: "chrome-csv", label: "Chrome CSV" },
    { id: "firefox-csv", label: "Firefox CSV" },
    { id: "lastpass-csv", label: "LastPass CSV" },
    { id: "1password-1pux", label: "1Password (1PUX)" },
    { id: "1password-csv", label: "1Password CSV" },
    { id: "keepass-xml", label: "KeePass XML" },
  ];

  createEffect(() => {
    if (vault.showSettingsModal()) {
      loadSettings();
      setImportSource("");
    }
  });

  async function loadSettings() {
    try {
      // Load auto lock
      const data = JSON.parse(await daemon("settings.get"));
      if (data.auto_lock_minutes) setLockMinutes(data.auto_lock_minutes);
      // Favicon setting (default: enabled)
      setFetchFavicons(data.fetch_favicons !== false);

      // Load biometric status
      const status = JSON.parse(await daemon("vault.biometric_status"));
      setBiometricAvailable(status.available);
      setBiometricEnabled(status.enabled);
    } catch (e) {}
  }

  async function saveAutoLock() {
    try {
      await daemon("settings.set", JSON.stringify({ auto_lock_minutes: lockMinutes() }));
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e) {}
  }

  async function toggleFetchFavicons() {
    const next = !fetchFavicons();
    setFetchFavicons(next);
    try {
      await daemon("settings.set", JSON.stringify({ fetch_favicons: next }));
    } catch (e) {
      setFetchFavicons(!next);
    }
  }

  async function toggleBiometric() {
    try {
      if (biometricEnabled()) {
        await daemon("vault.biometric_disable");
        setBiometricEnabled(false);
      } else {
        const password = prompt("Enter master password to enable Quick Unlock:");
        if (password) {
          await daemon("vault.biometric_enable", JSON.stringify(buildBiometricEnablePayload(password)));
          setBiometricEnabled(true);
        }
      }
    } catch (e) {
      alert(e.message);
    }
  }

  async function doImport(format) {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = format === "1password-1pux" ? ".1pux" : ".csv,.json,.xml,.txt";
    input.onchange = async () => {
      const file = input.files[0];
      if (!file) return;
      setImporting(true);
      setMessage(null);
      try {
        let data;
        if (format === "1password-1pux") {
          const buf = await file.arrayBuffer();
          const bytes = new Uint8Array(buf);
          let binary = "";
          bytes.forEach(b => binary += String.fromCharCode(b));
          data = btoa(binary);
        } else {
          data = await file.text();
        }
        const payload = JSON.stringify(buildImportPayload(format, data));
        const resp = await daemon("vault.import", payload);
        const result = JSON.parse(resp);
        setMessage(`Imported ${result.imported || 0} entries` + (result.skipped ? `, skipped ${result.skipped}` : ""));
        setImportSource("");
        await vault.refreshCiphers(t);
      } catch (e) {
        setMessage("Import failed: " + sanitizeError(e, t));
      } finally {
        setImporting(false);
      }
    };
    input.click();
  }

  async function doExport(format) {
    setExporting(true);
    setMessage(null);
    try {
      const resp = await daemon("vault.export", JSON.stringify(buildExportPayload(format)));
      const isCsv = format === "bw-csv";
      const blob = new Blob([resp], { type: isCsv ? "text/csv;charset=utf-8" : "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `idtty_export.${isCsv ? "csv" : "json"}`;
      a.click();
      URL.revokeObjectURL(url);
      setMessage("Exported successfully");
    } catch (e) {
      setMessage("Export failed: " + sanitizeError(e, t));
    } finally {
      setExporting(false);
    }
  }

  return (
    <Transition name="fade">
      <Show when={vault.showSettingsModal()}>
        <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-[100]" onClick={() => vault.setShowSettingsModal(false)}>
          <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[500px] max-h-[90vh] flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
            {/* Header */}
            <div class="p-6 pb-4 border-b border-[var(--color-border)] flex items-center justify-between shrink-0">
              <h3 class="text-lg font-bold text-[var(--color-text)]">App Settings</h3>
              <button
                 onClick={() => vault.setShowSettingsModal(false)}
                 class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-lg border border-transparent hover:border-[var(--color-border)] transition-all cursor-pointer flex items-center justify-center"
                 title="Close"
               >
                 <IconX class="w-4 h-4" />
               </button>
            </div>

            {/* Navigation Tabs */}
            <div class="px-6 flex gap-4 border-b border-[var(--color-border)] shrink-0 bg-[var(--color-sidebar)]/30">
              <button
                onClick={() => setActiveTab("general")}
                class={`py-3 text-xs font-bold transition-all relative cursor-pointer ${activeTab() === "general" ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)]"}`}
              >
                General & Security
                <Show when={activeTab() === "general"}>
                  <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-primary)] rounded-full"></div>
                </Show>
              </button>
              <button
                onClick={() => setActiveTab("data")}
                class={`py-3 text-xs font-bold transition-all relative cursor-pointer ${activeTab() === "data" ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)]"}`}
              >
                Data Import / Export
                <Show when={activeTab() === "data"}>
                  <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-primary)] rounded-full"></div>
                </Show>
              </button>
              <button
                onClick={() => setActiveTab("devices")}
                class={`py-3 text-xs font-bold transition-all relative cursor-pointer ${activeTab() === "devices" ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)]"}`}
              >
                Devices
                <Show when={activeTab() === "devices"}>
                  <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-primary)] rounded-full"></div>
                </Show>
              </button>
            </div>

            {/* Content */}
            <div class="flex-1 overflow-y-auto p-6 space-y-6">
              <Show when={activeTab() === "general"}>
                {/* Theme Settings */}
                <div class="space-y-2">
                  <label class="text-xs font-bold text-[var(--color-text)]">App Theme</label>
                  <div class="grid grid-cols-2 gap-3">
                    <button
                      onClick={() => setTheme("dark")}
                      class={`flex items-center justify-center gap-2 p-3 rounded-xl border transition-all cursor-pointer ${theme() === "dark" ? "bg-[var(--color-sidebar)] text-[var(--color-primary)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:border-[var(--color-text)]"}`}
                    >
                      <IconMoon class="w-4 h-4" />
                      <span class="text-xs font-bold">Dark Mode</span>
                    </button>
                    <button
                      onClick={() => setTheme("light")}
                      class={`flex items-center justify-center gap-2 p-3 rounded-xl border transition-all cursor-pointer ${theme() === "light" ? "bg-[var(--color-sidebar)] text-[var(--color-primary)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:border-[var(--color-text)]"}`}
                    >
                      <IconSunFull class="w-4 h-4" />
                      <span class="text-xs font-bold">Light Mode</span>
                    </button>
                  </div>
                </div>

                {/* Auto-lock Settings */}
                <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
                  <div class="flex flex-col">
                    <span class="text-xs font-bold text-[var(--color-text)]">Auto-lock Timeout</span>
                    <span class="text-[10px] text-[var(--color-muted)] mt-0.5">Automatically locks the vault after a period of inactivity.</span>
                  </div>
                  <div class="flex items-center gap-3">
                    <div class="flex items-center gap-2 bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-xl px-3 py-1.5 flex-1 max-w-[200px]">
                      <input
                        type="number"
                        min="1"
                        max="120"
                        value={lockMinutes()}
                        onInput={e => setLockMinutes(parseInt(e.target.value) || 15)}
                        class="w-full bg-transparent text-sm text-[var(--color-text)] outline-none font-bold text-center"
                      />
                      <span class="text-xs text-[var(--color-muted)]">minutes</span>
                    </div>
                    <button
                      onClick={saveAutoLock}
                      class="px-5 py-2 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md"
                    >
                      {saved() ? "Saved" : "Save"}
                    </button>
                  </div>
                </div>

                {/* Quick Unlock (Biometric) Settings */}
                <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
                  <div class="flex items-center justify-between">
                    <div class="flex flex-col flex-1 pr-4">
                      <span class="text-xs font-bold text-[var(--color-text)]">Quick Unlock</span>
                      <span class="text-[10px] text-[var(--color-muted)] mt-0.5">Store credentials securely in OS Keychain using device biometrics (fingerprint/face) or PIN code.</span>
                    </div>
                    <Show when={biometricAvailable()} fallback={
                      <div class="text-[10px] text-[var(--color-muted)] bg-[var(--color-sidebar)] px-2.5 py-1 rounded-lg border border-[var(--color-border)] font-bold">Unsupported</div>
                    }>
                      <button
                        onClick={toggleBiometric}
                        class={`px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${biometricEnabled() ? "bg-green-950/20 text-green-400 border-green-900/50 hover:bg-green-950/30" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
                      >
                        {biometricEnabled() ? "Enabled" : "Enable"}
                      </button>
                    </Show>
                  </div>
                </div>

                {/* Favicon Settings */}
                <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
                  <div class="flex items-center justify-between">
                    <div class="flex flex-col flex-1 pr-4">
                      <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.faviconLabel")}</span>
                      <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.faviconDesc")}</span>
                    </div>
                    <button
                      onClick={toggleFetchFavicons}
                      class={`px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${fetchFavicons() ? "bg-green-950/20 text-green-400 border-green-900/50 hover:bg-green-950/30" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
                    >
                      {fetchFavicons() ? "Enabled" : "Disabled"}
                    </button>
                  </div>
                </div>
              </Show>

              <Show when={activeTab() === "data"}>
                {/* Import Section */}
                <div class="space-y-3">
                  <div class="flex flex-col">
                    <span class="text-xs font-bold text-[var(--color-text)]">Import Vault Data</span>
                    <span class="text-[10px] text-[var(--color-muted)] mt-0.5">Select a source to import entries from.</span>
                  </div>
                  <div class="flex items-end gap-3">
                    <div class="flex-1">
                      <select
                        value={importSource() || ""}
                        onChange={e => setImportSource(e.target.value)}
                        class="w-full px-3 py-2.5 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all cursor-pointer"
                      >
                        <option value="" disabled>Choose source...</option>
                        <For each={formats}>
                          {(f) => <option value={f.id}>{f.label}</option>}
                        </For>
                      </select>
                    </div>
                    <button
                      onClick={() => doImport(importSource())}
                      disabled={!importSource() || importing()}
                      class="px-5 py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
                    >
                      {importing() ? "Importing..." : "Import"}
                    </button>
                  </div>
                </div>

                {/* Export Section */}
                <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
                  <label class="text-xs font-bold text-[var(--color-text)]">Export Vault Data</label>
                  <div class="grid grid-cols-2 gap-3">
                    <button
                      onClick={() => doExport("bw-json")}
                      disabled={exporting()}
                      class="flex items-center justify-center gap-2 p-3 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50"
                    >
                      <IconDownload class="w-4 h-4 text-[var(--color-muted)]" />
                      JSON
                    </button>
                    <button
                      onClick={() => doExport("bw-csv")}
                      disabled={exporting()}
                      class="flex items-center justify-center gap-2 p-3 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50"
                    >
                      <IconDownload class="w-4 h-4 text-[var(--color-muted)]" />
                      CSV
                    </button>
                  </div>
                </div>

                {/* Message Display */}
                <Show when={message()}>
                  <div class="p-3.5 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-primary)] font-bold text-center">
                    {message()}
                  </div>
                </Show>
              </Show>

              <Show when={activeTab() === "devices"}>
                <DeviceFleetPanel />
              </Show>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}

