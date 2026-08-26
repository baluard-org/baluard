import { createSignal, createEffect, Show, For } from "solid-js";
import { Transition } from "../lib/transition";
import { useVault } from "../context/VaultContext.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { theme, setTheme } from "../context/themeSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon, getDesktopPrefs, setTrayOnly } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { buildImportPayload, buildExportPayload } from "../lib/payload.js";
import { VAULT_TIMEOUT_PRESETS, normalizeVaultTimeout } from "../lib/vaultTimeout.js";
import { biometryAvailable } from "../lib/biometry.js";
import { IconX, IconMoon, IconSunFull, IconDownload, IconMonitor, IconRefresh, IconPencil } from "./Icon.jsx";
import FocusTrap from "./FocusTrap.jsx";
import DeviceFleetPanel from "./DeviceFleetPanel.jsx";
import SyncTab from "./SyncTab.jsx";
import BridgeTab from "./BridgeTab.jsx";

export default function SettingsModal() {
  const vault = useVault();
  const auth = useAuth();
  const { t } = useI18n();
  let dialogRef;

  const [activeTab, setActiveTab] = createSignal("general"); // "general" or "data"
  
  // Auto-lock state (vault timeout policy token)
  const [timeoutToken, setTimeoutToken] = createSignal("15m");
  const [saved, setSaved] = createSignal(false);

  // Biometric state
  const [biometricEnabled, setBiometricEnabled] = createSignal(false);
  // Audit C3: true when reading the stored password requires a
  // user-presence prompt (macOS). False on Linux/Windows keyring backends.
  const [biometricReadGated, setBiometricReadGated] = createSignal(true);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);
  // Install command for a missing system keyring (Linux Secret Service):
  // shown as text next to the "unsupported" badge; the user runs it.
  const [biometricInstallHint, setBiometricInstallHint] = createSignal(null);
  const [biometricPassword, setBiometricPassword] = createSignal("");
  const [showBiometricInput, setShowBiometricInput] = createSignal(false);

  // Session PIN state (in-memory KEK escrow; Linux / no-Windows-Hello path)
  const [pinEnabled, setPinEnabled] = createSignal(false);
  const [showPinSetup, setShowPinSetup] = createSignal(false);
  const [pinPassword, setPinPassword] = createSignal("");
  const [pinValue, setPinValue] = createSignal("");
  const [pinConfirm, setPinConfirm] = createSignal("");

  async function loadPinStatus() {
    try {
      const s = JSON.parse(await daemon("vault.pin_status"));
      setPinEnabled(!!s.enabled);
    } catch { setPinEnabled(false); }
  }

  // Favicon state
  const [fetchFavicons, setFetchFavicons] = createSignal(false);

  // Tray-only mode (app-global: hide from Dock / taskbar). Lives in the Tauri
  // layer, not the daemon — pre-unlock client preference.
  const [trayOnly, setTrayOnlySignal] = createSignal(false);

  // Import/Export state
  const [importing, setImporting] = createSignal(false);
  const [importSource, setImportSource] = createSignal("");
  const [exporting, setExporting] = createSignal(false);
  const [message, setMessage] = createSignal(null);

  // Sync profile to VaultContext when settings modal closes
  let wasSettingsOpen = false;
  createEffect(
    () => vault.showSettingsModal(),
    (isOpen) => {
      if (isOpen) wasSettingsOpen = true;
      if (wasSettingsOpen && !isOpen) {
        wasSettingsOpen = false;
        vault.refreshProfile();
      }
    },
  );

  // Profile state
  const [displayName, setDisplayName] = createSignal("");
  const [avatarB64, setAvatarB64] = createSignal("");
  const [avatarExt, setAvatarExt] = createSignal("png");

  const formats = [
    { id: "bw-json", label: t("settings.formatBwJson") },
    { id: "bw-csv", label: t("settings.formatBwCsv") },
    { id: "chrome-csv", label: t("settings.formatChromeCsv") },
    { id: "firefox-csv", label: t("settings.formatFirefoxCsv") },
    { id: "lastpass-csv", label: t("settings.formatLastpassCsv") },
    { id: "1password-1pux", label: t("settings.format1password1pux") },
    { id: "1password-csv", label: t("settings.format1passwordCsv") },
    { id: "keepass-xml", label: t("settings.formatKeePassXml") },
  ];

  createEffect(
    () => vault.showSettingsModal(),
    (isOpen) => {
      if (isOpen) {
        loadSettings();
        setImportSource("");
      }
    },
  );

  async function loadSettings() {
    try {
      // Load auto lock
      const data = JSON.parse(await daemon("settings.get"));
      setTimeoutToken(normalizeVaultTimeout(data.vault_timeout));
      // Favicon setting (default: disabled — opt-in for privacy)
      setFetchFavicons(data.fetch_favicons === true);

      // Load biometric status. Single daemon fetch also carries install_hint
      // when the system keyring is missing (Linux), so the UI can print the fix.
      const available = await biometryAvailable();
      let enabled = false;
      let installHint = null;
      try {
        const status = JSON.parse(await daemon("vault.biometric_status"));
        if (available) {
          enabled = status.enabled;
          setBiometricReadGated(status.read_gated !== false);
        } else if (!status.available) {
          installHint = status.install_hint || null;
        }
      } catch {}
      setBiometricInstallHint(installHint);
      setBiometricAvailable(available);
      setBiometricEnabled(enabled);
      await loadPinStatus();

      // Tray-only pref is app-global (Tauri layer), separate from daemon
      // vault settings. Load failures fall back to off (default).
      try {
        const prefs = await getDesktopPrefs();
        setTrayOnlySignal(!!prefs.tray_only);
      } catch {}

      // Load profile
      setDisplayName(data.display_name || "");
      setAvatarExt(data.avatar_ext || "png");
    } catch (e) {}

    // Load avatar separately (binary)
    try {
      const b64 = await daemon("vault.avatar.get");
      setAvatarB64(b64 || "");
    } catch (e) {
      if (import.meta.env.DEV) console.warn("loadSettings avatar:", e);
    }
  }

  async function saveAutoLock(token) {
    const next = normalizeVaultTimeout(token);
    setTimeoutToken(next);
    try {
      await daemon("settings.set", JSON.stringify({ vault_timeout: next }));
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e) {}
  }

  async function changeTheme(t) {
    setTheme(t);
    try {
      await daemon("settings.set", JSON.stringify({ theme: t }));
    } catch (e) {
      if (import.meta.env.DEV) console.error("Failed to save theme:", e);
    }
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

  async function toggleTrayOnly() {
    const next = !trayOnly();
    setTrayOnlySignal(next);
    try {
      await setTrayOnly(next);
      toastSuccess(t(next ? "settings.trayOnlyEnabled" : "settings.trayOnlyDisabled"));
    } catch (e) {
      setTrayOnlySignal(!next);
      toastError(sanitizeError(e, t));
    }
  }

  async function saveProfile() {
    try {
      await daemon("settings.set", JSON.stringify({
        display_name: displayName() || null,
      }));
      toastSuccess(t("settings.profileSaved"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function handleAvatarUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const ext = file.name.split(".").pop().toLowerCase();
    if (!["png", "jpg", "jpeg", "gif", "webp"].includes(ext)) {
      toastError(t("entry.unsupportedImageFormat"));
      return;
    }
    // Read, resize to 256x256 via canvas, upload
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = async () => {
      URL.revokeObjectURL(url);
      const size = 256;
      const canvas = document.createElement("canvas");
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext("2d");
      // Center-crop to square
      const scale = Math.max(size / img.width, size / img.height);
      const sw = size / scale;
      const sh = size / scale;
      const sx = (img.width - sw) / 2;
      const sy = (img.height - sh) / 2;
      ctx.drawImage(img, sx, sy, sw, sh, 0, 0, size, size);
      const resizedExt = ext === "jpeg" ? "jpg" : ext;
      const mime = resizedExt === "png" ? "image/png" : "image/jpeg";
      const b64 = canvas.toDataURL(mime, 0.85).split(",")[1];
      try {
        await daemon("vault.avatar.set", JSON.stringify({ data: b64, ext: resizedExt }));
        setAvatarB64(b64);
        setAvatarExt(resizedExt);
        toastSuccess(t("settings.avatarSaved"));
      } catch (e) {
        toastError(sanitizeError(e, t));
      }
    };
    img.src = url;
  }

  async function removeAvatar() {
    try {
      await daemon("vault.avatar.set", JSON.stringify({ data: "", ext: "" }));
      setAvatarB64("");
      setAvatarExt("png");
      toastSuccess(t("settings.avatarRemoved"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function toggleBiometric() {
    try {
      if (biometricEnabled()) {
        await daemon("vault.biometric_disable");
        setBiometricEnabled(false);
        auth.refreshBiometric();
        toastSuccess(t("settings.quickUnlockDisabled"));
      } else {
        setShowBiometricInput(true);
      }
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function confirmBiometricEnable() {
    const password = biometricPassword();
    if (!password) return;
    try {
      // Validate password via daemon (temp handle, doesn't affect session)
      // Then store in file-based keychain (biometric read enforced at daemon level)
      const res = JSON.parse(await daemon("vault.biometric_enable", JSON.stringify({ password })));
      setBiometricEnabled(true);
      setBiometricReadGated(res.read_gated !== false);
      auth.refreshBiometric();
      setShowBiometricInput(false);
      setBiometricPassword("");
      toastSuccess(t("settings.quickUnlockEnabled"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  // ── Session PIN handlers ──
  function togglePin() {
    if (pinEnabled()) {
      disablePin();
    } else {
      setShowPinSetup(true);
    }
  }

  async function disablePin() {
    try {
      await daemon("vault.pin_disable");
      setPinEnabled(false);
      auth.refreshPin();
      toastSuccess(t("settings.pinDisabled"));
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function confirmPinEnable() {
    const password = pinPassword();
    const pin = pinValue();
    const confirm = pinConfirm();
    if (!password) { toastError(t("settings.pinNeedPassword")); return; }
    if (!/^\d{6}$/.test(pin)) { toastError(t("settings.pinMustBe6Digits")); return; }
    if (pin !== confirm) { toastError(t("settings.pinMismatch")); return; }
    try {
      await daemon("vault.pin_enable", JSON.stringify({ password, pin }));
      setPinEnabled(true);
      auth.refreshPin();
      setShowPinSetup(false);
      setPinPassword(""); setPinValue(""); setPinConfirm("");
      toastSuccess(t("settings.pinEnabled"));
    } catch (e) {
      toastError(sanitizeError(e, t));
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
        if (result.skipped) {
          setMessage(t("settings.importSuccessSkipped", { imported: result.imported || 0, skipped: result.skipped }));
        } else {
          setMessage(t("settings.importSuccess", { imported: result.imported || 0 }));
        }
        setImportSource("");
        await vault.refreshCiphers(t);
      } catch (e) {
        setMessage(t("settings.importFailed", { error: sanitizeError(e, t) }));
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
      a.download = `baluard_export.${isCsv ? "csv" : "json"}`;
      a.click();
      URL.revokeObjectURL(url);
      setMessage(t("settings.exportComplete"));
    } catch (e) {
      setMessage(t("settings.exportFailed", { error: sanitizeError(e, t) }));
    } finally {
      setExporting(false);
    }
  }

  return (
    <Transition name="fade">
      <Show when={vault.showSettingsModal()}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="settings-title"
          class="fixed inset-0 bg-black/60 flex items-center justify-center z-[100]"
          onClick={() => vault.setShowSettingsModal(false)}
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => vault.setShowSettingsModal(false)} />
          <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[720px] max-w-[94vw] max-h-[90vh] flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
            {/* Header */}
            <div class="p-6 pb-4 border-b border-[var(--color-border)] flex items-center justify-between shrink-0">
              <h3 id="settings-title" class="text-lg font-bold text-[var(--color-text)]">{t("settings.title")}</h3>
              <button
                 onClick={() => vault.setShowSettingsModal(false)}
                 class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-lg border border-transparent hover:border-[var(--color-border)] transition-all cursor-pointer flex items-center justify-center"
                 title={t("entry.close")}
               >
                 <IconX class="w-4 h-4" />
               </button>
            </div>

            {/* Navigation Tabs */}
            <div class="px-6 py-3 border-b border-[var(--color-border)] shrink-0 bg-[var(--color-sidebar)]/30 flex gap-2 w-full">
              <button
                onClick={() => setActiveTab("general")}
                class={`flex-1 px-3 py-1.5 text-xs font-bold rounded-lg transition-all text-center whitespace-nowrap cursor-pointer ${
                  activeTab() === "general"
                    ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]"
                    : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)]/50"
                }`}
              >
                {t("settings.tabGeneral")}
              </button>
              <button
                onClick={() => setActiveTab("data")}
                class={`flex-1 px-3 py-1.5 text-xs font-bold rounded-lg transition-all text-center whitespace-nowrap cursor-pointer ${
                  activeTab() === "data"
                    ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]"
                    : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)]/50"
                }`}
              >
                {t("settings.tabData")}
              </button>
              <button
                onClick={() => setActiveTab("sync")}
                class={`flex-1 px-3 py-1.5 text-xs font-bold rounded-lg transition-all text-center whitespace-nowrap cursor-pointer ${
                  activeTab() === "sync"
                    ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]"
                    : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)]/50"
                }`}
              >
                {t("settings.tabSync")}
              </button>
              <button
                onClick={() => setActiveTab("devices")}
                class={`flex-1 px-3 py-1.5 text-xs font-bold rounded-lg transition-all text-center whitespace-nowrap cursor-pointer ${
                  activeTab() === "devices"
                    ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]"
                    : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)]/50"
                }`}
              >
                {t("settings.tabDevices")}
              </button>
              <button
                onClick={() => setActiveTab("bridge")}
                class={`flex-1 px-3 py-1.5 text-xs font-bold rounded-lg transition-all text-center whitespace-nowrap cursor-pointer ${
                  activeTab() === "bridge"
                    ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]"
                    : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)]/50"
                }`}
              >
                {t("settings.tabBridge")}
              </button>
            </div>

            {/* Content */}
            <div class="flex-1 overflow-y-auto p-6 space-y-6">
              <Show when={activeTab() === "general"}>
                {/* Profile */}
                <div class="space-y-3">
                  <label class="text-xs font-bold text-[var(--color-text)]">{t("settings.profile")}</label>
                  <p class="text-[10px] text-[var(--color-muted)]">{t("settings.profileDesc")}</p>
                  <div class="flex items-center gap-4">
                    <div class="shrink-0 flex flex-col items-center gap-1.5">
                      <div class="relative w-16 h-16">
                        <Show when={avatarB64()} fallback={
                          <div class="w-full h-full rounded-full bg-gradient-to-tr from-[var(--color-accent)] to-[var(--color-primary)] flex items-center justify-center text-[var(--color-sidebar)] font-extrabold text-lg shadow-md border border-[var(--color-border)]">
                            {(displayName() || "?").slice(0, 2).toUpperCase()}
                          </div>
                        }>
                          <img
                            src={`data:image/${avatarExt() === "jpg" ? "jpeg" : avatarExt()};base64,${avatarB64()}`}
                            alt="Avatar"
                            class="w-full h-full rounded-full object-cover shadow-md border border-[var(--color-border)]"
                          />
                        </Show>
                        <label
                          class="absolute bottom-0 right-0 w-6 h-6 rounded-full bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] flex items-center justify-center cursor-pointer shadow-md border border-[var(--color-sidebar)] transition-all hover:scale-105 active:scale-95"
                          title={t("settings.changeAvatar")}
                          aria-label={t("settings.changeAvatar")}
                        >
                          <IconPencil class="w-3 h-3" />
                          <input type="file" accept="image/*" class="hidden" onChange={handleAvatarUpload} />
                        </label>
                      </div>
                      <Show when={avatarB64()}>
                        <button
                          onClick={removeAvatar}
                          class="text-[10px] text-[var(--color-muted)] hover:text-red-400 cursor-pointer transition-colors"
                        >{t("settings.removeAvatar")}</button>
                      </Show>
                    </div>
                    <div class="flex-1 min-w-0">
                      <label class="text-[10px] font-bold text-[var(--color-muted)] uppercase tracking-wider">{t("settings.displayName")}</label>
                      <input
                        type="text"
                        placeholder={t("settings.displayNamePlaceholder")}
                        class="w-full mt-1 px-3 py-2 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                        value={displayName()}
                        onInput={e => setDisplayName(e.target.value)}
                        onBlur={saveProfile}
                        autocomplete="off"
                      />
                    </div>
                  </div>
                </div>

                {/* Theme Settings */}
                <div class="space-y-2">
                  <label class="text-xs font-bold text-[var(--color-text)]">{t("settings.appTheme")}</label>
                  <div class="grid grid-cols-3 gap-3">
                    <button
                      onClick={() => changeTheme("system")}
                      class={`flex items-center justify-center gap-2 p-3 rounded-xl border transition-all cursor-pointer ${theme() === "system" ? "bg-[var(--color-sidebar)] text-[var(--color-primary)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:border-[var(--color-text)]"}`}
                    >
                      <IconMonitor class="w-4 h-4" />
                      <span class="text-xs font-bold">{t("settings.themeSystem")}</span>
                    </button>
                    <button
                      onClick={() => changeTheme("dark")}
                      class={`flex items-center justify-center gap-2 p-3 rounded-xl border transition-all cursor-pointer ${theme() === "dark" ? "bg-[var(--color-sidebar)] text-[var(--color-primary)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:border-[var(--color-text)]"}`}
                    >
                      <IconMoon class="w-4 h-4" />
                      <span class="text-xs font-bold">{t("settings.darkMode")}</span>
                    </button>
                    <button
                      onClick={() => changeTheme("light")}
                      class={`flex items-center justify-center gap-2 p-3 rounded-xl border transition-all cursor-pointer ${theme() === "light" ? "bg-[var(--color-sidebar)] text-[var(--color-primary)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:border-[var(--color-text)]"}`}
                    >
                      <IconSunFull class="w-4 h-4" />
                      <span class="text-xs font-bold">{t("settings.lightMode")}</span>
                    </button>
                  </div>
                </div>

                {/* Auto-lock Settings */}
                <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
                  <div class="flex flex-col">
                    <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.autolockTimeout")}</span>
                    <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.autolockDesc")}</span>
                  </div>
                  <div class="flex items-center gap-3">
                    <select
                      value={timeoutToken()}
                      onChange={(e) => saveAutoLock(e.currentTarget.value)}
                      class="flex-1 px-3 py-2.5 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all cursor-pointer"
                      aria-label={t("settings.autolockTimeout")}
                    >
                      <For each={VAULT_TIMEOUT_PRESETS}>
                        {(p) => <option value={p.token}>{t(`settings.timeoutPreset.${p.token}`)}</option>}
                      </For>
                    </select>
                    <Show when={saved()}>
                      <span class="text-[10px] text-[var(--color-primary)] font-bold shrink-0">{t("settings.saved")}</span>
                    </Show>
                  </div>
                </div>

                {/* Quick Unlock (Biometric) Settings */}
                <div class="pt-4 border-t border-[var(--color-border)]">
                  <div class="flex items-center justify-between">
                    <div class="flex flex-col flex-1 pr-4">
                      <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.quickUnlock")}</span>
                      <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.quickUnlockLongDesc")}</span>
                    </div>
                    <Show when={biometricAvailable()} fallback={
                      <div class="text-[10px] text-[var(--color-muted)] bg-[var(--color-sidebar)] px-2.5 py-1 rounded-lg border border-[var(--color-border)] font-bold">{t("settings.unsupported")}</div>
                    }>
                      <Show when={biometricEnabled()} fallback={
                        <button
                          onClick={toggleBiometric}
                          disabled={showBiometricInput()}
                          class={`px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${showBiometricInput() ? "opacity-50 cursor-not-allowed bg-transparent text-[var(--color-muted)] border-[var(--color-border)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
                        >
                          {t("settings.enable")}
                        </button>
                      }>
                        <button
                          onClick={toggleBiometric}
                          class="px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer btn-active-green"
                        >
                          {t("settings.enabled")}
                        </button>
                      </Show>
                    </Show>
                  </div>

                  {/* Audit C3: platforms without a per-read keychain gate */}
                  <Show when={biometricEnabled() && !biometricReadGated()}>
                    <div class="mt-2 p-2.5 rounded-lg border border-[var(--color-danger)] bg-[var(--color-sidebar)] text-[10px] text-[var(--color-danger)] leading-relaxed">
                      {t("settings.quickUnlockNoReadGate")}
                    </div>
                  </Show>

                  {/* Missing system keyring: print the fix, never run it */}
                  <Show when={!biometricAvailable() && biometricInstallHint()}>
                    <div class="mt-2 text-[10px] text-[var(--color-muted)] leading-relaxed">
                      {t("common.keyringMissing")}{" "}
                      <code class="font-mono bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded">{biometricInstallHint()}</code>
                    </div>
                  </Show>

                  <Show when={biometricAvailable() && showBiometricInput()}>
                    <div class="mt-3 p-3 bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-xl space-y-3">
                      <div class="text-[10px] text-[var(--color-muted)] font-bold">
                        {t("settings.promptQuickUnlock")}
                      </div>
                      <div class="flex items-center gap-2">
                        <input
                          type="password"
                          placeholder={t("entry.passwordPlaceholder")}
                          class="flex-1 px-3 py-1.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                          value={biometricPassword()}
                          onInput={e => setBiometricPassword(e.target.value)}
                          onKeyDown={e => e.key === "Enter" && confirmBiometricEnable()}
                        />
                        <button
                          onClick={confirmBiometricEnable}
                          class="px-3 py-1.5 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] font-bold hover:bg-[var(--color-primary-hover)] transition-all cursor-pointer text-xs"
                        >
                          {t("settings.enable")}
                        </button>
                        <button
                          onClick={() => { setShowBiometricInput(false); setBiometricPassword(""); }}
                          class="px-2 py-1.5 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer text-xs"
                        >
                          {t("entry.cancel")}
                        </button>
                      </div>
                    </div>
                  </Show>
                </div>

                {/* Quick Unlock (Session PIN) Settings */}
                <div class="pt-4 border-t border-[var(--color-border)]">
                  <div class="flex items-center justify-between">
                    <div class="flex flex-col flex-1 pr-4">
                      <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.pinUnlock")}</span>
                      <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.pinLongDesc")}</span>
                    </div>
                    <Show when={pinEnabled()} fallback={
                      <button
                        onClick={togglePin}
                        disabled={showPinSetup()}
                        class={`px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${showPinSetup() ? "opacity-50 cursor-not-allowed bg-transparent text-[var(--color-muted)] border-[var(--color-border)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
                      >
                        {t("settings.enable")}
                      </button>
                    }>
                      <button
                        onClick={togglePin}
                        class="px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer btn-active-green"
                      >
                        {t("settings.enabled")}
                      </button>
                    </Show>
                  </div>

                  <Show when={showPinSetup()}>
                    <div class="mt-3 p-3 bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-xl space-y-3">
                      <div class="text-[10px] text-[var(--color-warning)] font-bold">
                        {t("settings.pinWarning")}
                      </div>
                      <div class="space-y-2">
                        <input
                          type="password"
                          placeholder={t("entry.passwordPlaceholder")}
                          class="w-full px-3 py-1.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                          value={pinPassword()}
                          onInput={e => setPinPassword(e.target.value)}
                        />
                        <input
                          type="password"
                          inputmode="numeric"
                          pattern="[0-9]*"
                          maxlength="6"
                          placeholder={t("settings.pinPlaceholder")}
                          class="w-full px-3 py-1.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-xs text-[var(--color-text)] text-center tracking-[0.4em] outline-none focus:border-[var(--color-primary)] transition-all"
                          value={pinValue()}
                          onInput={e => setPinValue(e.target.value.replace(/\D/g, "").slice(0, 6))}
                        />
                        <input
                          type="password"
                          inputmode="numeric"
                          pattern="[0-9]*"
                          maxlength="6"
                          placeholder={t("settings.pinConfirmPlaceholder")}
                          class="w-full px-3 py-1.5 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)] text-xs text-[var(--color-text)] text-center tracking-[0.4em] outline-none focus:border-[var(--color-primary)] transition-all"
                          value={pinConfirm()}
                          onInput={e => setPinConfirm(e.target.value.replace(/\D/g, "").slice(0, 6))}
                          onKeyDown={e => e.key === "Enter" && confirmPinEnable()}
                        />
                      </div>
                      <div class="flex items-center gap-2">
                        <button
                          onClick={confirmPinEnable}
                          class="px-3 py-1.5 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] font-bold hover:bg-[var(--color-primary-hover)] transition-all cursor-pointer text-xs"
                        >
                          {t("settings.enable")}
                        </button>
                        <button
                          onClick={() => { setShowPinSetup(false); setPinPassword(""); setPinValue(""); setPinConfirm(""); }}
                          class="px-2 py-1.5 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer text-xs"
                        >
                          {t("entry.cancel")}
                        </button>
                      </div>
                    </div>
                  </Show>
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
                      class={`px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${fetchFavicons() ? "btn-active-green" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
                    >
                      {fetchFavicons() ? t("settings.enabled") : t("settings.disabled")}
                    </button>
                  </div>
                </div>

                {/* Tray-only mode (hide from Dock / taskbar) */}
                <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
                  <div class="flex items-center justify-between">
                    <div class="flex flex-col flex-1 pr-4">
                      <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.trayOnlyLabel")}</span>
                      <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.trayOnlyDesc")}</span>
                    </div>
                    <button
                      onClick={toggleTrayOnly}
                      class={`px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${trayOnly() ? "btn-active-green" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
                    >
                      {trayOnly() ? t("settings.enabled") : t("settings.disabled")}
                    </button>
                  </div>
                </div>
              </Show>

              <Show when={activeTab() === "data"}>
                {/* Import Section */}
                <div class="space-y-3">
                  <div class="flex flex-col">
                    <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.importTitle")}</span>
                    <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.importDesc")}</span>
                  </div>
                  <div class="flex items-end gap-3">
                    <div class="flex-1">
                      <select
                        value={importSource() || ""}
                        onChange={e => setImportSource(e.target.value)}
                        class="w-full px-3 py-2.5 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all cursor-pointer"
                      >
                        <option value="" disabled>{t("settings.chooseSource")}</option>
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
                      {importing() ? t("settings.importing") : t("settings.import")}
                    </button>
                  </div>
                </div>

                {/* Export Section */}
                <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
                  <label class="text-xs font-bold text-[var(--color-text)]">{t("settings.exportTitle")}</label>
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

              <Show when={activeTab() === "sync"}>
                <SyncTab />
              </Show>

              <Show when={activeTab() === "devices"}>
                <DeviceFleetPanel />
              </Show>
              <Show when={activeTab() === "bridge"}>
                <BridgeTab />
              </Show>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
