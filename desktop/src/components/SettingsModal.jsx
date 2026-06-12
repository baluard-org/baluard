import { createSignal, createEffect, Show, For } from "solid-js";
import { Transition } from "solid-transition-group";
import { useVault } from "../context/VaultContext.jsx";
import { theme, setTheme } from "../context/themeSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { buildImportPayload, buildExportPayload } from "../lib/payload.js";
import { biometryAvailable } from "../lib/biometry.js";
import { IconX, IconMoon, IconSunFull, IconDownload, IconMonitor } from "./Icon.jsx";
import FocusTrap from "./FocusTrap.jsx";
import DeviceFleetPanel from "./DeviceFleetPanel.jsx";

export default function SettingsModal() {
  const vault = useVault();
  const { t } = useI18n();
  let dialogRef;

  const [activeTab, setActiveTab] = createSignal("general"); // "general" or "data"
  
  // Auto-lock state
  const [lockMinutes, setLockMinutes] = createSignal(15);
  const [saved, setSaved] = createSignal(false);

  // Biometric state
  const [biometricEnabled, setBiometricEnabled] = createSignal(false);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);
  const [biometricPassword, setBiometricPassword] = createSignal("");
  const [showBiometricInput, setShowBiometricInput] = createSignal(false);

  // Favicon state
  const [fetchFavicons, setFetchFavicons] = createSignal(true);

  // Import/Export state
  const [importing, setImporting] = createSignal(false);
  const [importSource, setImportSource] = createSignal("");
  const [exporting, setExporting] = createSignal(false);
  const [message, setMessage] = createSignal(null);

  // Sync profile to VaultContext when settings modal closes
  let wasSettingsOpen = false;
  createEffect(() => {
    const isOpen = vault.showSettingsModal();
    if (isOpen) wasSettingsOpen = true;
    if (wasSettingsOpen && !isOpen) {
      wasSettingsOpen = false;
      vault.refreshProfile();
    }
  });

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
      const available = await biometryAvailable();
      let enabled = false;
      if (available) {
        try {
          const status = JSON.parse(await daemon("vault.biometric_status"));
          enabled = status.enabled;
        } catch {}
      }
      setBiometricAvailable(available);
      setBiometricEnabled(enabled);

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

  async function saveAutoLock() {
    try {
      await daemon("settings.set", JSON.stringify({ auto_lock_minutes: lockMinutes() }));
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
      await daemon("vault.biometric_enable", JSON.stringify({ password }));
      setBiometricEnabled(true);
      setShowBiometricInput(false);
      setBiometricPassword("");
      toastSuccess(t("settings.quickUnlockEnabled"));
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
          <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[500px] max-h-[90vh] flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
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
            <div class="px-6 flex gap-4 border-b border-[var(--color-border)] shrink-0 bg-[var(--color-sidebar)]/30">
              <button
                onClick={() => setActiveTab("general")}
                class={`py-3 text-xs font-bold transition-all relative cursor-pointer ${activeTab() === "general" ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)]"}`}
              >
                {t("settings.tabGeneral")}
                <Show when={activeTab() === "general"}>
                  <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-primary)] rounded-full"></div>
                </Show>
              </button>
              <button
                onClick={() => setActiveTab("data")}
                class={`py-3 text-xs font-bold transition-all relative cursor-pointer ${activeTab() === "data" ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)]"}`}
              >
                {t("settings.tabData")}
                <Show when={activeTab() === "data"}>
                  <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-primary)] rounded-full"></div>
                </Show>
              </button>
              <button
                onClick={() => setActiveTab("devices")}
                class={`py-3 text-xs font-bold transition-all relative cursor-pointer ${activeTab() === "devices" ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)]"}`}
              >
                {t("settings.tabDevices")}
                <Show when={activeTab() === "devices"}>
                  <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-primary)] rounded-full"></div>
                </Show>
              </button>
            </div>

            {/* Content */}
            <div class="flex-1 overflow-y-auto p-6 space-y-6">
              <Show when={activeTab() === "general"}>
                {/* Profile */}
                <div class="space-y-3">
                  <label class="text-xs font-bold text-[var(--color-text)]">{t("settings.profile")}</label>
                  <p class="text-[10px] text-[var(--color-muted)]">{t("settings.profileDesc")}</p>
                  <div class="flex items-start gap-4">
                    <div class="shrink-0 flex flex-col items-center gap-1">
                      <div class="relative group">
                        <Show when={avatarB64()} fallback={
                          <div class="w-16 h-16 rounded-full bg-gradient-to-tr from-[var(--color-accent)] to-[var(--color-primary)] flex items-center justify-center text-[var(--color-sidebar)] font-extrabold text-lg shadow-md">
                            {(displayName() || "?").slice(0, 2).toUpperCase()}
                          </div>
                        }>
                          <img
                            src={`data:image/${avatarExt() === "jpg" ? "jpeg" : avatarExt()};base64,${avatarB64()}`}
                            alt="Avatar"
                            class="w-16 h-16 rounded-full object-cover shadow-md"
                          />
                        </Show>
                        <label class="absolute inset-0 rounded-full bg-black/50 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer">
                          <span class="text-[10px] font-bold text-white">{t("settings.changeAvatar")}</span>
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
                      <span class="text-xs font-bold">{t("setup.themeSystem")}</span>
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
                    <div class="flex items-center gap-2 bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-xl px-3 py-1.5 flex-1 max-w-[200px]">
                      <input
                        type="number"
                        min="1"
                        max="120"
                        value={lockMinutes()}
                        onInput={e => setLockMinutes(parseInt(e.target.value) || 15)}
                        class="w-full bg-transparent text-sm text-[var(--color-text)] outline-none font-bold text-center"
                      />
                      <span class="text-xs text-[var(--color-muted)]">{t("settings.minutes")}</span>
                    </div>
                    <button
                      onClick={saveAutoLock}
                      class="px-5 py-2 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md"
                    >
                      {saved() ? t("settings.saved") : t("settings.save")}
                    </button>
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
                          class="px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer bg-green-950/20 text-green-400 border-green-900/50 hover:bg-green-950/30"
                        >
                          {t("settings.enabled")}
                        </button>
                      </Show>
                    </Show>
                  </div>

                  <Show when={biometricAvailable() && showBiometricInput()}>
                    <div class="mt-3 p-3 bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-xl space-y-3">
                      <div class="text-[10px] text-[var(--color-muted)] font-bold">
                        {t("settings.promptQuickUnlock")}
                      </div>
                      <div class="flex items-center gap-2">
                        <input
                          type="password"
                          placeholder={t("login.passwordPlaceholder")}
                          class="flex-1 px-3 py-1.5 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                          value={biometricPassword()}
                          onInput={e => setBiometricPassword(e.target.value)}
                          onKeyDown={e => { if (e.key === "Enter") confirmBiometricEnable(); if (e.key === "Escape") { setShowBiometricInput(false); setBiometricPassword(""); } }}
                          autofocus
                        />
                        <button
                          onClick={confirmBiometricEnable}
                          class="px-3 py-1.5 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold cursor-pointer"
                        >
                          {t("entry.confirm")}
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
                      {fetchFavicons() ? t("settings.enabled") : t("settings.disabled")}
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
