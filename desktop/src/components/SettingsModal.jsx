import { createSignal, createEffect, Show, For } from "solid-js";
import { Transition } from "../lib/transition";
import { useVault } from "../context/VaultContext.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { theme, setTheme } from "../context/themeSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon, getDesktopPrefs, setTrayOnly, getRenderState, setCompatibleRendering } from "../lib/daemon.js";
import ConfirmModal from "./ConfirmModal.jsx";
import { sanitizeError, generatePassphrase } from "../lib/utils.js";
import { copyToClipboard } from "../lib/clipboard.js";
import { invoke } from "@tauri-apps/api/core";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { buildImportPayload } from "../lib/payload.js";
import { VAULT_TIMEOUT_PRESETS, normalizeVaultTimeout } from "../lib/vaultTimeout.js";
import { biometryAvailable } from "../lib/biometry.js";
import { IconX, IconMoon, IconSunFull, IconDownload, IconMonitor, IconRefresh, IconPencil, IconCopy } from "./Icon.jsx";
import FocusTrap from "./FocusTrap.jsx";
import DeviceFleetPanel from "./DeviceFleetPanel.jsx";
import SyncTab from "./SyncTab.jsx";
import PeopleTab from "./PeopleTab.jsx";
import SpaceTab from "./SpaceTab.jsx";
import CollectionsTab from "./CollectionsTab.jsx";
import GroupsTab from "./GroupsTab.jsx";
import ContactsTab from "./ContactsTab.jsx";
import OutboxesTab from "./OutboxesTab.jsx";
import BridgeTab from "./BridgeTab.jsx";
import RecoveryPhraseCard from "./RecoveryPhraseCard.jsx";
import LegacyTab from "./LegacyTab.jsx";

function TabButton(props) {
  return (
    <button
      onClick={() => props.setActiveTab(props.id)}
      data-testid={`settings-tab-${props.id}`}
      class={`flex-1 px-3 py-1.5 text-xs font-bold rounded-lg transition-all text-center whitespace-nowrap cursor-pointer ${
        props.active === props.id
          ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]"
          : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)]/50"
      }`}
    >
      {props.label}
    </button>
  );
}

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

  // Linux compatible rendering (WebKitGTK workaround). Setting cycles
  // automatic → on → off → automatic; `active` mirrors what the backend
  // decided for THIS launch (auto heuristics included); `recovery` marks a
  // session enabled by the crash-recovery heuristic.
  const [isLinux, setIsLinux] = createSignal(false);
  const [renderSetting, setRenderSetting] = createSignal(null); // null | true | false
  const [renderActive, setRenderActive] = createSignal(false);
  const [renderRecovery, setRenderRecovery] = createSignal(false);

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
        // A close that is not the Cancel button must still scrub the
        // credential prompts.
        setBiometricPassword("");
        setPinPassword("");
        setPinValue("");
        setPinConfirm("");
        vault.refreshProfile();
      }
    },
  );

  // Profile state
  const [displayName, setDisplayName] = createSignal("");
  const [avatarB64, setAvatarB64] = createSignal("");
  const [avatarExt, setAvatarExt] = createSignal("png");

  // Encrypted backup (docs/plan-encrypted-backup.md §7): one passphrase
  // dialog serving both directions. The default is a generated 6-word
  // passphrase; the master password is NEVER offered (§7: a second dialog
  // asking for it is the phishing shape the product forbids).
  const [backupMode, setBackupMode] = createSignal(null); // null | "export" | "import"
  const [backupPw, setBackupPw] = createSignal("");
  const [backupPwConfirm, setBackupPwConfirm] = createSignal("");
  const [backupPwSaved, setBackupPwSaved] = createSignal(false);
  const [backupBusy, setBackupBusy] = createSignal(false);
  let backupDialogRef;

  // Device security chip (progressive enhancement): the card renders
  // only when the probe reports a usable chip; devices without one see
  // nothing (docs/plan-hardware-backed-keys.md §2).
  const [hwStatus, setHwStatus] = createSignal(null);
  const [hwBusy, setHwBusy] = createSignal(false);
  const [hwConfirm, setHwConfirm] = createSignal(null); // "enable" | "disable" | null
  const [healthBusy, setHealthBusy] = createSignal(false);
  const [healthOpen, setHealthOpen] = createSignal(false);
  const [healthReport, setHealthReport] = createSignal(null);
  let healthDialogRef;

  const HEALTH_REASON_KEYS = {
    short: "settings.healthRShort",
    common: "settings.healthRCommon",
    same_char: "settings.healthRSameChar",
    sequential: "settings.healthRSequential",
    weak: "settings.healthRWeak",
    old: "settings.healthROld",
    reused: "settings.healthRReused",
  };
  // Core attaches a machine kind and a number so the GUI can localize;
  // anything else falls back to the raw English reason.
  const healthReason = (f) => {
    const key = HEALTH_REASON_KEYS[f.kind];
    return key ? t(key, { n: f.n ?? 0 }) : f.reason;
  };

  async function runHealthCheck() {
    setHealthBusy(true);
    try {
      const report = JSON.parse(await daemon("vault.health"));
      setHealthReport(report);
      setHealthOpen(true);
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setHealthBusy(false);
    }
  }

  async function loadHwStatus() {
    try {
      setHwStatus(JSON.parse(await daemon("vault.hw_status")));
    } catch {
      setHwStatus({ capable: false });
    }
  }

  async function hwToggle() {
    const mode = hwConfirm();
    setHwConfirm(null);
    if (!mode) return;
    setHwBusy(true);
    try {
      if (mode === "enable") {
        await daemon("vault.hw_enable", { consent: false });
      } else if (mode === "disable") {
        await daemon("vault.hw_disable");
      } else {
        // "consent-on" | "consent-off": re-key between the silent and
        // per-use-confirmation chip keys.
        await daemon("vault.hw_set_consent", { consent: mode === "consent-on" });
      }
      await loadHwStatus();
      toastSuccess(
        t(
          mode === "enable"
            ? "settings.hwEnabledToast"
            : mode === "disable"
              ? "settings.hwDisabledToast"
              : mode === "consent-on"
                ? "settings.hwConsentOnToast"
                : "settings.hwConsentOffToast",
        ),
      );
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setHwBusy(false);
    }
  }

  function openBackupPass(mode) {
    // Export prefills a generated passphrase; import expects the one the
    // user saved when they made the backup — never a fresh random value.
    setBackupPw(mode === "export" ? generatePassphrase(6, "-") : "");
    setBackupPwConfirm("");
    setBackupPwSaved(false);
    setBackupBusy(false);
    setBackupMode(mode);
    setTimeout(() => backupDialogRef?.querySelector("input")?.focus(), 0);
  }

  // Every dismissal path (cancel, backdrop, Escape, post-action) scrubs the
  // dialog state so a stale passphrase or ack never survives a re-open.
  function closeBackupPass() {
    setBackupMode(null);
    setBackupPw("");
    setBackupPwConfirm("");
    setBackupPwSaved(false);
    setBackupBusy(false);
  }

  const formats = [
    { id: "baluard-encrypted", label: t("settings.backupImportOption") },
    { id: "baluard", label: t("settings.formatBaluard") },
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
        loadHwStatus();
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

      // Linux compatible rendering state (also Tauri layer). One call fills
      // platform flag, current decision, and the user setting.
      try {
        const rs = await getRenderState();
        setIsLinux(rs.linux);
        setRenderActive(!!rs.active);
        setRenderRecovery(!!rs.recovery);
        setRenderSetting(rs.setting ?? null);
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
    const prev = timeoutToken();
    const next = normalizeVaultTimeout(token);
    setTimeoutToken(next);
    try {
      await daemon("settings.set", JSON.stringify({ vault_timeout: next }));
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      setTimeoutToken(prev);
      toastError(sanitizeError(e, t));
    }
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

  // Cycle: automatic → on → off → automatic. `null` is the automatic state;
  // Tauri maps it to Option::None backend-side. Applies after restart.
  async function cycleCompatibleRendering() {
    const order = [null, true, false];
    const prev = renderSetting();
    const next = order[(order.indexOf(prev) + 1) % order.length];
    setRenderSetting(next);
    try {
      await setCompatibleRendering(next);
      toastSuccess(t("settings.renderRestart"));
    } catch (e) {
      setRenderSetting(prev);
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
    if (format === "baluard-encrypted") {
      // Encrypted backups go through the Rust-side open dialog; the
      // container never rides the webview file input.
      openBackupPass("import");
      return;
    }
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
          const buf = await file.arrayBuffer();
          const head = new Uint8Array(buf, 0, Math.min(6, buf.byteLength));
          if (String.fromCharCode(...head) === "BLDBAK") {
            // An encrypted container chosen as a plain file: route it to
            // the passphrase dialog instead of dead-ending on a message.
            setImporting(false);
            openBackupPass("import");
            return;
          }
          data = await file.text();
          // Auto-detect our own backup: the header identifies it with no
          // collision risk, so a user restoring a Baluard backup never
          // needs to know what format their file is.
          if (data.slice(0, 512).includes("baluard.vault")) {
            format = "baluard";
          }
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
      const r = await invoke("export_save_plain", { format });
      // saved=false is the user cancelling the save dialog: stay silent
      // (desktop parity with the recovery sheet and the encrypted backup).
      if (r && r.saved) setMessage(t("settings.exportComplete"));
    } catch (e) {
      setMessage(t("settings.exportFailed", { error: sanitizeError(e, t) }));
    } finally {
      setExporting(false);
    }
  }

  function regenBackupPw() {
    setBackupPw(generatePassphrase(6, "-"));
  }

  async function confirmBackup() {
    const mode = backupMode();
    setBackupBusy(true);
    setMessage(null);
    try {
      if (mode === "export") {
        const r = await invoke("backup_save_encrypted", { passphrase: backupPw() });
        // saved=false is the user cancelling the save dialog: stay open,
        // stay silent (desktop parity with the recovery sheet).
        if (r && r.saved) {
          setMessage(t("settings.backupChecked", { n: r.entries }));
          closeBackupPass();
        }
      } else {
        const resp = await invoke("backup_import_encrypted", { passphrase: backupPw() });
        if (resp !== null) {
          const result = JSON.parse(resp);
          setMessage(t("settings.importSuccess", { imported: result.imported || 0 }));
          closeBackupPass();
          await vault.refreshCiphers(t);
        }
      }
    } catch (e) {
      setMessage(t("settings.backupFailed", { error: sanitizeError(e, t) }));
    } finally {
      setBackupBusy(false);
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
              <TabButton id="general" label={t("settings.tabGeneral")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="data" label={t("settings.tabData")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="sync" label={t("settings.tabSync")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="people" label={t("settings.tabPeople")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="space" label={t("settings.tabSpace")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="collections" label={t("settings.tabCollections")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="groups" label={t("settings.tabGroups")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="contacts" label={t("settings.tabContacts")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="outboxes" label={t("settings.tabOutboxes")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="devices" label={t("settings.tabDevices")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="bridge" label={t("settings.tabBridge")} active={activeTab()} setActiveTab={setActiveTab} />
              <TabButton id="legacy" label={t("settings.tabLegacy")} active={activeTab()} setActiveTab={setActiveTab} />
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
                      {/* P1d: explicit shared-enrollment warning before enabling */}
                      <div class="text-[10px] text-[var(--color-warning)] leading-relaxed">
                        {t("settings.quickUnlockSharedWarning")}
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
                      {/* P1d: explicit shared-enrollment warning before enabling */}
                      <div class="text-[10px] text-[var(--color-warning)] leading-relaxed">
                        {t("settings.pinSharedWarning")}
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

                {/* Linux compatible rendering (WebKitGTK blank-window fix).
                    Visible on Linux only; the backend reports the platform. */}
                <Show when={isLinux()}>
                  <div class="space-y-3 pt-4 border-t border-[var(--color-border)]">
                    <div class="flex items-center justify-between">
                      <div class="flex flex-col flex-1 pr-4">
                        <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.compatibleRenderingLabel")}</span>
                        <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.compatibleRenderingDesc")}</span>
                      </div>
                      <button
                        onClick={cycleCompatibleRendering}
                        class={`px-4 py-2 rounded-xl border text-xs font-bold transition-all cursor-pointer ${(renderSetting() === true || (renderSetting() === null && renderActive())) ? "btn-active-green" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:text-[var(--color-text)]"}`}
                      >
                        {renderSetting() === null ? t("settings.compatibleRenderingAuto") : renderSetting() ? t("settings.enabled") : t("settings.disabled")}
                      </button>
                    </div>
                  </div>
                </Show>
              </Show>

              <Show when={activeTab() === "data"}>
                {/* Device security chip: AND-wraps this device's key seal
                    with the platform keystore. Hidden unless capable. */}
                <Show when={hwStatus()?.capable}>
                  <div class="space-y-3 mb-6" data-testid="hw-guard-card">
                    <div class="flex items-center justify-between">
                      <div class="flex flex-col flex-1 pr-4">
                        <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.hwTitle")}</span>
                        <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.hwDesc")}</span>
                        <span class="text-[10px] text-[var(--color-muted)] mt-0.5">
                          {hwStatus()?.enabled ? t("settings.hwOn") : t("settings.hwOff")}
                        </span>
                      </div>
                      <button
                        data-testid="hw-toggle"
                        onClick={() => setHwConfirm(hwStatus()?.enabled ? "disable" : "enable")}
                        disabled={hwBusy()}
                        class="px-5 py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
                      >
                        {hwBusy() ? t("common.pleaseWait") : hwStatus()?.enabled ? t("settings.hwDisable") : t("settings.hwEnable")}
                      </button>
                    </div>
                    {/* Per-use confirmation (Phase 5): the chip demands the
                        platform's own verification on every unlock. Only
                        offered when the seal is on and the chip supports it. */}
                    <Show when={hwStatus()?.enabled && hwStatus()?.consent_supported}>
                      <div class="flex items-center justify-between border-t border-[var(--color-border)] pt-3">
                        <div class="flex flex-col flex-1 pr-4">
                          <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.hwConsentTitle")}</span>
                          <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.hwConsentDesc")}</span>
                          <span class="text-[10px] text-[var(--color-muted)] mt-0.5">
                            {hwStatus()?.consent ? t("settings.hwConsentStatusOn") : t("settings.hwConsentStatusOff")}
                          </span>
                        </div>
                        <button
                          data-testid="hw-consent-toggle"
                          onClick={() => setHwConfirm(hwStatus()?.consent ? "consent-off" : "consent-on")}
                          disabled={hwBusy()}
                          class="px-5 py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
                        >
                          {hwBusy() ? t("common.pleaseWait") : hwStatus()?.consent ? t("settings.hwConsentOff") : t("settings.hwConsentOn")}
                        </button>
                      </div>
                    </Show>
                  </div>
                </Show>

                <ConfirmModal
                  show={!!hwConfirm()}
                  idPrefix="hw-guard"
                  title={t(hwConfirm() === "enable" ? "settings.hwEnableTitle" : hwConfirm() === "disable" ? "settings.hwDisableTitle" : hwConfirm() === "consent-on" ? "settings.hwConsentOnTitle" : "settings.hwConsentOffTitle")}
                  body={t(hwConfirm() === "enable" ? "settings.hwEnableBody" : hwConfirm() === "disable" ? "settings.hwDisableBody" : hwConfirm() === "consent-on" ? "settings.hwConsentOnBody" : "settings.hwConsentOffBody")}
                  confirmLabel={t(hwConfirm() === "enable" ? "settings.hwEnable" : hwConfirm() === "disable" ? "settings.hwDisable" : hwConfirm() === "consent-on" ? "settings.hwConsentOn" : "settings.hwConsentOff")}
                  confirmVariant={hwConfirm() === "disable" || hwConfirm() === "consent-off" ? "danger" : "primary"}
                  onConfirm={hwToggle}
                  onClose={() => setHwConfirm(null)}
                />

                {/* Security check: whole-vault password analysis, run on demand. */}
                <div class="space-y-3 mb-6">
                  <div class="flex items-center justify-between">
                    <div class="flex flex-col flex-1 pr-4">
                      <span class="text-xs font-bold text-[var(--color-text)]">{t("settings.healthCheck")}</span>
                      <span class="text-[10px] text-[var(--color-muted)] mt-0.5">{t("settings.healthDesc")}</span>
                    </div>
                    <button
                      onClick={runHealthCheck}
                      disabled={healthBusy()}
                      class="px-5 py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
                    >
                      {healthBusy() ? t("settings.healthChecking") : t("settings.healthRun")}
                    </button>
                  </div>
                </div>

                {/* Recovery phrase exit path */}
                <div class="space-y-3 mb-6">
                  <RecoveryPhraseCard />
                </div>

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
                  <div class="grid grid-cols-3 gap-3">
                    <button
                      onClick={() => doExport("baluard")}
                      disabled={exporting()}
                      class="flex flex-col items-center justify-center gap-1 p-3 rounded-xl border border-[var(--color-primary)] bg-[var(--color-primary)]/10 hover:bg-[var(--color-primary)]/20 text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50"
                    >
                      <span class="flex items-center gap-2">
                        <IconDownload class="w-4 h-4 text-[var(--color-primary)]" />
                        {t("settings.exportBackup")}
                      </span>
                      <span class="text-[10px] font-normal text-[var(--color-muted)]">{t("settings.exportBackupHint")}</span>
                    </button>
                    <button
                      data-testid="backup-encrypted"
                      onClick={() => window.__baluardReprompt?.show(() => openBackupPass("export"))}
                      disabled={exporting()}
                      class="flex flex-col items-center justify-center gap-1 p-3 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50"
                    >
                      <span class="flex items-center gap-2">
                        <IconDownload class="w-4 h-4 text-[var(--color-muted)]" />
                        {t("settings.backupExport")}
                      </span>
                      <span class="text-[10px] font-normal text-[var(--color-muted)]">{t("settings.backupExportHint")}</span>
                    </button>
                    <button
                      onClick={() => doExport("bw-csv")}
                      disabled={exporting()}
                      class="flex flex-col items-center justify-center gap-1 p-3 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50"
                    >
                      <span class="flex items-center gap-2">
                        <IconDownload class="w-4 h-4 text-[var(--color-muted)]" />
                        {t("settings.exportSpreadsheet")}
                      </span>
                      <span class="text-[10px] font-normal text-[var(--color-muted)]">{t("settings.exportSpreadsheetHint")}</span>
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

              <Show when={activeTab() === "people"}>
                <PeopleTab />
              </Show>
              <Show when={activeTab() === "space"}>
                <SpaceTab />
              </Show>
              <Show when={activeTab() === "collections"}>
                <CollectionsTab />
              </Show>
              <Show when={activeTab() === "groups"}>
                <GroupsTab />
              </Show>
              <Show when={activeTab() === "contacts"}>
                <ContactsTab />
              </Show>
              <Show when={activeTab() === "outboxes"}>
                <OutboxesTab />
              </Show>

              <Show when={activeTab() === "devices"}>
                <DeviceFleetPanel />
              </Show>
              <Show when={activeTab() === "legacy"}>
                <LegacyTab />
              </Show>
              <Show when={activeTab() === "bridge"}>
                <BridgeTab />
              </Show>
            </div>

            {/* Encrypted-backup passphrase dialog (§7). One dialog, both
                directions. Export prefills a generated 6-word passphrase and
                requires the saved acknowledgment; import explains this is the
                backup's password, not the master password. */}
            <Show when={backupMode()}>
              <div
                ref={backupDialogRef}
                data-testid="backup-pass-dialog"
                class="fixed inset-0 bg-black/60 flex items-center justify-center z-[110]"
                onClick={() => !backupBusy() && closeBackupPass()}
              >
                <FocusTrap containerRef={backupDialogRef} onEscape={() => !backupBusy() && closeBackupPass()} />
                <div
                  class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[460px] max-w-[92vw] p-5 space-y-3"
                  onClick={(e) => e.stopPropagation()}
                >
                  <label class="text-sm font-bold text-[var(--color-text)]">
                    {backupMode() === "export" ? t("settings.backupPassTitleExport") : t("settings.backupPassTitleImport")}
                  </label>
                  <p class="text-xs text-[var(--color-muted)]">
                    {backupMode() === "export" ? t("settings.backupPassDesc") : t("settings.backupPassImportDesc")}
                  </p>
                  <div class="flex gap-2">
                    <input
                      data-testid="backup-pass-input"
                      value={backupPw()}
                      onInput={(e) => setBackupPw(e.currentTarget.value)}
                      type={backupMode() === "export" ? "text" : "password"}
                      spellcheck={false}
                      autocomplete="off"
                      class="flex-1 px-3 py-2 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                    />
                    <Show when={backupMode() === "export"}>
                      <button
                        onClick={regenBackupPw}
                        title={t("settings.backupRegenerate")}
                        class="px-2.5 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] transition-all cursor-pointer"
                      >
                        <IconRefresh class="w-4 h-4 text-[var(--color-muted)]" />
                      </button>
                      <button
                        onClick={() => copyToClipboard(backupPw())}
                        title={t("common.copy")}
                        class="px-2.5 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] transition-all cursor-pointer"
                      >
                        <IconCopy class="w-4 h-4 text-[var(--color-muted)]" />
                      </button>
                    </Show>
                  </div>
                  <Show when={backupMode() === "export"}>
                    <input
                      value={backupPwConfirm()}
                      onInput={(e) => setBackupPwConfirm(e.currentTarget.value)}
                      placeholder={t("settings.backupPassConfirmLabel")}
                      spellcheck={false}
                      autocomplete="off"
                      class="w-full px-3 py-2 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                    />
                    <label class="flex items-start gap-2 text-xs text-[var(--color-text)] cursor-pointer">
                      <input
                        data-testid="backup-saved-ack"
                        type="checkbox"
                        checked={backupPwSaved()}
                        onChange={(e) => setBackupPwSaved(e.currentTarget.checked)}
                        class="mt-0.5 accent-[var(--color-primary)]"
                      />
                      {t("settings.backupSavedAck")}
                    </label>
                  </Show>
                  <div class="flex justify-end gap-2 pt-1">
                    <button
                      data-testid="backup-cancel"
                      onClick={closeBackupPass}
                      disabled={backupBusy()}
                      class="px-4 py-2 rounded-xl text-xs text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-40"
                    >
                      {t("common.cancel")}
                    </button>
                    <button
                      data-testid="backup-confirm"
                      onClick={confirmBackup}
                      disabled={
                        backupBusy() ||
                        backupPw().length < 8 ||
                        (backupMode() === "export" &&
                          (backupPw() !== backupPwConfirm() || !backupPwSaved()))
                      }
                      class="px-5 py-2 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {backupMode() === "export" ? t("settings.exportBackup") : t("settings.import")}
                    </button>
                  </div>
                </div>
              </div>
            </Show>

            {/* Security check findings. The report is already grouped
                weak/reused/old server-side; entries localize via the
                machine kind with the raw reason as fallback. */}
            <Show when={healthOpen() && healthReport()}>
              <div
                ref={healthDialogRef}
                class="fixed inset-0 bg-black/60 flex items-center justify-center z-[110]"
                onClick={() => setHealthOpen(false)}
              >
                <FocusTrap containerRef={healthDialogRef} onEscape={() => setHealthOpen(false)} />
                <div
                  class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[560px] max-w-[92vw] max-h-[80vh] flex flex-col"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div class="p-5 pb-3 border-b border-[var(--color-border)]">
                    <label class="text-sm font-bold text-[var(--color-text)]">{t("settings.healthCheck")}</label>
                  </div>
                  <div class="flex-1 overflow-y-auto p-5 space-y-4">
                    <For each={["weak", "reused", "old"]}>
                      {(group) => (
                        <Show when={(healthReport()[group] || []).length > 0}>
                          <div class="space-y-1.5">
                            <div class="text-xs font-bold text-[var(--color-text)]">
                              {t(group === "weak" ? "settings.healthWeak" : group === "reused" ? "settings.healthReused" : "settings.healthOld")} ({healthReport()[group].length})
                            </div>
                            <For each={healthReport()[group]}>
                              {(f) => (
                                <div class="px-3 py-2 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)]" data-testid="health-finding">
                                  <div class="text-xs text-[var(--color-text)]">{f.name}</div>
                                  <div class="text-[10px] text-[var(--color-muted)] mt-0.5">{healthReason(f)}</div>
                                </div>
                              )}
                            </For>
                          </div>
                        </Show>
                      )}
                    </For>
                    <Show when={
                      (healthReport().weak?.length ?? 0) +
                        (healthReport().reused?.length ?? 0) +
                        (healthReport().old?.length ?? 0) === 0
                    }>
                      <p class="text-xs text-[var(--color-muted)]">{t("settings.healthEmpty")}</p>
                    </Show>
                  </div>
                  <div class="p-5 pt-3 border-t border-[var(--color-border)] flex justify-end">
                    <button
                      onClick={() => setHealthOpen(false)}
                      class="px-5 py-2 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer shadow-md"
                    >
                      {t("common.close")}
                    </button>
                  </div>
                </div>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
