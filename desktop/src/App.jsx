import { createSignal, onMount, onCleanup, Show, For, createContext, useContext, createEffect } from "solid-js";
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

// Normalize URI (string or {uri, match_strategy}) to plain string
const uriStr = (u) => typeof u === "string" ? u : (u?.uri || "");

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
  
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += pool.charAt(arr[i] % pool.length);
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
  const [selectedFolder, setSelectedFolder] = createSignal(null);
  const [folders, setFolders] = createSignal([]);
  const [searchQuery, setSearchQuery] = createSignal("");
  
  // View/Form states
  const [activePane, setActivePane] = createSignal("welcome"); // 'welcome', 'detail', 'add', 'edit'
  const [viewCipher, setViewCipher] = createSignal(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);
const [showReprompt, setShowReprompt] = createSignal(false);
const [repromptCallback, setRepromptCallback] = createSignal(null);
const [biometricAvailable, setBiometricAvailable] = createSignal(false);

// Check biometric availability on load
createEffect(() => {
  daemon("vault.biometric_status").then(r => {
    const s = JSON.parse(r);
    setBiometricAvailable(s.available && s.enabled);
  }).catch(() => {});
});
  const [showGenerator, setShowGenerator] = createSignal(false);
  const [showSettingsModal, setShowSettingsModal] = createSignal(false);
  
  // New / Edited entry buffers
  const [newCipher, setNewCipher] = createSignal({
    name: "", username: "", password: "", uris: [], notes: "", cipherType: "login", favorite: false, reprompt: false, attachments: [], folder_id: null, custom_fields: [], totp_uri: "",
  });
  
  const [trashCiphers, setTrashCiphers] = createSignal([]);
  const [archivedCiphers, setArchivedCiphers] = createSignal([]);
  const [deviceFleet, setDeviceFleet] = createSignal([]);
const [selfDeviceId, setSelfDeviceId] = createSignal(null);
  const [revokeWarning, setRevokeWarning] = createSignal(null);
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
    trashCiphers, setTrashCiphers,
    archivedCiphers, setArchivedCiphers,
    deviceFleet, setDeviceFleet,
    selfDeviceId, setSelfDeviceId,
    revokeWarning, setRevokeWarning,
    error, setError,
    vaultInfo, setVaultInfo,
    theme, setTheme,
    selectedCategory, setSelectedCategory,
  selectedFolder, setSelectedFolder,
  folders, setFolders,
    searchQuery, setSearchQuery,
    activePane, setActivePane,
    viewCipher, setViewCipher,
    showDeleteConfirm, setShowDeleteConfirm,
  showReprompt, setShowReprompt,
  repromptCallback, setRepromptCallback,
  biometricAvailable,
    showGenerator, setShowGenerator,
    showSettingsModal, setShowSettingsModal,
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
  const { t } = useI18n();
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
      app.setRevokeWarning(null);
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

  async function refreshTrashCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.trash.list"));
      const ids = data.cipher_ids || [];
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
      app.setTrashCiphers(fullCiphers);
    } catch (e) {
      // Non-critical
    }
  }

  async function refreshArchivedCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.list_archived"));
      const metas = data.ciphers || [];
      const fullCiphers = await Promise.all(
        metas.map(async (meta) => {
          try {
            const detailStr = await daemon("vault.get", JSON.stringify({ id: meta.id, decrypt: true }));
            return JSON.parse(detailStr);
          } catch (e) {
            return { id: meta.id, name: "Decryption Error", username: "", uris: [] };
          }
        })
      );
      app.setArchivedCiphers(fullCiphers);
    } catch (e) {
      // Non-critical
    }
  }

  async function refreshDeviceFleet() {
    try {
      const resp = await invoke("daemon_request", { action: "vault.device_activity", payload: "" });
      const data = typeof resp === "string" ? JSON.parse(resp) : resp;
      app.setDeviceFleet(data.devices || []);
      if (data.self_device_id) app.setSelfDeviceId(data.self_device_id);
    } catch (e) {
      // Non-critical
    }
  }

  async function refreshCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.list"));
      // vault.list now returns {ciphers: [CipherMeta]} with type, favorite, username
      const metas = data.ciphers || [];
      
      // Decrypt and load full details in parallel
      const fullCiphers = await Promise.all(
        metas.map(async (meta) => {
          try {
            const detailStr = await daemon("vault.get", JSON.stringify({ id: meta.id, decrypt: true }));
            return { ...JSON.parse(detailStr), _meta: meta };
          } catch (e) {
            return { ...meta, name: meta.name || "Decryption Error", username: "", uris: [] };
          }
        })
      );
      
      app.setCiphers(fullCiphers);

      // Load folders
      try {
        const folderData = JSON.parse(await daemon("folder.list"));
        app.setFolders(Array.isArray(folderData) ? folderData : []);
      } catch (e) {}

      await refreshTrashCiphers();
      await refreshArchivedCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function addCipher(t) {
    const c = app.newCipher();
    if (!c.name) {
      app.setError(t("entry.namePlaceholder") + " required");
      return;
    }
    try {
      const cipherType = c.cipherType || "login";
      let kind;
      if (cipherType === "secureNote") {
        kind = { type: "secureNote", data: {} };
      } else if (cipherType === "card") {
        kind = {
          type: "card",
          data: {
            cardholder_name: c.cardholder_name || null,
            number: c.cardNumber || null,
            brand: c.cardBrand || null,
            exp_month: c.expMonth || null,
            exp_year: c.expYear || null,
            code: c.cvv || null,
          },
        };
      } else if (cipherType === "identity") {
        kind = {
          type: "identity",
          data: {
            title: c.idTitle || null,
            first_name: c.firstName || null,
            middle_name: c.middleName || null,
            last_name: c.lastName || null,
            username: c.username || null,
            company: c.company || null,
            email: c.email || null,
            phone: c.phone || null,
            address1: c.address1 || null,
            address2: c.address2 || null,
            address3: c.address3 || null,
            city: c.city || null,
            state: c.state || null,
            postal_code: c.postalCode || null,
            country: c.country || null,
            ssn: c.ssn || null,
            passport_number: c.passportNumber || null,
            license_number: c.licenseNumber || null,
          },
        };
      } else if (cipherType === "sshKey") {
        kind = {
          type: "sshKey",
          data: {
            public_key: c.publicKey || null,
            private_key: c.privateKey || null,
            key_fingerprint: c.fingerprint || null,
          },
        };
      } else if (cipherType === "bankAccount") {
        kind = {
          type: "bankAccount",
          data: {
            bank_name: c.bankName || null,
            name_on_account: c.nameOnAccount || null,
            account_type: c.accountType || null,
            account_number: c.accountNumber || null,
            routing_number: c.routingNumber || null,
            branch_number: c.branchNumber || null,
            pin: c.bankPin || null,
            swift_code: c.swiftCode || null,
            iban: c.iban || null,
            bank_contact_phone: c.bankPhone || null,
          },
        };
      } else if (cipherType === "driversLicense") {
        kind = {
          type: "driversLicense",
          data: {
            first_name: c.dlFirstName || null,
            middle_name: c.dlMiddleName || null,
            last_name: c.dlLastName || null,
            date_of_birth: c.dlDob || null,
            license_number: c.dlNumber || null,
            issuing_country: c.dlCountry || null,
            issuing_state: c.dlState || null,
            issue_date: c.dlIssueDate || null,
            expiration_date: c.dlExpDate || null,
            issuing_authority: c.dlAuthority || null,
            license_class: c.dlClass || null,
          },
        };
      } else if (cipherType === "passport") {
        kind = {
          type: "passport",
          data: {
            surname: c.ppSurname || null,
            given_name: c.ppGivenName || null,
            date_of_birth: c.ppDob || null,
            sex: c.ppSex || null,
            birth_place: c.ppBirthPlace || null,
            nationality: c.ppNationality || null,
            issuing_country: c.ppCountry || null,
            passport_number: c.ppNumber || null,
            passport_type: c.ppType || null,
            national_identification_number: c.ppNationalId || null,
            issuing_authority: c.ppAuthority || null,
            issue_date: c.ppIssueDate || null,
            expiration_date: c.ppExpDate || null,
          },
        };
      } else {
        // Login
        kind = {
          type: "login",
          data: {
            username: c.username || null,
            password: c.password || null,
            uris: (c.uris || []).map(u => {
              const obj = { uri: u.uri || u };
              if (u.match_strategy) obj.match_strategy = u.match_strategy;
              return obj;
            }),
            totp_uri: c.totp_uri || null,
          },
        };
      }
      await daemon("vault.add", JSON.stringify({
        name: c.name,
        kind,
        favorite: c.favorite || false,
        notes: c.notes || null,
        folder_id: c.folder_id || null,
        custom_fields: c.custom_fields || [],
      }));
      app.setNewCipher({ name: "", username: "", password: "", uris: [], notes: "", cipherType: "login", favorite: false, reprompt: false, attachments: [], folder_id: null, custom_fields: [], totp_uri: "" });
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
      const cipherType = c.cipherType || "login";
      let kind;
      if (cipherType === "secureNote") {
        kind = { type: "secureNote", data: {} };
      } else if (cipherType === "card") {
        kind = {
          type: "card",
          data: {
            cardholder_name: c.cardholder_name || null,
            number: c.cardNumber || null,
            brand: c.cardBrand || null,
            exp_month: c.expMonth || null,
            exp_year: c.expYear || null,
            code: c.cvv || null,
          },
        };
      } else if (cipherType === "identity") {
        kind = {
          type: "identity",
          data: {
            title: c.idTitle || null,
            first_name: c.firstName || null,
            middle_name: c.middleName || null,
            last_name: c.lastName || null,
            username: c.username || null,
            company: c.company || null,
            email: c.email || null,
            phone: c.phone || null,
            address1: c.address1 || null,
            address2: c.address2 || null,
            address3: c.address3 || null,
            city: c.city || null,
            state: c.state || null,
            postal_code: c.postalCode || null,
            country: c.country || null,
            ssn: c.ssn || null,
            passport_number: c.passportNumber || null,
            license_number: c.licenseNumber || null,
          },
        };
      } else if (cipherType === "sshKey") {
        kind = {
          type: "sshKey",
          data: {
            public_key: c.publicKey || null,
            private_key: c.privateKey || null,
            key_fingerprint: c.fingerprint || null,
          },
        };
      } else if (cipherType === "bankAccount") {
        kind = {
          type: "bankAccount",
          data: {
            bank_name: c.bankName || null,
            name_on_account: c.nameOnAccount || null,
            account_type: c.accountType || null,
            account_number: c.accountNumber || null,
            routing_number: c.routingNumber || null,
            branch_number: c.branchNumber || null,
            pin: c.bankPin || null,
            swift_code: c.swiftCode || null,
            iban: c.iban || null,
            bank_contact_phone: c.bankPhone || null,
          },
        };
      } else if (cipherType === "driversLicense") {
        kind = {
          type: "driversLicense",
          data: {
            first_name: c.dlFirstName || null,
            middle_name: c.dlMiddleName || null,
            last_name: c.dlLastName || null,
            date_of_birth: c.dlDob || null,
            license_number: c.dlNumber || null,
            issuing_country: c.dlCountry || null,
            issuing_state: c.dlState || null,
            issue_date: c.dlIssueDate || null,
            expiration_date: c.dlExpDate || null,
            issuing_authority: c.dlAuthority || null,
            license_class: c.dlClass || null,
          },
        };
      } else if (cipherType === "passport") {
        kind = {
          type: "passport",
          data: {
            surname: c.ppSurname || null,
            given_name: c.ppGivenName || null,
            date_of_birth: c.ppDob || null,
            sex: c.ppSex || null,
            birth_place: c.ppBirthPlace || null,
            nationality: c.ppNationality || null,
            issuing_country: c.ppCountry || null,
            passport_number: c.ppNumber || null,
            passport_type: c.ppType || null,
            national_identification_number: c.ppNationalId || null,
            issuing_authority: c.ppAuthority || null,
            issue_date: c.ppIssueDate || null,
            expiration_date: c.ppExpDate || null,
          },
        };
      } else {
        kind = {
          type: "login",
          data: {
            username: c.username || null,
            password: c.password || null,
            uris: (c.uris || []).map(u => {
              const obj = { uri: u.uri || u };
              if (u.match_strategy) obj.match_strategy = u.match_strategy;
              return obj;
            }),
            totp_uri: c.totp_uri || null,
          },
        };
      }
      await daemon("vault.update", JSON.stringify({
        id,
        name: c.name,
        kind,
        favorite: c.favorite || false,
        notes: c.notes || null,
        folder_id: c.folder_id || null,
        custom_fields: c.custom_fields || [],
      }));
      app.setActivePane("welcome");
      await refreshCiphers();
      
      // Select the updated item
      const updatedData = JSON.parse(await daemon("vault.get", JSON.stringify({ id, decrypt: true })));
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

  async function restoreCipher(id, t) {
    try {
      await daemon("vault.trash.restore", id);
      app.setViewCipher(null);
      app.setActivePane("welcome");
      await refreshCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function archiveCipher(id) {
    try {
      await daemon("vault.archive", id);
      app.setViewCipher(null);
      app.setActivePane("welcome");
      await refreshCiphers();
      await refreshArchivedCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function unarchiveCipher(id) {
    try {
      await daemon("vault.unarchive", id);
      app.setViewCipher(null);
      app.setActivePane("welcome");
      await refreshCiphers();
      await refreshArchivedCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  function onKeyUnlock(e) {
    if (e.key === "Enter") unlock(useI18n().t);
  }

  return { loginPasswordRef, setLoginPasswordRef: (r) => { loginPasswordRef = r; }, unlock, lock, createVault, refreshCiphers, addCipher, updateCipher, getCipher, deleteCipher, restoreCipher, archiveCipher, unarchiveCipher, onKeyUnlock, refreshDeviceFleet };
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

function detectCardBrand(number) {
  const n = number.replace(/\s/g, "");
  if (!n) return null;
  if (/^4/.test(n)) return "Visa";
  if (/^5[1-5]/.test(n) || /^2[2-7]/.test(n)) return "Mastercard";
  if (/^3[47]/.test(n)) return "Amex";
  if (/^6(?:011|5)/.test(n)) return "Discover";
  if (/^35(?:2[89]|[3-8])/.test(n)) return "JCB";
  return null;
}

function CardBrandDisplay(props) {
  const brand = () => detectCardBrand(props.number);
  const brandColors = { Visa: "bg-blue-600", Mastercard: "bg-orange-500", Amex: "bg-blue-800", Discover: "bg-orange-600", JCB: "bg-green-600" };
  return (
    <Show when={brand()}>
      <div class={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg ${brandColors[brand()] || "bg-slate-600"} text-white text-xs font-bold`}>
        {brand()}
      </div>
    </Show>
  );
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

function GeneratorModal() {
  const { showGenerator, setShowGenerator } = useApp();

  const [genLen, setGenLen] = createSignal(20);
  const [genUpper, setGenUpper] = createSignal(true);
  // Note: lowercase is always included (matches Bitwarden behavior)
  const [genNums, setGenNums] = createSignal(true);
  const [genSyms, setGenSyms] = createSignal(true);
  const [genMode, setGenMode] = createSignal("password");
  const [genResult, setGenResult] = createSignal("");

  // Passphrase settings
  const [passWords, setPassWords] = createSignal(4);
  const [passSep, setPassSep] = createSignal("-");
  const [passCap, setPassCap] = createSignal(false);
  const [passNum, setPassNum] = createSignal(false);

  const EFF_WORDS = ["abacus","abdomen","abdominal","abide","abiding","ability","ablaze","able","abnormal","abrasion","abrasive","abreast","abridge","abroad","abruptly","absence","absentee","absently","absinthe","absolute","absolve","abstain","abstract","absurd","accent","acclaim","acclimate","accompany","account","accuracy","accurate","accustom","acetone","achiness","aching","acid","acorn","acquaint","acquire","acre","acrobat","acronym","acting","action","activate","activator","active","activism","activist","activity","actress","acts","acutely","acuteness","aeration","aerobics","aerosol","aerospace","afar","affair","affected","affecting","affection","affidavit","affiliate","affirm","affix","afflicted","affluent","afford","affront","aflame","afloat","aflutter","afoot","afraid","afterglow","afterlife","aftermath","aftermost","afternoon","aged","ageless","agency","agenda","agent","aggregate","aghast","agile","agility","aging","agnostic","agonize","agonizing","agony","agreeable","agreeably","agreed","agreeing","agreement","aground","ahead","ahoy","aide","aids","aim","ajar","alabaster","alarm","albatross","album","alfalfa","algebra","algorithm","alias","alibi","alienable","alienate","aliens","alike","alive","alkaline","alkalize","almanac","almighty","almost","aloe","aloft","aloha","alone","alongside","aloof","alphabet","alright","although","altitude","alto","aluminum","alumni","always","amaretto","amaze","amazingly","amber","ambiance","ambiguity","ambiguous","ambition","ambitious","ambulance","ambush","amendable","amendment","amends","amenity","amiable","amicably","amid","amigo","amino","amiss","ammonia","ammonium","amnesty","amniotic","among","amount","amperage","ample","amplifier","amplify","amply","amuck","amulet","amusable","amused","amusement","amuser","amusing","anaconda","anaerobic","anagram","anatomist","anatomy","anchor","anchovy","ancient","android","anemia","anemic","aneurism","anew","angelfish","angelic","anger","angled","angler","angles","angling","angrily","angriness","anguished","angular","animal","animate","animating","animation","animator","anime","animosity","ankle","annex","annotate","announcer","annoying","annually","annuity","anointer","another","answering","antacid","antarctic","anteater","antelope","antennae","anthem","anthill","anthology","antibody","antics","antidote","antihero","antiquely","antiques","antiquity","antirust","antitoxic","antitrust","antiviral","antivirus","antler","antonym","antsy","anvil","anybody","anyhow","anymore","anyone","anyplace","anything","anytime","anyway","anywhere","aorta","apache","apostle","appealing","appear","appease","appeasing","appendage","appendix","appetite","appetizer","applaud","applause","apple","appliance","applicant","applied","apply","appointee","appraisal","appraiser","apprehend","approach","approval","approve","apricot","april","apron","aptitude","aptly","aqua","aqueduct","arbitrary","arbitrate","ardently","area","arena","arguable","arguably","argue","arise","armadillo","armband","armchair","armed","armful","armhole","arming","armless","armoire","armored","armory","armrest","army","aroma","arose","around","arousal","arrange","array","arrest","arrival","arrive","arrogance","arrogant","arson","art","ascend","ascension","ascent","ascertain","ashamed","ashen","ashes","ashy","aside","askew","asleep","asparagus","aspect","aspirate","aspire","aspirin","astonish","astound","astride","astrology","astronaut","astronomy","astute","atlantic","atlas","atom","atonable","atop","atrium","atrocious","atrophy","attach","attain","attempt","attendant","attendee","attention","attentive","attest","attic","attire","attitude","attractor","attribute","atypical","auction","audacious","audacity","audible","audibly","audience","audio","audition","augmented","august","authentic","author","autism","autistic","autograph","automaker","automated","automatic","autopilot","available","avalanche","avatar","avenge","avenging","avenue","average","aversion","avert","aviation","aviator","avid","avoid","await","awaken","award","aware","awhile","awkward","awning","awoke","awry","axis","babble","babbling","babied","baboon","backache","backboard","backboned","backdrop","backed","backer","backfield","backfire","backhand","backing","backlands","backlash","backless","backlight","backlit","backlog","backpack","backpedal","backrest","backroom","backshift","backside","backslid","backspace","backspin","backstab","backstage","backtalk","backtrack","backup","backward","backwash","backwater","backyard","bacon","bacteria","bacterium","badass","badge","badland","badly","badness","baffle","baffling","bagel","bagful","baggage","bagged","baggie","bagginess","bagging","baggy","bagpipe","baguette","baked","bakery","bakeshop","baking","balance","balancing","balcony","balmy","balsamic","bamboo","banana","banish","banister","banjo","bankable","bankbook","banked","banker","banking","banknote","bankroll","banner","bannister","banshee","banter","barbecue","barbed","barbell","barber","barcode","barge","bargraph","barista","baritone","barley","barmaid","barman","barn","barometer","barrack","barracuda","barrel","barrette","barricade","barrier","barstool","bartender","barterer","bash","basically","basics","basil","basin","basis","basket","batboy","batch","bath","baton","bats","battalion","battered","battering","battery","batting","battle","bauble","bazooka","blabber","bladder","blade","blah","blame","blaming","blanching","blandness","blank","blaspheme","blasphemy","blast","blatancy","blatantly","blazer","blazing","bleach","bleak","bleep","blemish","blend","bless","blighted","blimp","bling","blinked","blinker","blinking","blinks","blip","blissful","blitz","blizzard","bloated","bloating","blob","blog","bloomers","blooming","blooper","blot","blouse","blubber","bluff","bluish","blunderer","blunt","blurb","blurred","blurry","blurt","blush","blustery","boaster","boastful","boasting","boat","bobbed","bobbing","bobble","bobcat","bobsled","bobtail","bodacious","body","bogged","boggle","bogus","boil","bok","bolster","bolt","bonanza","bonded","bonding","bondless","boned","bonehead","boneless","bonelike","boney","bonfire","bonnet","bonsai","bonus","bony","boogeyman","boogieman","book","boondocks","booted","booth","bootie","booting","bootlace","bootleg","boots","boozy","borax","boring","borough","borrower","borrowing","boss","botanical","botanist","botany","botch","both","bottle","bottling","bottom","bounce","bouncing","bouncy","bounding","boundless","bountiful","bovine","boxcar","boxer","boxing","boxlike","boxy","breach","breath","breeches","breeching","breeder","breeding","breeze","breezy","brethren","brewery","brewing","briar","bribe","brick","bride","bridged","brigade","bright","brilliant","brim","bring","brink","brisket","briskly","briskness","bristle","brittle","broadband","broadcast","broaden","broadly","broadness","broadside","broadways","broiler","broiling","broken","broker","bronchial","bronco","bronze","bronzing","brook","broom","brought","browbeat","brownnose","browse","browsing","bruising","brunch","brunette","brunt","brush","brussels","brute","brutishly","bubble","bubbling","bubbly","buccaneer","bucked","bucket","buckle","buckshot","buckskin","bucktooth","buckwheat","buddhism","buddhist","budding","buddy","budget","buffalo","buffed","buffer","buffing","buffoon","buggy","bulb","bulge","bulginess","bulgur","bulk","bulldog","bulldozer","bullfight","bullfrog","bullhorn","bullion","bullish","bullpen","bullring","bullseye","bullwhip","bully","bunch","bundle","bungee","bunion","bunkbed","bunkhouse","bunkmate","bunny","bunt","busboy","bush","busily","busload","bust","busybody","buzz","cabana","cabbage","cabbie","cabdriver","cable","caboose","cache","cackle","cacti","cactus","caddie","caddy","cadet","cadillac","cadmium","cage","cahoots","cake","calamari","calamity","calcium","calculate","calculus","caliber","calibrate","calm","caloric","calorie","calzone","camcorder","cameo","camera","camisole","camper","campfire","camping","campsite","campus","canal","canary","cancel","candied","candle","candy","cane","canine","canister","cannabis","canned","canning","cannon","cannot","canola","canon","canopener","canopy","canteen","canyon","capable","capably","capacity","cape","capillary","capital","capitol","capped","capricorn","capsize","capsule","caption","captivate","captive","captivity","capture","caramel","carat","caravan","carbon","cardboard","carded","cardiac","cardigan","cardinal","cardstock","carefully","caregiver","careless","caress","caretaker","cargo","caring","carless","carload","carmaker","carnage","carnation","carnival","carnivore","carol","carpenter","carpentry","carpool","carport","carried","carrot","carrousel","carry","cartel","cartload","carton","cartoon","cartridge","cartwheel","carve","carving","carwash","cascade","case","cash","casing","casino","casket","cassette","casually","casualty","catacomb","catalog","catalyst","catalyze","catapult","cataract","catatonic","catcall","catchable","catcher","catching","catchy","caterer","catering","catfight","catfish","cathedral","cathouse","catlike","catnap","catnip","catsup","cattail","cattishly","cattle","catty","catwalk","caucasian","caucus","causal","causation","cause","causing","cauterize","caution","cautious","cavalier","cavalry","caviar","cavity","cedar","celery","celestial","celibacy","celibate","celtic","cement","census","ceramics","ceremony","certainly","certainty","certified","certify","cesarean","cesspool","chafe","chaffing","chain","chair","chalice","challenge","chamber","chamomile","champion","chance","change","channel","chant","chaos","chaperone","chaplain","chapped","chaps","chapter","character","charbroil","charcoal","charger","charging","chariot","charity","charm","charred","charter","charting","chase","chasing","chaste","chastise","chastity","chatroom","chatter","chatting","chatty","cheating","cheddar","cheek","cheer","cheese","cheesy","chef","chemicals","chemist","chemo","cherisher","cherub","chess","chest","chevron","chevy","chewable","chewer","chewing","chewy","chief","chihuahua","childcare","childhood","childish","childless","childlike","chili","chill","chimp","chip","chirping","chirpy","chitchat","chivalry","chive","chloride","chlorine","choice","chokehold","choking","chomp","chooser","choosing","choosy","chop","chosen","chowder","chowtime","chrome","chubby","chuck","chug","chummy","chump","chunk","churn","chute","cider","cilantro","cinch","cinema","cinnamon","circle","circling","circular","circulate","circus","citable","citadel","citation","citizen","citric","citrus","city","civic","civil","clad","claim","clambake","clammy","clamor","clamp","clamshell","clang","clanking","clapped","clapper","clapping","clarify","clarinet","clarity","clash","clasp","class","clatter","clause","clavicle","claw","clay","clean","clear","cleat","cleaver","cleft","clench","clergyman","clerical","clerk","clever","clicker","client","climate","climatic","cling","clinic","clinking","clip","clique","cloak","clobber","clock","clone","cloning","closable","closure","clothes","clothing","cloud","clover","clubbed","clubbing","clubhouse","clump","clumsily","clumsy","clunky","clustered","clutch","clutter","coach","coagulant","coastal","coaster","coasting","coastland","coastline","coat","coauthor","cobalt","cobbler","cobweb","cocoa","coconut","cod","coeditor","coerce","coexist","coffee","cofounder","cognition","cognitive","cogwheel","coherence","coherent","cohesive","coil","coke","cola","cold","coleslaw","coliseum","collage","collapse","collar","collected","collector","collide","collie","collision","colonial","colonist","colonize","colony","colossal","colt","coma","come","comfort","comfy","comic","coming","comma","commence","commend","comment","commerce","commode","commodity","commodore","common","commotion","commute","commuting","compacted","compacter","compactly","compactor","companion","company","compare","compel","compile","comply","component","composed","composer","composite","compost","composure","compound","compress","comprised","computer","computing","comrade","concave","conceal","conceded","concept","concerned","concert","conch","concierge","concise","conclude","concrete","concur","condense","condiment","condition","condone","conducive","conductor","conduit","cone","confess","confetti","confidant","confident","confider","confiding","configure","confined","confining","confirm","conflict","conform","confound","confront","confused","confusing","confusion","congenial","congested","congrats","congress","conical","conjoined","conjure","conjuror","connected","connector","consensus","consent","console","consoling","consonant","constable","constant","constrain","constrict","construct","consult","consumer","consuming","contact","container","contempt","contend","contented","contently","contents","contest","context","contort","contour","contrite","control","contusion","convene","convent","copartner","cope","copied","copier","copilot","coping","copious","copper","copy","coral","cork","cornball","cornbread","corncob","cornea","corned","corner","cornfield","cornflake","cornhusk","cornmeal","cornstalk","corny","coronary","coroner","corporal","corporate","corral","correct","corridor","corrode","corroding","corrosive","corsage","corset","cortex","cosigner","cosmetics","cosmic","cosmos","cosponsor","cost","cottage","cotton","couch","cough","could","countable","countdown","counting","countless","country","county","courier","covenant","cover","coveted","coveting","coyness","cozily","coziness","cozy","crabbing","crabgrass","crablike","crabmeat","cradle","cradling","crafter","craftily","craftsman","craftwork","crafty","cramp","cranberry","crane","cranial","cranium","crank","crate","crave","craving","crawfish","crawlers","crawling","crayfish","crayon","crazed","crazily","craziness","crazy","creamed","creamer","creamlike","crease","creasing","creatable","create","creation","creative","creature","credible","credibly","credit","creed","creme","creole","crepe","crept","crescent","crested","cresting","crestless","crevice","crewless","crewman","crewmate","crib","cricket","cried","crier","crimp","crimson","cringe","cringing","crinkle","crinkly","crisped","crisping","crisply","crispness","crispy","criteria","critter","croak","crock","crook","croon","crop","cross","crouch","crouton","crowbar","crowd","crown","crucial","crudely","crudeness","cruelly","cruelness","cruelty","crumb","crummiest","crummy","crumpet","crumpled","cruncher","crunching","crunchy","crusader","crushable","crushed","crusher","crushing","crust","crux","crying","cryptic","crystal","cubbyhole","cube","cubical","cubicle","cucumber","cuddle","cuddly","cufflink","culinary","culminate","culpable","culprit","cultivate","cultural","culture","cupbearer","cupcake","cupid","cupped","cupping","curable","curator","curdle","cure","curfew","curing","curled","curler","curliness","curling","curly","curry","curse","cursive","cursor","curtain","curtly","curtsy","curvature","curve","curvy","cushy","cusp","cussed","custard","custodian","custody","customary","customer","customize","customs","cut","cycle","cyclic","cycling","cyclist","cylinder","cymbal","cytoplasm","cytoplast","dab","dad","daffodil","dagger","daily","daintily","dainty","dairy","daisy","dallying","dance","dancing","dandelion","dander","dandruff","dandy","danger","dangle","dangling","daredevil","dares","daringly","darkened","darkening","darkish","darkness","darkroom","darling","darn","dart","darwinism","dash","dastardly","data","datebook","dating","daughter","daunting","dawdler","dawn","daybed","daybreak","daycare","daydream","daylight","daylong","dayroom","daytime","dazzler","dazzling","deacon","deafening","deafness","dealer","dealing","dealmaker","dealt","dean","debatable","debate","debating","debit","debrief","debtless","debtor","debug","debunk","decade","decaf","decal","decathlon","decay","deceased","deceit","deceiver","deceiving","december","decency","decent","deception","deceptive","decibel","decidable","decimal","decimeter","decipher","deck","declared","decline","decode","decompose","decorated","decorator","decoy","decrease","decree","dedicate","dedicator","deduce","deduct","deed","deem","deepen","deeply","deepness","deface","defacing","defame","default","defeat","defection","defective","defendant","defender","defense","defensive","deferral","deferred","defiance","defiant","defile","defiling","define","definite","deflate","deflation","deflator","deflected","deflector","defog","deforest","defraud","defrost","deftly","defuse","defy","degraded","degrading","degrease","degree","dehydrate","deity","dejected","delay","delegate","delegator","delete","deletion","delicacy","delicate","delicious","delighted","delirious","delirium","deliverer","delivery","delouse","delta","deluge","delusion","deluxe","demanding","demeaning","demeanor","demise","democracy","democrat","demote","demotion","demystify","denatured","deniable","denial","denim","denote","dense","density","dental","dentist","denture","deny","deodorant","deodorize","departed","departure","depict","deplete","depletion","deplored","deploy","deport","depose","depraved","depravity","deprecate","depress","deprive","depth","deputize","deputy","derail","deranged","derby","derived","desecrate","deserve","deserving","designate","designed","designer","designing","deskbound","desktop","deskwork","desolate","despair","despise","despite","destiny","destitute","destruct","detached","detail","detection","detective","detector","detention","detergent","detest","detonate","detonator","detoxify","detract","deuce","devalue","deviancy","deviant","deviate","deviation","deviator","device","devious","devotedly","devotee","devotion","devourer","devouring","devoutly","dexterity","dexterous","diabetes","diabetic","diabolic","diagnoses","diagnosis","diagram","dial","diameter","diaper","diaphragm","diary","dice","dicing","dictate","dictation","dictator","difficult","diffused","diffuser","diffusion","diffusive","dig","dilation","diligence","diligent","dill","dilute","dime","diminish","dimly","dimmed","dimmer","dimness","dimple","diner","dingbat","dinghy","dinginess","dingo","dingy","dining","dinner","diocese","dioxide","diploma","dipped","dipper","dipping","directed","direction","directive","directly","directory","direness","dirtiness","disabled","disagree","disallow","disarm","disarray","disaster","disband","disbelief","disburse","discard","discern","discharge","disclose","discolor","discount","discourse","discover","discuss","disdain","disengage","disfigure","disgrace","dish","disinfect","disjoin","disk","dislike","disliking","dislocate","dislodge","disloyal","dismantle","dismay","dismiss","dismount","disobey","disorder","disown","disparate","disparity","dispatch","dispense","dispersal","dispersed","disperser","displace","display","displease","disposal","dispose","disprove","dispute","disregard","disrupt","dissuade","distance","distant","distaste","distill","distinct","distort","distract","distress","district","distrust","ditch","ditto","ditzy","dividable","divided","dividend","dividers","dividing","divinely","diving","divinity","divisible","divisibly","division","divisive","divorcee","dizziness","dizzy","doable","docile","dock","doctrine","document","dodge","dodgy","doily","doing","dole","dollar","dollhouse","dollop","dolly","dolphin","domain","domelike","domestic","dominion","dominoes","donated","donation","donator","donor","donut","doodle","doorbell","doorframe","doorknob","doorman","doormat","doornail","doorpost","doorstep","doorstop","doorway","doozy","dork","dormitory","dorsal","dosage","dose","dotted","doubling","douche","dove","down","dowry","doze","drab","dragging","dragonfly","dragonish","dragster","drainable","drainage","drained","drainer","drainpipe","dramatic","dramatize","drank","drapery","drastic","draw","dreaded","dreadful","dreadlock","dreamboat","dreamily","dreamland","dreamless","dreamlike","dreamt","dreamy","drearily","dreary","drench","dress","drew","dribble","dried","drier","drift","driller","drilling","drinkable","drinking","dripping","drippy","drivable","driven","driver","driveway","driving","drizzle","drizzly","drone","drool","droop","drop-down","dropbox","dropkick","droplet","dropout","dropper","drove","drown","drowsily","drudge","drum","dry","dubbed","dubiously","duchess","duckbill","ducking","duckling","ducktail","ducky","duct","dude","duffel","dugout","duh","duke","duller","dullness","duly","dumping","dumpling","dumpster","duo","dupe","duplex","duplicate","duplicity","durable","durably","duration","duress","during","dusk","dust","dutiful","duty","duvet","dwarf","dweeb","dwelled","dweller","dwelling","dwindle","dwindling","dynamic","dynamite","dynasty","dyslexia","dyslexic","each","eagle","earache","eardrum","earflap","earful","earlobe","early","earmark","earmuff","earphone","earpiece","earplugs","earring","earshot","earthen","earthlike","earthling","earthly","earthworm","earthy","earwig","easeful","easel","easiest","easily","easiness","easing","eastbound","eastcoast","easter","eastward","eatable","eaten","eatery","eating","eats","ebay","ebony","ebook","ecard","eccentric","echo","eclair","eclipse","ecologist","ecology","economic","economist","economy","ecosphere","ecosystem","edge","edginess","edging","edgy","edition","editor","educated","education","educator","eel","effective","effects","efficient","effort","eggbeater","egging","eggnog","eggplant","eggshell","egomaniac","egotism","egotistic","either","eject","elaborate","elastic","elated","elbow","eldercare","elderly","eldest","electable","election","elective","elephant","elevate","elevating","elevation","elevator","eleven","elf","eligible","eligibly","eliminate","elite","elitism","elixir","elk","ellipse","elliptic","elm","elongated","elope","eloquence","eloquent","elsewhere","elude","elusive","elves","email","embargo","embark","embassy","embattled","embellish","ember","embezzle","emblaze","emblem","embody","embolism","emboss","embroider","emcee","emerald","emergency","emission","emit","emote","emoticon","emotion","empathic","empathy","emperor","emphases","emphasis","emphasize","emphatic","empirical","employed","employee","employer","emporium","empower","emptier","emptiness","empty","emu","enable","enactment","enamel","enchanted","enchilada","encircle","enclose","enclosure","encode","encore","encounter","encourage","encroach","encrust","encrypt","endanger","endeared","endearing","ended","ending","endless","endnote","endocrine","endorphin","endorse","endowment","endpoint","endurable","endurance","enduring","energetic","energize","energy","enforced","enforcer","engaged","engaging","engine","engorge","engraved","engraver","engraving","engross","engulf","enhance","enigmatic","enjoyable","enjoyably","enjoyer","enjoying","enjoyment","enlarged","enlarging","enlighten","enlisted","enquirer","enrage","enrich","enroll","enslave","ensnare","ensure","entail","entangled","entering","entertain","enticing","entire","entitle","entity","entomb","entourage","entrap","entree","entrench","entrust","entryway","entwine","enunciate","envelope","enviable","enviably","envious","envision","envoy","envy","enzyme","epic","epidemic","epidermal","epidermis","epidural","epilepsy","epileptic","epilogue","epiphany","episode","equal","equate","equation","equator","equinox","equipment","equity","equivocal","eradicate","erasable","erased","eraser","erasure","ergonomic","errand","errant","erratic","error","erupt","escalate","escalator","escapable","escapade","escapist","escargot","eskimo","esophagus","espionage","espresso","esquire","essay","essence","essential","establish","estate","esteemed","estimate","estimator","estranged","estrogen","etching","eternal","eternity","ethanol","ether","ethically","ethics","euphemism","evacuate","evacuee","evade","evaluate","evaluator","evaporate","evasion","evasive","even","everglade","evergreen","everybody","everyday","everyone","evict","evidence","evident","evil","evoke","evolution","evolve","exact","exalted","example","excavate","excavator","exceeding","exception","excess","exchange","excitable","exciting","exclaim","exclude","excluding","exclusion","exclusive","excretion","excretory","excursion","excusable","excusably","excuse","exemplary","exemplify","exemption","exerciser","exert","exes","exfoliate","exhale","exhaust","exhume","exile","existing","exit","exodus","exonerate","exorcism","exorcist","expand","expanse","expansion","expansive","expectant","expedited","expediter","expel","expend","expenses","expensive","expert","expire","expiring","explain","expletive","explicit","explode","exploit","explore","exploring","exponent","exporter","exposable","expose","exposure","express","expulsion","exquisite","extended","extending","extent","extenuate","exterior","external","extinct","extortion","extradite","extras","extrovert","extrude","extruding","exuberant","fable","fabric","fabulous","facebook","facecloth","facedown","faceless","facelift","faceplate","faceted","facial","facility","facing","facsimile","faction","factoid","factor","factsheet","factual","faculty","fade","fading","failing","falcon","fall","false","falsify","fame","familiar","family","famine","famished","fanatic","fancied","fanciness","fancy","fanfare","fang","fanning","fantasize","fantastic","fantasy","fascism","fastball","faster","fasting","fastness","faucet","favorable","favorably","favored","favoring","favorite","fax","feast","federal","fedora","feeble","feed","feel","feisty","feline","felt-tip","feminine","feminism","feminist","feminize","femur","fence","fencing","fender","ferment","fernlike","ferocious","ferocity","ferret","ferris","ferry","fervor","fester","festival","festive","festivity","fetal","fetch","fever","fiber","fiction","fiddle","fiddling","fidelity","fidgeting","fidgety","fifteen","fifth","fiftieth","fifty","figment","figure","figurine","filing","filled","filler","filling","film","filter","filth","filtrate","finale","finalist","finalize","finally","finance","financial","finch","fineness","finer","finicky","finished","finisher","finishing","finite","finless","finlike","fiscally","fit","five","flaccid","flagman","flagpole","flagship","flagstick","flagstone","flail","flakily","flaky","flame","flammable","flanked","flanking","flannels","flap","flaring","flashback","flashbulb","flashcard","flashily","flashing","flashy","flask","flatbed","flatfoot","flatly","flatness","flatten","flattered","flatterer","flattery","flattop","flatware","flatworm","flavored","flavorful","flavoring","flaxseed","fled","fleshed","fleshy","flick","flier","flight","flinch","fling","flint","flip","flirt","float","flock","flogging","flop","floral","florist","floss","flounder","flyable","flyaway","flyer","flying","flyover","flypaper","foam","foe","fog","foil","folic","folk","follicle","follow","fondling","fondly","fondness","fondue","font","food","fool","footage","football","footbath","footboard","footer","footgear","foothill","foothold","footing","footless","footman","footnote","footpad","footpath","footprint","footrest","footsie","footsore","footwear","footwork","fossil","foster","founder","founding","fountain","fox","foyer","fraction","fracture","fragile","fragility","fragment","fragrance","fragrant","frail","frame","framing","frantic","fraternal","frayed","fraying","frays","freckled","freckles","freebase","freebee","freebie","freedom","freefall","freehand","freeing","freeload","freely","freemason","freeness","freestyle","freeware","freeway","freewill","freezable","freezing","freight","french","frenzied","frenzy","frequency","frequent","fresh","fretful","fretted","friction","friday","fridge","fried","friend","frighten","frightful","frigidity","frigidly","frill","fringe","frisbee","frisk","fritter","frivolous","frolic","from","front","frostbite","frosted","frostily","frosting","frostlike","frosty","froth","frown","frozen","fructose","frugality","frugally","fruit","frustrate","frying","gab","gaffe","gag","gainfully","gaining","gains","gala","gallantly","galleria","gallery","galley","gallon","gallows","gallstone","galore","galvanize","gambling","game","gaming","gamma","gander","gangly","gangrene","gangway","gap","garage","garbage","garden","gargle","garland","garlic","garment","garnet","garnish","garter","gas","gatherer","gathering","gating","gauging","gauntlet","gauze","gave","gawk","gazing","gear","gecko","geek","geiger","gem","gender","generic","generous","genetics","genre","gentile","gentleman","gently","gents","geography","geologic","geologist","geology","geometric","geometry","geranium","gerbil","geriatric","germicide","germinate","germless","germproof","gestate","gestation","gesture","getaway","getting","getup","giant","gibberish","giblet","giddily","giddiness","giddy","gift","gigabyte","gigahertz","gigantic","giggle","giggling","giggly","gigolo","gilled","gills","gimmick","girdle","giveaway","given","giver","giving","gizmo","gizzard","glacial","glacier","glade","gladiator","gladly","glamorous","glamour","glance","glancing","glandular","glare","glaring","glass","glaucoma","glazing","gleaming","gleeful","glider","gliding","glimmer","glimpse","glisten","glitch","glitter","glitzy","gloater","gloating","gloomily","gloomy","glorified","glorifier","glorify","glorious","glory","gloss","glove","glowing","glowworm","glucose","glue","gluten","glutinous","glutton","gnarly","gnat","goal","goatskin","goes","goggles","going","goldfish","goldmine","goldsmith","golf","goliath","gonad","gondola","gone","gong","good","gooey","goofball","goofiness","goofy","google","goon","gopher","gore","gorged","gorgeous","gory","gosling","gossip","gothic","gotten","gout","gown","grab","graceful","graceless","gracious","gradation","graded","grader","gradient","grading","gradually","graduate","graffiti","grafted","grafting","grain","granddad","grandkid","grandly","grandma","grandpa","grandson","granite","granny","granola","grant","granular","grape","graph","grapple","grappling","grasp","grass","gratified","gratify","grating","gratitude","gratuity","gravel","graveness","graves","graveyard","gravitate","gravity","gravy","gray","grazing","greasily","greedily","greedless","greedy","green","greeter","greeting","grew","greyhound","grid","grief","grievance","grieving","grievous","grill","grimace","grimacing","grime","griminess","grimy","grinch","grinning","grip","gristle","grit","groggily","groggy","groin","groom","groove","grooving","groovy","grope","ground","grouped","grout","grove","grower","growing","growl","grub","grudge","grudging","grueling","gruffly","grumble","grumbling","grumbly","grumpily","grunge","grunt","guacamole","guidable","guidance","guide","guiding","guileless","guise","gulf","gullible","gully","gulp","gumball","gumdrop","gumminess","gumming","gummy","gurgle","gurgling","guru","gush","gusto","gusty","gutless","guts","gutter","guy","guzzler","gyration","habitable","habitant","habitat","habitual","hacked","hacker","hacking","hacksaw","had","haggler","haiku","half","halogen","halt","halved","halves","hamburger","hamlet","hammock","hamper","hamster","hamstring","handbag","handball","handbook","handbrake","handcart","handclap","handclasp","handcraft","handcuff","handed","handful","handgrip","handgun","handheld","handiness","handiwork","handlebar","handled","handler","handling","handmade","handoff","handpick","handprint","handrail","handsaw","handset","handsfree","handshake","handstand","handwash","handwork","handwoven","handwrite","handyman","hangnail","hangout","hangover","hangup","hankering","hankie","hanky","haphazard","happening","happier","happiest","happily","happiness","happy","harbor","hardcopy","hardcore","hardcover","harddisk","hardened","hardener","hardening","hardhat","hardhead","hardiness","hardly","hardness","hardship","hardware","hardwired","hardwood","hardy","harmful","harmless","harmonica","harmonics","harmonize","harmony","harness","harpist","harsh","harvest","hash","hassle","haste","hastily","hastiness","hasty","hatbox","hatchback","hatchery","hatchet","hatching","hatchling","hate","hatless","hatred","haunt","haven","hazard","hazelnut","hazily","haziness","hazing","hazy","headache","headband","headboard","headcount","headdress","headed","header","headfirst","headgear","heading","headlamp","headless","headlock","headphone","headpiece","headrest","headroom","headscarf","headset","headsman","headstand","headstone","headway","headwear","heap","heat","heave","heavily","heaviness","heaving","hedge","hedging","heftiness","hefty","helium","helmet","helper","helpful","helping","helpless","helpline","hemlock","hemstitch","hence","henchman","henna","herald","herbal","herbicide","herbs","heritage","hermit","heroics","heroism","herring","herself","hertz","hesitancy","hesitant","hesitate","hexagon","hexagram","hubcap","huddle","huddling","huff","hug","hula","hulk","hull","human","humble","humbling","humbly","humid","humiliate","humility","humming","hummus","humongous","humorist","humorless","humorous","humpback","humped","humvee","hunchback","hundredth","hunger","hungrily","hungry","hunk","hunter","hunting","huntress","huntsman","hurdle","hurled","hurler","hurling","hurray","hurricane","hurried","hurry","hurt","husband","hush","husked","huskiness","hut","hybrid","hydrant","hydrated","hydration","hydrogen","hydroxide","hyperlink","hypertext","hyphen","hypnoses","hypnosis","hypnotic","hypnotism","hypnotist","hypnotize","hypocrisy","hypocrite","ibuprofen","ice","iciness","icing","icky","icon","icy","idealism","idealist","idealize","ideally","idealness","identical","identify","identity","ideology","idiocy","idiom","idly","igloo","ignition","ignore","iguana","illicitly","illusion","illusive","image","imaginary","imagines","imaging","imbecile","imitate","imitation","immature","immerse","immersion","imminent","immobile","immodest","immorally","immortal","immovable","immovably","immunity","immunize","impaired","impale","impart","impatient","impeach","impeding","impending","imperfect","imperial","impish","implant","implement","implicate","implicit","implode","implosion","implosive","imply","impolite","important","importer","impose","imposing","impotence","impotency","impotent","impound","imprecise","imprint","imprison","impromptu","improper","improve","improving","improvise","imprudent","impulse","impulsive","impure","impurity","iodine","iodize","ion","ipad","iphone","ipod","irate","irk","iron","irregular","irrigate","irritable","irritably","irritant","irritate","islamic","islamist","isolated","isolating","isolation","isotope","issue","issuing","italicize","italics","item","itinerary","itunes","ivory","ivy","jab","jackal","jacket","jackknife","jackpot","jailbird","jailbreak","jailer","jailhouse","jalapeno","jam","janitor","january","jargon","jarring","jasmine","jaundice","jaunt","java","jawed","jawless","jawline","jaws","jaybird","jaywalker","jazz","jeep","jeeringly","jellied","jelly","jersey","jester","jet","jiffy","jigsaw","jimmy","jingle","jingling","jinx","jitters","jittery","job","jockey","jockstrap","jogger","jogging","john","joining","jokester","jokingly","jolliness","jolly","jolt","jot","jovial","joyfully","joylessly","joyous","joyride","joystick","jubilance","jubilant","judge","judgingly","judicial","judiciary","judo","juggle","juggling","jugular","juice","juiciness","juicy","jujitsu","jukebox","july","jumble","jumbo","jump","junction","juncture","june","junior","juniper","junkie","junkman","junkyard","jurist","juror","jury","justice","justifier","justify","justly","justness","juvenile","kabob","kangaroo","karaoke","karate","karma","kebab","keenly","keenness","keep","keg","kelp","kennel","kept","kerchief","kerosene","kettle","kick","kiln","kilobyte","kilogram","kilometer","kilowatt","kilt","kimono","kindle","kindling","kindly","kindness","kindred","kinetic","kinfolk","king","kinship","kinsman","kinswoman","kissable","kisser","kissing","kitchen","kite","kitten","kitty","kiwi","kleenex","knapsack","knee","knelt","knickers","knoll","koala","kooky","kosher","krypton","kudos","kung","labored","laborer","laboring","laborious","labrador","ladder","ladies","ladle","ladybug","ladylike","lagged","lagging","lagoon","lair","lake","lance","landed","landfall","landfill","landing","landlady","landless","landline","landlord","landmark","landmass","landmine","landowner","landscape","landside","landslide","language","lankiness","lanky","lantern","lapdog","lapel","lapped","lapping","laptop","lard","large","lark","lash","lasso","last","latch","late","lather","latitude","latrine","latter","latticed","launch","launder","laundry","laurel","lavender","lavish","laxative","lazily","laziness","lazy","lecturer","left","legacy","legal","legend","legged","leggings","legible","legibly","legislate","lego","legroom","legume","legwarmer","legwork","lemon","lend","length","lens","lent","leotard","lesser","letdown","lethargic","lethargy","letter","lettuce","level","leverage","levers","levitate","levitator","liability","liable","liberty","librarian","library","licking","licorice","lid","life","lifter","lifting","liftoff","ligament","likely","likeness","likewise","liking","lilac","lilly","lily","limb","limeade","limelight","limes","limit","limping","limpness","line","lingo","linguini","linguist","lining","linked","linoleum","linseed","lint","lion","lip","liquefy","liqueur","liquid","lisp","list","litigate","litigator","litmus","litter","little","livable","lived","lively","liver","livestock","lividly","living","lizard","lubricant","lubricate","lucid","luckily","luckiness","luckless","lucrative","ludicrous","lugged","lukewarm","lullaby","lumber","luminance","luminous","lumpiness","lumping","lumpish","lunacy","lunar","lunchbox","luncheon","lunchroom","lunchtime","lung","lurch","lure","luridness","lurk","lushly","lushness","luster","lustfully","lustily","lustiness","lustrous","lusty","luxurious","luxury","lying","lyrically","lyricism","lyricist","lyrics","macarena","macaroni","macaw","mace","machine","machinist","magazine","magenta","maggot","magical","magician","magma","magnesium","magnetic","magnetism","magnetize","magnifier","magnify","magnitude","magnolia","mahogany","maimed","majestic","majesty","majorette","majority","makeover","maker","makeshift","making","malformed","malt","mama","mammal","mammary","mammogram","manager","managing","manatee","mandarin","mandate","mandatory","mandolin","manger","mangle","mango","mangy","manhandle","manhole","manhood","manhunt","manicotti","manicure","manifesto","manila","mankind","manlike","manliness","manly","manmade","manned","mannish","manor","manpower","mantis","mantra","manual","many","map","marathon","marauding","marbled","marbles","marbling","march","mardi","margarine","margarita","margin","marigold","marina","marine","marital","maritime","marlin","marmalade","maroon","married","marrow","marry","marshland","marshy","marsupial","marvelous","marxism","mascot","masculine","mashed","mashing","massager","masses","massive","mastiff","matador","matchbook","matchbox","matcher","matching","matchless","material","maternal","maternity","math","mating","matriarch","matrimony","matrix","matron","matted","matter","maturely","maturing","maturity","mauve","maverick","maximize","maximum","maybe","mayday","mayflower","moaner","moaning","mobile","mobility","mobilize","mobster","mocha","mocker","mockup","modified","modify","modular","modulator","module","moisten","moistness","moisture","molar","molasses","mold","molecular","molecule","molehill","mollusk","mom","monastery","monday","monetary","monetize","moneybags","moneyless","moneywise","mongoose","mongrel","monitor","monkhood","monogamy","monogram","monologue","monopoly","monorail","monotone","monotype","monoxide","monsieur","monsoon","monstrous","monthly","monument","moocher","moodiness","moody","mooing","moonbeam","mooned","moonlight","moonlike","moonlit","moonrise","moonscape","moonshine","moonstone","moonwalk","mop","morale","morality","morally","morbidity","morbidly","morphine","morphing","morse","mortality","mortally","mortician","mortified","mortify","mortuary","mosaic","mossy","most","mothball","mothproof","motion","motivate","motivator","motive","motocross","motor","motto","mountable","mountain","mounted","mounting","mourner","mournful","mouse","mousiness","moustache","mousy","mouth","movable","move","movie","moving","mower","mowing","much","muck","mud","mug","mulberry","mulch","mule","mulled","mullets","multiple","multiply","multitask","multitude","mumble","mumbling","mumbo","mummified","mummify","mummy","mumps","munchkin","mundane","municipal","muppet","mural","murkiness","murky","murmuring","muscular","museum","mushily","mushiness","mushroom","mushy","music","musket","muskiness","musky","mustang","mustard","muster","mustiness","musty","mutable","mutate","mutation","mute","mutilated","mutilator","mutiny","mutt","mutual","muzzle","myself","myspace","mystified","mystify","myth","nacho","nag","nail","name","naming","nanny","nanometer","nape","napkin","napped","napping","nappy","narrow","nastily","nastiness","national","native","nativity","natural","nature","naturist","nautical","navigate","navigator","navy","nearby","nearest","nearly","nearness","neatly","neatness","nebula","nebulizer","nectar","negate","negation","negative","neglector","negligee","negligent","negotiate","nemeses","nemesis","neon","nephew","nerd","nervous","nervy","nest","net","neurology","neuron","neurosis","neurotic","neuter","neutron","never","next","nibble","nickname","nicotine","niece","nifty","nimble","nimbly","nineteen","ninetieth","ninja","nintendo","ninth","nuclear","nuclei","nucleus","nugget","nullify","number","numbing","numbly","numbness","numeral","numerate","numerator","numeric","numerous","nuptials","nursery","nursing","nurture","nutcase","nutlike","nutmeg","nutrient","nutshell","nuttiness","nutty","nuzzle","nylon","oaf","oak","oasis","oat","obedience","obedient","obituary","object","obligate","obliged","oblivion","oblivious","oblong","obnoxious","oboe","obscure","obscurity","observant","observer","observing","obsessed","obsession","obsessive","obsolete","obstacle","obstinate","obstruct","obtain","obtrusive","obtuse","obvious","occultist","occupancy","occupant","occupier","occupy","ocean","ocelot","octagon","octane","october","octopus","ogle","oil","oink","ointment","okay","old","olive","olympics","omega","omen","ominous","omission","omit","omnivore","onboard","oncoming","ongoing","onion","online","onlooker","only","onscreen","onset","onshore","onslaught","onstage","onto","onward","onyx","oops","ooze","oozy","opacity","opal","open","operable","operate","operating","operation","operative","operator","opium","opossum","opponent","oppose","opposing","opposite","oppressed","oppressor","opt","opulently","osmosis","other","otter","ouch","ought","ounce","outage","outback","outbid","outboard","outbound","outbreak","outburst","outcast","outclass","outcome","outdated","outdoors","outer","outfield","outfit","outflank","outgoing","outgrow","outhouse","outing","outlast","outlet","outline","outlook","outlying","outmatch","outmost","outnumber","outplayed","outpost","outpour","output","outrage","outrank","outreach","outright","outscore","outsell","outshine","outshoot","outsider","outskirts","outsmart","outsource","outspoken","outtakes","outthink","outward","outweigh","outwit","oval","ovary","oven","overact","overall","overarch","overbid","overbill","overbite","overblown","overboard","overbook","overbuilt","overcast","overcoat","overcome","overcook","overcrowd","overdraft","overdrawn","overdress","overdrive","overdue","overeager","overeater","overexert","overfed","overfeed","overfill","overflow","overfull","overgrown","overhand","overhang","overhaul","overhead","overhear","overheat","overhung","overjoyed","overkill","overlabor","overlaid","overlap","overlay","overload","overlook","overlord","overlying","overnight","overpass","overpay","overplant","overplay","overpower","overprice","overrate","overreach","overreact","override","overripe","overrule","overrun","overshoot","overshot","oversight","oversized","oversleep","oversold","overspend","overstate","overstay","overstep","overstock","overstuff","oversweet","overtake","overthrow","overtime","overtly","overtone","overture","overturn","overuse","overvalue","overview","overwrite","owl","oxford","oxidant","oxidation","oxidize","oxidizing","oxygen","oxymoron","oyster","ozone","paced","pacemaker","pacific","pacifier","pacifism","pacifist","pacify","padded","padding","paddle","paddling","padlock","pagan","pager","paging","pajamas","palace","palatable","palm","palpable","palpitate","paltry","pampered","pamperer","pampers","pamphlet","panama","pancake","pancreas","panda","pandemic","pang","panhandle","panic","panning","panorama","panoramic","panther","pantomime","pantry","pants","pantyhose","paparazzi","papaya","paper","paprika","papyrus","parabola","parachute","parade","paradox","paragraph","parakeet","paralegal","paralyses","paralysis","paralyze","paramedic","parameter","paramount","parasail","parasite","parasitic","parcel","parched","parchment","pardon","parish","parka","parking","parkway","parlor","parmesan","parole","parrot","parsley","parsnip","partake","parted","parting","partition","partly","partner","partridge","party","passable","passably","passage","passcode","passenger","passerby","passing","passion","passive","passivism","passover","passport","password","pasta","pasted","pastel","pastime","pastor","pastrami","pasture","pasty","patchwork","patchy","paternal","paternity","path","patience","patient","patio","patriarch","patriot","patrol","patronage","patronize","pauper","pavement","paver","pavestone","pavilion","paving","pawing","payable","payback","paycheck","payday","payee","payer","paying","payment","payphone","payroll","pebble","pebbly","pecan","pectin","peculiar","peddling","pediatric","pedicure","pedigree","pedometer","pegboard","pelican","pellet","pelt","pelvis","penalize","penalty","pencil","pendant","pending","penholder","penknife","pennant","penniless","penny","penpal","pension","pentagon","pentagram","pep","perceive","percent","perch","percolate","perennial","perfected","perfectly","perfume","periscope","perish","perjurer","perjury","perkiness","perky","perm","peroxide","perpetual","perplexed","persecute","persevere","persuaded","persuader","pesky","peso","pessimism","pessimist","pester","pesticide","petal","petite","petition","petri","petroleum","petted","petticoat","pettiness","petty","petunia","phantom","phobia","phoenix","phonebook","phoney","phonics","phoniness","phony","phosphate","photo","phrase","phrasing","placard","placate","placidly","plank","planner","plant","plasma","plaster","plastic","plated","platform","plating","platinum","platonic","platter","platypus","plausible","plausibly","playable","playback","player","playful","playgroup","playhouse","playing","playlist","playmaker","playmate","playoff","playpen","playroom","playset","plaything","playtime","plaza","pleading","pleat","pledge","plentiful","plenty","plethora","plexiglas","pliable","plod","plop","plot","plow","ploy","pluck","plug","plunder","plunging","plural","plus","plutonium","plywood","poach","pod","poem","poet","pogo","pointed","pointer","pointing","pointless","pointy","poise","poison","poker","poking","polar","police","policy","polio","polish","politely","polka","polo","polyester","polygon","polygraph","polymer","poncho","pond","pony","popcorn","pope","poplar","popper","poppy","popsicle","populace","popular","populate","porcupine","pork","porous","porridge","portable","portal","portfolio","porthole","portion","portly","portside","poser","posh","posing","possible","possibly","possum","postage","postal","postbox","postcard","posted","poster","posting","postnasal","posture","postwar","pouch","pounce","pouncing","pound","pouring","pout","powdered","powdering","powdery","power","powwow","pox","praising","prance","prancing","pranker","prankish","prankster","prayer","praying","preacher","preaching","preachy","preamble","precinct","precise","precision","precook","precut","predator","predefine","predict","preface","prefix","preflight","preformed","pregame","pregnancy","pregnant","preheated","prelaunch","prelaw","prelude","premiere","premises","premium","prenatal","preoccupy","preorder","prepaid","prepay","preplan","preppy","preschool","prescribe","preseason","preset","preshow","president","presoak","press","presume","presuming","preteen","pretended","pretender","pretense","pretext","pretty","pretzel","prevail","prevalent","prevent","preview","previous","prewar","prewashed","prideful","pried","primal","primarily","primary","primate","primer","primp","princess","print","prior","prism","prison","prissy","pristine","privacy","private","privatize","prize","proactive","probable","probably","probation","probe","probing","probiotic","problem","procedure","process","proclaim","procreate","procurer","prodigal","prodigy","produce","product","profane","profanity","professed","professor","profile","profound","profusely","progeny","prognosis","program","progress","projector","prologue","prolonged","promenade","prominent","promoter","promotion","prompter","promptly","prone","prong","pronounce","pronto","proofing","proofread","proofs","propeller","properly","property","proponent","proposal","propose","props","prorate","protector","protegee","proton","prototype","protozoan","protract","protrude","proud","provable","proved","proven","provided","provider","providing","province","proving","provoke","provoking","provolone","prowess","prowler","prowling","proximity","proxy","prozac","prude","prudishly","prune","pruning","pry","psychic","public","publisher","pucker","pueblo","pug","pull","pulmonary","pulp","pulsate","pulse","pulverize","puma","pumice","pummel","punch","punctual","punctuate","punctured","pungent","punisher","punk","pupil","puppet","puppy","purchase","pureblood","purebred","purely","pureness","purgatory","purge","purging","purifier","purify","purist","puritan","purity","purple","purplish","purposely","purr","purse","pursuable","pursuant","pursuit","purveyor","pushcart","pushchair","pusher","pushiness","pushing","pushover","pushpin","pushup","pushy","putdown","putt","puzzle","puzzling","pyramid","pyromania","python","quack","quadrant","quail","quaintly","quake","quaking","qualified","qualifier","qualify","quality","qualm","quantum","quarrel","quarry","quartered","quarterly","quarters","quartet","quench","query","quicken","quickly","quickness","quicksand","quickstep","quiet","quill","quilt","quintet","quintuple","quirk","quit","quiver","quizzical","quotable","quotation","quote","rabid","race","racing","racism","rack","racoon","radar","radial","radiance","radiantly","radiated","radiation","radiator","radio","radish","raffle","raft","rage","ragged","raging","ragweed","raider","railcar","railing","railroad","railway","raisin","rake","raking","rally","ramble","rambling","ramp","ramrod","ranch","rancidity","random","ranged","ranger","ranging","ranked","ranking","ransack","ranting","rants","rare","rarity","rascal","rash","rasping","ravage","raven","ravine","raving","ravioli","ravishing","reabsorb","reach","reacquire","reaction","reactive","reactor","reaffirm","ream","reanalyze","reappear","reapply","reappoint","reapprove","rearrange","rearview","reason","reassign","reassure","reattach","reawake","rebalance","rebate","rebel","rebirth","reboot","reborn","rebound","rebuff","rebuild","rebuilt","reburial","rebuttal","recall","recant","recapture","recast","recede","recent","recess","recharger","recipient","recital","recite","reckless","reclaim","recliner","reclining","recluse","reclusive","recognize","recoil","recollect","recolor","reconcile","reconfirm","reconvene","recopy","record","recount","recoup","recovery","recreate","rectal","rectangle","rectified","rectify","recycled","recycler","recycling","reemerge","reenact","reenter","reentry","reexamine","referable","referee","reference","refill","refinance","refined","refinery","refining","refinish","reflected","reflector","reflex","reflux","refocus","refold","reforest","reformat","reformed","reformer","reformist","refract","refrain","refreeze","refresh","refried","refueling","refund","refurbish","refurnish","refusal","refuse","refusing","refutable","refute","regain","regalia","regally","reggae","regime","region","register","registrar","registry","regress","regretful","regroup","regular","regulate","regulator","rehab","reheat","rehire","rehydrate","reimburse","reissue","reiterate","rejoice","rejoicing","rejoin","rekindle","relapse","relapsing","relatable","related","relation","relative","relax","relay","relearn","release","relenting","reliable","reliably","reliance","reliant","relic","relieve","relieving","relight","relish","relive","reload","relocate","relock","reluctant","rely","remake","remark","remarry","rematch","remedial","remedy","remember","reminder","remindful","remission","remix","remnant","remodeler","remold","remorse","remote","removable","removal","removed","remover","removing","rename","renderer","rendering","rendition","renegade","renewable","renewably","renewal","renewed","renounce","renovate","renovator","rentable","rental","rented","renter","reoccupy","reoccur","reopen","reorder","repackage","repacking","repaint","repair","repave","repaying","repayment","repeal","repeated","repeater","repent","rephrase","replace","replay","replica","reply","reporter","repose","repossess","repost","repressed","reprimand","reprint","reprise","reproach","reprocess","reproduce","reprogram","reps","reptile","reptilian","repugnant","repulsion","repulsive","repurpose","reputable","reputably","request","require","requisite","reroute","rerun","resale","resample","rescuer","reseal","research","reselect","reseller","resemble","resend","resent","reset","reshape","reshoot","reshuffle","residence","residency","resident","residual","residue","resigned","resilient","resistant","resisting","resize","resolute","resolved","resonant","resonate","resort","resource","respect","resubmit","result","resume","resupply","resurface","resurrect","retail","retainer","retaining","retake","retaliate","retention","rethink","retinal","retired","retiree","retiring","retold","retool","retorted","retouch","retrace","retract","retrain","retread","retreat","retrial","retrieval","retriever","retry","return","retying","retype","reunion","reunite","reusable","reuse","reveal","reveler","revenge","revenue","reverb","revered","reverence","reverend","reversal","reverse","reversing","reversion","revert","revisable","revise","revision","revisit","revivable","revival","reviver","reviving","revocable","revoke","revolt","revolver","revolving","reward","rewash","rewind","rewire","reword","rework","rewrap","rewrite","rhyme","ribbon","ribcage","rice","riches","richly","richness","rickety","ricotta","riddance","ridden","ride","riding","rifling","rift","rigging","rigid","rigor","rimless","rimmed","rind","rink","rinse","rinsing","riot","ripcord","ripeness","ripening","ripping","ripple","rippling","riptide","rise","rising","risk","risotto","ritalin","ritzy","rival","riverbank","riverbed","riverboat","riverside","riveter","riveting","roamer","roaming","roast","robbing","robe","robin","robotics","robust","rockband","rocker","rocket","rockfish","rockiness","rocking","rocklike","rockslide","rockstar","rocky","rogue","roman","romp","rope","roping","roster","rosy","rotten","rotting","rotunda","roulette","rounding","roundish","roundness","roundup","roundworm","routine","routing","rover","roving","royal","rubbed","rubber","rubbing","rubble","rubdown","ruby","ruckus","rudder","rug","ruined","rule","rumble","rumbling","rummage","rumor","runaround","rundown","runner","running","runny","runt","runway","rupture","rural","ruse","rush","rust","rut","sabbath","sabotage","sacrament","sacred","sacrifice","sadden","saddlebag","saddled","saddling","sadly","sadness","safari","safeguard","safehouse","safely","safeness","saffron","saga","sage","sagging","saggy","said","saint","sake","salad","salami","salaried","salary","saline","salon","saloon","salsa","salt","salutary","salute","salvage","salvaging","salvation","same","sample","sampling","sanction","sanctity","sanctuary","sandal","sandbag","sandbank","sandbar","sandblast","sandbox","sanded","sandfish","sanding","sandlot","sandpaper","sandpit","sandstone","sandstorm","sandworm","sandy","sanitary","sanitizer","sank","santa","sapling","sappiness","sappy","sarcasm","sarcastic","sardine","sash","sasquatch","sassy","satchel","satiable","satin","satirical","satisfied","satisfy","saturate","saturday","sauciness","saucy","sauna","savage","savanna","saved","savings","savior","savor","saxophone","say","scabbed","scabby","scalded","scalding","scale","scaling","scallion","scallop","scalping","scam","scandal","scanner","scanning","scant","scapegoat","scarce","scarcity","scarecrow","scared","scarf","scarily","scariness","scarring","scary","scavenger","scenic","schedule","schematic","scheme","scheming","schilling","schnapps","scholar","science","scientist","scion","scoff","scolding","scone","scoop","scooter","scope","scorch","scorebook","scorecard","scored","scoreless","scorer","scoring","scorn","scorpion","scotch","scoundrel","scoured","scouring","scouting","scouts","scowling","scrabble","scraggly","scrambled","scrambler","scrap","scratch","scrawny","screen","scribble","scribe","scribing","scrimmage","script","scroll","scrooge","scrounger","scrubbed","scrubber","scruffy","scrunch","scrutiny","scuba","scuff","sculptor","sculpture","scurvy","scuttle","secluded","secluding","seclusion","second","secrecy","secret","sectional","sector","secular","securely","security","sedan","sedate","sedation","sedative","sediment","seduce","seducing","segment","seismic","seizing","seldom","selected","selection","selective","selector","self","seltzer","semantic","semester","semicolon","semifinal","seminar","semisoft","semisweet","senate","senator","send","senior","senorita","sensation","sensitive","sensitize","sensually","sensuous","sepia","september","septic","septum","sequel","sequence","sequester","series","sermon","serotonin","serpent","serrated","serve","service","serving","sesame","sessions","setback","setting","settle","settling","setup","sevenfold","seventeen","seventh","seventy","severity","shabby","shack","shaded","shadily","shadiness","shading","shadow","shady","shaft","shakable","shakily","shakiness","shaking","shaky","shale","shallot","shallow","shame","shampoo","shamrock","shank","shanty","shape","shaping","share","sharpener","sharper","sharpie","sharply","sharpness","shawl","sheath","shed","sheep","sheet","shelf","shell","shelter","shelve","shelving","sherry","shield","shifter","shifting","shiftless","shifty","shimmer","shimmy","shindig","shine","shingle","shininess","shining","shiny","ship","shirt","shivering","shock","shone","shoplift","shopper","shopping","shoptalk","shore","shortage","shortcake","shortcut","shorten","shorter","shorthand","shortlist","shortly","shortness","shorts","shortwave","shorty","shout","shove","showbiz","showcase","showdown","shower","showgirl","showing","showman","shown","showoff","showpiece","showplace","showroom","showy","shrank","shrapnel","shredder","shredding","shrewdly","shriek","shrill","shrimp","shrine","shrink","shrivel","shrouded","shrubbery","shrubs","shrug","shrunk","shucking","shudder","shuffle","shuffling","shun","shush","shut","shy","siamese","siberian","sibling","siding","sierra","siesta","sift","sighing","silenced","silencer","silent","silica","silicon","silk","silliness","silly","silo","silt","silver","similarly","simile","simmering","simple","simplify","simply","sincere","sincerity","singer","singing","single","singular","sinister","sinless","sinner","sinuous","sip","siren","sister","sitcom","sitter","sitting","situated","situation","sixfold","sixteen","sixth","sixties","sixtieth","sixtyfold","sizable","sizably","size","sizing","sizzle","sizzling","skater","skating","skedaddle","skeletal","skeleton","skeptic","sketch","skewed","skewer","skid","skied","skier","skies","skiing","skilled","skillet","skillful","skimmed","skimmer","skimming","skimpily","skincare","skinhead","skinless","skinning","skinny","skintight","skipper","skipping","skirmish","skirt","skittle","skydiver","skylight","skyline","skype","skyrocket","skyward","slab","slacked","slacker","slacking","slackness","slacks","slain","slam","slander","slang","slapping","slapstick","slashed","slashing","slate","slather","slaw","sled","sleek","sleep","sleet","sleeve","slept","sliceable","sliced","slicer","slicing","slick","slider","slideshow","sliding","slighted","slighting","slightly","slimness","slimy","slinging","slingshot","slinky","slip","slit","sliver","slobbery","slogan","sloped","sloping","sloppily","sloppy","slot","slouching","slouchy","sludge","slug","slum","slurp","slush","sly","small","smartly","smartness","smasher","smashing","smashup","smell","smelting","smile","smilingly","smirk","smite","smith","smitten","smock","smog","smoked","smokeless","smokiness","smoking","smoky","smolder","smooth","smother","smudge","smudgy","smuggler","smuggling","smugly","smugness","snack","snagged","snaking","snap","snare","snarl","snazzy","sneak","sneer","sneeze","sneezing","snide","sniff","snippet","snipping","snitch","snooper","snooze","snore","snoring","snorkel","snort","snout","snowbird","snowboard","snowbound","snowcap","snowdrift","snowdrop","snowfall","snowfield","snowflake","snowiness","snowless","snowman","snowplow","snowshoe","snowstorm","snowsuit","snowy","snub","snuff","snuggle","snugly","snugness","speak","spearfish","spearhead","spearman","spearmint","species","specimen","specked","speckled","specks","spectacle","spectator","spectrum","speculate","speech","speed","spellbind","speller","spelling","spendable","spender","spending","spent","spew","sphere","spherical","sphinx","spider","spied","spiffy","spill","spilt","spinach","spinal","spindle","spinner","spinning","spinout","spinster","spiny","spiral","spirited","spiritism","spirits","spiritual","splashed","splashing","splashy","splatter","spleen","splendid","splendor","splice","splicing","splinter","splotchy","splurge","spoilage","spoiled","spoiler","spoiling","spoils","spoken","spokesman","sponge","spongy","sponsor","spoof","spookily","spooky","spool","spoon","spore","sporting","sports","sporty","spotless","spotlight","spotted","spotter","spotting","spotty","spousal","spouse","spout","sprain","sprang","sprawl","spray","spree","sprig","spring","sprinkled","sprinkler","sprint","sprite","sprout","spruce","sprung","spry","spud","spur","sputter","spyglass","squabble","squad","squall","squander","squash","squatted","squatter","squatting","squeak","squealer","squealing","squeamish","squeegee","squeeze","squeezing","squid","squiggle","squiggly","squint","squire","squirt","squishier","squishy","stability","stabilize","stable","stack","stadium","staff","stage","staging","stagnant","stagnate","stainable","stained","staining","stainless","stalemate","staleness","stalling","stallion","stamina","stammer","stamp","stand","stank","staple","stapling","starboard","starch","stardom","stardust","starfish","stargazer","staring","stark","starless","starlet","starlight","starlit","starring","starry","starship","starter","starting","startle","startling","startup","starved","starving","stash","state","static","statistic","statue","stature","status","statute","statutory","staunch","stays","steadfast","steadier","steadily","steadying","steam","steed","steep","steerable","steering","steersman","stegosaur","stellar","stem","stench","stencil","step","stereo","sterile","sterility","sterilize","sterling","sternness","sternum","stew","stick","stiffen","stiffly","stiffness","stifle","stifling","stillness","stilt","stimulant","stimulate","stimuli","stimulus","stinger","stingily","stinging","stingray","stingy","stinking","stinky","stipend","stipulate","stir","stitch","stock","stoic","stoke","stole","stomp","stonewall","stoneware","stonework","stoning","stony","stood","stooge","stool","stoop","stoplight","stoppable","stoppage","stopped","stopper","stopping","stopwatch","storable","storage","storeroom","storewide","storm","stout","stove","stowaway","stowing","straddle","straggler","strained","strainer","straining","strangely","stranger","strangle","strategic","strategy","stratus","straw","stray","streak","stream","street","strength","strenuous","strep","stress","stretch","strewn","stricken","strict","stride","strife","strike","striking","strive","striving","strobe","strode","stroller","strongbox","strongly","strongman","struck","structure","strudel","struggle","strum","strung","strut","stubbed","stubble","stubbly","stubborn","stucco","stuck","student","studied","studio","study","stuffed","stuffing","stuffy","stumble","stumbling","stump","stung","stunned","stunner","stunning","stunt","stupor","sturdily","sturdy","styling","stylishly","stylist","stylized","stylus","suave","subarctic","subatomic","subdivide","subdued","subduing","subfloor","subgroup","subheader","subject","sublease","sublet","sublevel","sublime","submarine","submerge","submersed","submitter","subpanel","subpar","subplot","subprime","subscribe","subscript","subsector","subside","subsiding","subsidize","subsidy","subsoil","subsonic","substance","subsystem","subtext","subtitle","subtly","subtotal","subtract","subtype","suburb","subway","subwoofer","subzero","succulent","such","suction","sudden","sudoku","suds","sufferer","suffering","suffice","suffix","suffocate","suffrage","sugar","suggest","suing","suitable","suitably","suitcase","suitor","sulfate","sulfide","sulfite","sulfur","sulk","sullen","sulphate","sulphuric","sultry","superbowl","superglue","superhero","superior","superjet","superman","supermom","supernova","supervise","supper","supplier","supply","support","supremacy","supreme","surcharge","surely","sureness","surface","surfacing","surfboard","surfer","surgery","surgical","surging","surname","surpass","surplus","surprise","surreal","surrender","surrogate","surround","survey","survival","survive","surviving","survivor","sushi","suspect","suspend","suspense","sustained","sustainer","swab","swaddling","swagger","swampland","swan","swapping","swarm","sway","swear","sweat","sweep","swell","swept","swerve","swifter","swiftly","swiftness","swimmable","swimmer","swimming","swimsuit","swimwear","swinger","swinging","swipe","swirl","switch","swivel","swizzle","swooned","swoop","swoosh","swore","sworn","swung","sycamore","sympathy","symphonic","symphony","symptom","synapse","syndrome","synergy","synopses","synopsis","synthesis","synthetic","syrup","system","t-shirt","tabasco","tabby","tableful","tables","tablet","tableware","tabloid","tackiness","tacking","tackle","tackling","tacky","taco","tactful","tactical","tactics","tactile","tactless","tadpole","taekwondo","tag","tainted","take","taking","talcum","talisman","tall","talon","tamale","tameness","tamer","tamper","tank","tanned","tannery","tanning","tantrum","tapeless","tapered","tapering","tapestry","tapioca","tapping","taps","tarantula","target","tarmac","tarnish","tarot","tartar","tartly","tartness","task","tassel","taste","tastiness","tasting","tasty","tattered","tattle","tattling","tattoo","taunt","tavern","thank","that","thaw","theater","theatrics","thee","theft","theme","theology","theorize","thermal","thermos","thesaurus","these","thesis","thespian","thicken","thicket","thickness","thieving","thievish","thigh","thimble","thing","think","thinly","thinner","thinness","thinning","thirstily","thirsting","thirsty","thirteen","thirty","thong","thorn","those","thousand","thrash","thread","threaten","threefold","thrift","thrill","thrive","thriving","throat","throbbing","throng","throttle","throwaway","throwback","thrower","throwing","thud","thumb","thumping","thursday","thus","thwarting","thyself","tiara","tibia","tidal","tidbit","tidiness","tidings","tidy","tiger","tighten","tightly","tightness","tightrope","tightwad","tigress","tile","tiling","till","tilt","timid","timing","timothy","tinderbox","tinfoil","tingle","tingling","tingly","tinker","tinkling","tinsel","tinsmith","tint","tinwork","tiny","tipoff","tipped","tipper","tipping","tiptoeing","tiptop","tiring","tissue","trace","tracing","track","traction","tractor","trade","trading","tradition","traffic","tragedy","trailing","trailside","train","traitor","trance","tranquil","transfer","transform","translate","transpire","transport","transpose","trapdoor","trapeze","trapezoid","trapped","trapper","trapping","traps","trash","travel","traverse","travesty","tray","treachery","treading","treadmill","treason","treat","treble","tree","trekker","tremble","trembling","tremor","trench","trend","trespass","triage","trial","triangle","tribesman","tribunal","tribune","tributary","tribute","triceps","trickery","trickily","tricking","trickle","trickster","tricky","tricolor","tricycle","trident","tried","trifle","trifocals","trillion","trilogy","trimester","trimmer","trimming","trimness","trinity","trio","tripod","tripping","triumph","trivial","trodden","trolling","trombone","trophy","tropical","tropics","trouble","troubling","trough","trousers","trout","trowel","truce","truck","truffle","trump","trunks","trustable","trustee","trustful","trusting","trustless","truth","try","tubby","tubeless","tubular","tucking","tuesday","tug","tuition","tulip","tumble","tumbling","tummy","turban","turbine","turbofan","turbojet","turbulent","turf","turkey","turmoil","turret","turtle","tusk","tutor","tutu","tux","tweak","tweed","tweet","tweezers","twelve","twentieth","twenty","twerp","twice","twiddle","twiddling","twig","twilight","twine","twins","twirl","twistable","twisted","twister","twisting","twisty","twitch","twitter","tycoon","tying","tyke","udder","ultimate","ultimatum","ultra","umbilical","umbrella","umpire","unabashed","unable","unadorned","unadvised","unafraid","unaired","unaligned","unaltered","unarmored","unashamed","unaudited","unawake","unaware","unbaked","unbalance","unbeaten","unbend","unbent","unbiased","unbitten","unblended","unblessed","unblock","unbolted","unbounded","unboxed","unbraided","unbridle","unbroken","unbuckled","unbundle","unburned","unbutton","uncanny","uncapped","uncaring","uncertain","unchain","unchanged","uncharted","uncheck","uncivil","unclad","unclaimed","unclamped","unclasp","uncle","unclip","uncloak","unclog","unclothed","uncoated","uncoiled","uncolored","uncombed","uncommon","uncooked","uncork","uncorrupt","uncounted","uncouple","uncouth","uncover","uncross","uncrown","uncrushed","uncured","uncurious","uncurled","uncut","undamaged","undated","undaunted","undead","undecided","undefined","underage","underarm","undercoat","undercook","undercut","underdog","underdone","underfed","underfeed","underfoot","undergo","undergrad","underhand","underline","underling","undermine","undermost","underpaid","underpass","underpay","underrate","undertake","undertone","undertook","undertow","underuse","underwear","underwent","underwire","undesired","undiluted","undivided","undocked","undoing","undone","undrafted","undress","undrilled","undusted","undying","unearned","unearth","unease","uneasily","uneasy","uneatable","uneaten","unedited","unelected","unending","unengaged","unenvied","unequal","unethical","uneven","unexpired","unexposed","unfailing","unfair","unfasten","unfazed","unfeeling","unfiled","unfilled","unfitted","unfitting","unfixable","unfixed","unflawed","unfocused","unfold","unfounded","unframed","unfreeze","unfrosted","unfrozen","unfunded","unglazed","ungloved","unglue","ungodly","ungraded","ungreased","unguarded","unguided","unhappily","unhappy","unharmed","unhealthy","unheard","unhearing","unheated","unhelpful","unhidden","unhinge","unhitched","unholy","unhook","unicorn","unicycle","unified","unifier","uniformed","uniformly","unify","unimpeded","uninjured","uninstall","uninsured","uninvited","union","uniquely","unisexual","unison","unissued","unit","universal","universe","unjustly","unkempt","unkind","unknotted","unknowing","unknown","unlaced","unlatch","unlawful","unleaded","unlearned","unleash","unless","unleveled","unlighted","unlikable","unlimited","unlined","unlinked","unlisted","unlit","unlivable","unloaded","unloader","unlocked","unlocking","unlovable","unloved","unlovely","unloving","unluckily","unlucky","unmade","unmanaged","unmanned","unmapped","unmarked","unmasked","unmasking","unmatched","unmindful","unmixable","unmixed","unmolded","unmoral","unmovable","unmoved","unmoving","unnamable","unnamed","unnatural","unneeded","unnerve","unnerving","unnoticed","unopened","unopposed","unpack","unpadded","unpaid","unpainted","unpaired","unpaved","unpeeled","unpicked","unpiloted","unpinned","unplanned","unplanted","unpleased","unpledged","unplowed","unplug","unpopular","unproven","unquote","unranked","unrated","unraveled","unreached","unread","unreal","unreeling","unrefined","unrelated","unrented","unrest","unretired","unrevised","unrigged","unripe","unrivaled","unroasted","unrobed","unroll","unruffled","unruly","unrushed","unsaddle","unsafe","unsaid","unsalted","unsaved","unsavory","unscathed","unscented","unscrew","unsealed","unseated","unsecured","unseeing","unseemly","unseen","unselect","unselfish","unsent","unsettled","unshackle","unshaken","unshaved","unshaven","unsheathe","unshipped","unsightly","unsigned","unskilled","unsliced","unsmooth","unsnap","unsocial","unsoiled","unsold","unsolved","unsorted","unspoiled","unspoken","unstable","unstaffed","unstamped","unsteady","unsterile","unstirred","unstitch","unstopped","unstuck","unstuffed","unstylish","unsubtle","unsubtly","unsuited","unsure","unsworn","untagged","untainted","untaken","untamed","untangled","untapped","untaxed","unthawed","unthread","untidy","untie","until","untimed","untimely","untitled","untoasted","untold","untouched","untracked","untrained","untreated","untried","untrimmed","untrue","untruth","unturned","untwist","untying","unusable","unused","unusual","unvalued","unvaried","unvarying","unveiled","unveiling","unvented","unviable","unvisited","unvocal","unwanted","unwarlike","unwary","unwashed","unwatched","unweave","unwed","unwelcome","unwell","unwieldy","unwilling","unwind","unwired","unwitting","unwomanly","unworldly","unworn","unworried","unworthy","unwound","unwoven","unwrapped","unwritten","unzip","upbeat","upchuck","upcoming","upcountry","update","upfront","upgrade","upheaval","upheld","uphill","uphold","uplifted","uplifting","upload","upon","upper","upright","uprising","upriver","uproar","uproot","upscale","upside","upstage","upstairs","upstart","upstate","upstream","upstroke","upswing","uptake","uptight","uptown","upturned","upward","upwind","uranium","urban","urchin","urethane","urgency","urgent","urging","urologist","urology","usable","usage","useable","used","uselessly","user","usher","usual","utensil","utility","utilize","utmost","utopia","utter","vacancy","vacant","vacate","vacation","vagabond","vagrancy","vagrantly","vaguely","vagueness","valiant","valid","valium","valley","valuables","value","vanilla","vanish","vanity","vanquish","vantage","vaporizer","variable","variably","varied","variety","various","varmint","varnish","varsity","varying","vascular","vaseline","vastly","vastness","veal","vegan","veggie","vehicular","velcro","velocity","velvet","vendetta","vending","vendor","veneering","vengeful","venomous","ventricle","venture","venue","venus","verbalize","verbally","verbose","verdict","verify","verse","version","versus","vertebrae","vertical","vertigo","very","vessel","vest","veteran","veto","vexingly","viability","viable","vibes","vice","vicinity","victory","video","viewable","viewer","viewing","viewless","viewpoint","vigorous","village","villain","vindicate","vineyard","vintage","violate","violation","violator","violet","violin","viper","viral","virtual","virtuous","virus","visa","viscosity","viscous","viselike","visible","visibly","vision","visiting","visitor","visor","vista","vitality","vitalize","vitally","vitamins","vivacious","vividly","vividness","vixen","vocalist","vocalize","vocally","vocation","voice","voicing","void","volatile","volley","voltage","volumes","voter","voting","voucher","vowed","vowel","voyage","wackiness","wad","wafer","waffle","waged","wager","wages","waggle","wagon","wake","waking","walk","walmart","walnut","walrus","waltz","wand","wannabe","wanted","wanting","wasabi","washable","washbasin","washboard","washbowl","washcloth","washday","washed","washer","washhouse","washing","washout","washroom","washstand","washtub","wasp","wasting","watch","water","waviness","waving","wavy","whacking","whacky","wham","wharf","wheat","whenever","whiff","whimsical","whinny","whiny","whisking","whoever","whole","whomever","whoopee","whooping","whoops","why","wick","widely","widen","widget","widow","width","wieldable","wielder","wife","wifi","wikipedia","wildcard","wildcat","wilder","wildfire","wildfowl","wildland","wildlife","wildly","wildness","willed","willfully","willing","willow","willpower","wilt","wimp","wince","wincing","wind","wing","winking","winner","winnings","winter","wipe","wired","wireless","wiring","wiry","wisdom","wise","wish","wisplike","wispy","wistful","wizard","wobble","wobbling","wobbly","wok","wolf","wolverine","womanhood","womankind","womanless","womanlike","womanly","womb","woof","wooing","wool","woozy","word","work","worried","worrier","worrisome","worry","worsening","worshiper","worst","wound","woven","wow","wrangle","wrath","wreath","wreckage","wrecker","wrecking","wrench","wriggle","wriggly","wrinkle","wrinkly","wrist","writing","written","wrongdoer","wronged","wrongful","wrongly","wrongness","wrought","xbox","xerox","yahoo","yam","yanking","yapping","yard","yarn","yeah","yearbook","yearling","yearly","yearning","yeast","yelling","yelp","yen","yesterday","yiddish","yield","yin","yippee","yo-yo","yodel","yoga","yogurt","yonder","yoyo","yummy","zap","zealous","zebra","zen","zeppelin","zero","zestfully","zesty","zigzagged","zipfile","zipping","zippy","zips","zit","zodiac","zombie","zone","zoning","zookeeper","zoologist","zoology","zoom"];

  function generatePassword() {
    if (genMode() === "passphrase") {
      const count = passWords();
      const randArr = new Uint32Array(count * 2); // extra for digits
      crypto.getRandomValues(randArr);
      let words = [];
      for (let i = 0; i < count; i++) {
        let w = EFF_WORDS[randArr[i] % EFF_WORDS.length];
        if (passCap()) w = w.charAt(0).toUpperCase() + w.slice(1);
        if (passNum()) w += (randArr[count + i] % 10);
        words.push(w);
      }
      setGenResult(words.join(passSep()));
    } else {
      setGenResult(generateSecurePassword(genLen(), genUpper(), genNums(), genSyms()));
    }
  }

  return (
    <Show when={showGenerator()}>
      <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-[100]" onClick={() => setShowGenerator(false)}>
        <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[480px] max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
          <div class="p-6">
            <div class="flex items-center justify-between mb-5">
              <h3 class="text-lg font-bold text-[var(--color-text)]">Password Generator</h3>
              <button onClick={() => setShowGenerator(false)} class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
              </button>
            </div>

            {/* Mode tabs */}
            <div class="flex gap-2 mb-5">
              <button onClick={() => setGenMode("password")} class={`flex-1 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${genMode() === "password" ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]" : "bg-[var(--color-sidebar)] text-[var(--color-muted)]"}`}>Password</button>
              <button onClick={() => setGenMode("passphrase")} class={`flex-1 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${genMode() === "passphrase" ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]" : "bg-[var(--color-sidebar)] text-[var(--color-muted)]"}`}>Passphrase</button>
            </div>

            <Show when={genMode() === "password"}>
              <div class="flex items-center justify-between text-xs text-[var(--color-text)] mb-3">
                <span>Length: <strong class="text-[var(--color-primary)] text-sm">{genLen()}</strong></span>
                <input type="range" min="4" max="128" value={genLen()} onInput={e => { setGenLen(parseInt(e.target.value)); }} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
              </div>
              <div class="grid grid-cols-3 gap-2 mb-4">
                <button onClick={() => setGenUpper(!genUpper())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genUpper() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>A-Z</button>
                <button onClick={() => setGenNums(!genNums())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genNums() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>0-9</button>
                <button onClick={() => setGenSyms(!genSyms())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genSyms() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>!@#</button>
              </div>
            </Show>

            <Show when={genMode() === "passphrase"}>
              <div class="flex items-center justify-between text-xs text-[var(--color-text)] mb-3">
                <span>Words: <strong class="text-[var(--color-primary)] text-sm">{passWords()}</strong></span>
                <input type="range" min="3" max="10" value={passWords()} onInput={e => setPassWords(parseInt(e.target.value))} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
              </div>
              <div class="grid grid-cols-3 gap-2 mb-4">
                <select value={passSep()} onChange={e => setPassSep(e.target.value)} class="px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer">
                  <option value="-">Dash (-)</option>
                  <option value=" ">Space</option>
                  <option value=".">Dot (.)</option>
                  <option value="_">Underscore (_)</option>
                </select>
                <button onClick={() => setPassCap(!passCap())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${passCap() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>Capitalize</button>
                <button onClick={() => setPassNum(!passNum())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${passNum() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>+ Number</button>
              </div>
            </Show>

            <button onClick={generatePassword} class="w-full py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-bold text-sm transition-all cursor-pointer mb-4">Generate</button>

            {/* Result */}
            <Show when={genResult()}>
              <div class="p-3 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] flex items-center justify-between">
                <code class="text-sm text-[var(--color-text)] font-mono break-all flex-1 select-all">{genResult()}</code>
                <button onClick={() => navigator.clipboard.writeText(genResult())} class="ml-3 p-2 text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer shrink-0" title="Copy">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
                </button>
              </div>
            </Show>
          </div>
        </div>
      </div>
    </Show>
  );
}

function SettingsModal() {
  const { showSettingsModal, setShowSettingsModal, theme, setTheme, deviceFleet, selfDeviceId, revokeWarning, setRevokeWarning } = useApp();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();

  const [activeTab, setActiveTab] = createSignal("general"); // "general" or "data"
  
  // Auto-lock state
  const [lockMinutes, setLockMinutes] = createSignal(15);
  const [saved, setSaved] = createSignal(false);

  // Biometric state
  const [biometricEnabled, setBiometricEnabled] = createSignal(false);
  const [biometricAvailable, setBiometricAvailable] = createSignal(false);

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
    if (showSettingsModal()) {
      loadSettings();
      setImportSource("");
    }
  });

  async function loadSettings() {
    try {
      // Load auto lock
      const data = JSON.parse(await daemon("settings.get"));
      if (data.auto_lock_minutes) setLockMinutes(data.auto_lock_minutes);

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

  async function toggleBiometric() {
    try {
      if (biometricEnabled()) {
        await daemon("vault.biometric_disable");
        setBiometricEnabled(false);
      } else {
        const password = prompt("Enter master password to enable Quick Unlock:");
        if (password) {
          await daemon("vault.biometric_enable", JSON.stringify({ password }));
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
        const payload = JSON.stringify({ format, data });
        const resp = await daemon("vault.import", payload);
        const result = JSON.parse(resp);
        setMessage(`Imported ${result.imported || 0} entries` + (result.skipped ? `, skipped ${result.skipped}` : ""));
        setImportSource("");
        await refreshCiphers();
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
      const resp = await daemon("vault.export", JSON.stringify({ format }));
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
    <Show when={showSettingsModal()}>
      <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-[100]" onClick={() => setShowSettingsModal(false)}>
        <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[500px] max-h-[90vh] flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
          {/* Header */}
          <div class="p-6 pb-4 border-b border-[var(--color-border)] flex items-center justify-between shrink-0">
            <h3 class="text-lg font-bold text-[var(--color-text)]">App Settings</h3>
            <button onClick={() => setShowSettingsModal(false)} class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
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
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
                    <span class="text-xs font-bold">Dark Mode</span>
                  </button>
                  <button
                    onClick={() => setTheme("light")}
                    class={`flex items-center justify-center gap-2 p-3 rounded-xl border transition-all cursor-pointer ${theme() === "light" ? "bg-[var(--color-sidebar)] text-[var(--color-primary)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)] hover:border-[var(--color-text)]"}`}
                  >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m12.728 12.728l.707.707M12 8a4 4 0 100 8 4 4 0 000-8z"/></svg>
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
                    <svg class="w-4 h-4 text-[var(--color-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                    JSON
                  </button>
                  <button
                    onClick={() => doExport("bw-csv")}
                    disabled={exporting()}
                    class="flex items-center justify-center gap-2 p-3 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer disabled:opacity-50"
                  >
                    <svg class="w-4 h-4 text-[var(--color-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
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
  );
}

function AutoLockButton() {
  const [showSettings, setShowSettings] = createSignal(false);
  const [lockMinutes, setLockMinutes] = createSignal(15);
  const [saved, setSaved] = createSignal(false);

  async function saveAutoLock() {
    try {
      await daemon("settings.set", JSON.stringify({ auto_lock_minutes: lockMinutes() }));
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      // Non-critical
    }
  }

  async function loadSetting() {
    try {
      const data = JSON.parse(await daemon("settings.get"));
      if (data.auto_lock_minutes) setLockMinutes(data.auto_lock_minutes);
    } catch (e) {}
  }

  return (
    <div class="relative">
      <button
        onClick={() => { const next = !showSettings(); setShowSettings(next); if (next) loadSetting(); }}
        title="Auto-lock settings"
        class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
      >
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      </button>
      <Show when={showSettings()}>
        <div class="absolute bottom-full right-0 mb-2 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl p-4 w-56 z-50">
          <div class="text-xs font-bold text-[var(--color-text)] mb-3">Auto-lock timeout</div>
          <div class="flex items-center gap-2 mb-3">
            <input
              type="number"
              min="1"
              max="120"
              value={lockMinutes()}
              onInput={e => setLockMinutes(parseInt(e.target.value) || 15)}
              class="w-20 px-3 py-2 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] text-center"
            />
            <span class="text-xs text-[var(--color-muted)]">minutes</span>
          </div>
          <button
            onClick={saveAutoLock}
            class="w-full py-1.5 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer"
          >
            {saved() ? "Saved" : "Save"}
          </button>
          <div class="text-[10px] text-[var(--color-muted)] mt-2">Vault locks after inactivity</div>

          {/* Biometric Unlock */}
          <div class="border-t border-[var(--color-border)] mt-3 pt-3">
            <div class="flex items-center justify-between">
              <div class="text-xs font-bold text-[var(--color-text)]">Quick Unlock</div>
              <button
                onClick={async () => {
                  try {
                    const status = JSON.parse(await daemon("vault.biometric_status"));
                    if (status.enabled) {
                      await daemon("vault.biometric_disable");
                    } else {
                      const password = prompt("Enter master password to enable Quick Unlock:");
                      if (password) {
                        await daemon("vault.biometric_enable", JSON.stringify({ password }));
                      }
                    }
                    loadSetting();
                  } catch (e) { alert(e.message); }
                }}
                class="p-1.5 rounded-lg transition-colors cursor-pointer text-[var(--color-muted)] hover:text-[var(--color-primary)]"
                title="Store unlock secret in OS keychain (biometric protected)"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0-1.1.9-2 2-2s2 .9 2 2-.9 2-2 2-2-.9-2-2zm-6 6c0-2.21 3.58-4 8-4s8 1.79 8 4" /></svg>
              </button>
            </div>
            <div class="text-[10px] text-[var(--color-muted)] mt-1">Unlock with biometric or device PIN</div>
          </div>
        </div>
      </Show>
    </div>
  );
}

function ImportExportButton() {
  const [showMenu, setShowMenu] = createSignal(false);
  const [importing, setImporting] = createSignal(false);
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
        const payload = JSON.stringify({ format, data });
        const resp = await daemon("vault.import", payload);
        const result = JSON.parse(resp);
        setMessage(`Imported ${result.imported || 0} entries` + (result.skipped ? `, skipped ${result.skipped}` : ""));
      } catch (e) {
        setMessage("Import failed: " + sanitizeError(e, null));
      }
      setImporting(false);
      setShowMenu(false);
    };
    input.click();
  }

  async function doExport(format) {
    setExporting(true);
    setMessage(null);
    try {
      const resp = await daemon("vault.export", format);
      const ext = format === "bw-csv" ? "csv" : "json";
      const blob = new Blob([resp], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `idtty-export.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      setMessage("Export complete");
    } catch (e) {
      setMessage("Export failed: " + sanitizeError(e, null));
    }
    setExporting(false);
    setShowMenu(false);
  }

  return (
    <div class="relative">
      <button
        onClick={() => setShowMenu(!showMenu())}
        title="Import / Export"
        class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
      >
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" /></svg>
      </button>
      <Show when={showMenu()}>
        <div class="absolute bottom-full right-0 mb-2 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl p-4 w-64 z-50">
          <div class="text-xs font-bold text-[var(--color-text)] mb-2">Import from</div>
          <div class="space-y-1 mb-3">
            <For each={formats}>
              {(f) => (
                <button
                  onClick={() => doImport(f.id)}
                  disabled={importing()}
                  class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer disabled:opacity-50"
                >
                  {f.label}
                </button>
              )}
            </For>
          </div>
          <div class="border-t border-[var(--color-border)] pt-2">
            <div class="text-xs font-bold text-[var(--color-text)] mb-2">Export as</div>
            <button
              onClick={() => doExport("bw-json")}
              disabled={exporting()}
              class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer disabled:opacity-50"
            >
              JSON
            </button>
            <button
              onClick={() => doExport("bw-csv")}
              disabled={exporting()}
              class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer disabled:opacity-50"
            >
              CSV
            </button>
          </div>
          <Show when={message()}>
            <div class="mt-2 text-[10px] text-[var(--color-primary)] font-bold">{message()}</div>
          </Show>
        </div>
      </Show>
    </div>
  );
}

function DeleteConfirmModal() {
  const { viewCipher, setShowDeleteConfirm, showDeleteConfirm, selectedCategory } = useApp();
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
          
          <h3 class="text-lg font-bold text-[var(--color-text)]">
            {selectedCategory() === "Trash" ? "Permanently Delete?" : "Delete Entry?"}
          </h3>
          <p class="text-xs text-[var(--color-muted)] mt-2 leading-relaxed px-2">
            <Show when={selectedCategory() === "Trash"} fallback={
              <span>Are you sure you want to delete <strong class="text-[var(--color-text)] font-semibold select-all">{viewCipher()?.name}</strong>? It will be moved to the Trash.</span>
            }>
              <span>Are you sure you want to permanently delete <strong class="text-[var(--color-text)] font-semibold select-all">{viewCipher()?.name}</strong>? This action is irreversible.</span>
            </Show>
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
              {selectedCategory() === "Trash" ? t("entry.deletePermanently") : t("entry.delete")}
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

          {/* Quick Unlock (Biometric) */}
          <Show when={app.biometricAvailable()}>
            <button
              type="button"
              onClick={async () => {
                try {
                  await daemon("vault.biometric_unlock");
                  // Daemon unlocked the vault internally. Refresh UI.
                  app.setStatus("unlocked");
                  app.setError(null);
                } catch (e) { /* Biometric failed or cancelled */ }
              }}
              class="w-full mt-2 py-3 rounded-xl border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] font-semibold transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0-1.1.9-2 2-2s2 .9 2 2-.9 2-2 2-2-.9-2-2zm-6 6c0-2.21 3.58-4 8-4s8 1.79 8 4" /></svg>
              Quick Unlock
            </button>
          </Show>
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
  const cipherType = () => props.cipher.type || props.cipher._meta?.type || "login";
  const isFav = () => props.cipher.favorite || props.cipher._meta?.favorite || false;

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
          <div class="flex items-center gap-1.5">
            <span class={`text-sm font-semibold truncate ${isSelected() ? "text-[var(--color-primary-text)]" : "text-[var(--color-text)]"}`}>
              {props.cipher.name || "Untitled"}
            </span>
            {isFav() && (
              <svg class={`w-3.5 h-3.5 shrink-0 ${isSelected() ? "text-yellow-300" : "text-yellow-500"}`} fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
              </svg>
            )}
            {(props.cipher.reprompt || props.cipher._meta?.reprompt) && (
              <svg class="w-3.5 h-3.5 shrink-0 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            )}
          </div>
          <div class={`text-xs truncate mt-0.5 ${isSelected() ? "text-[var(--color-primary-text)]/75" : "text-[var(--color-muted)]"}`}>
            {props.cipher.username || (cipherType() === "login" ? "No username" : cipherType() === "secureNote" ? "Secure note" : cipherType())}
          </div>
        </div>
      </div>
      
      {/* Quick Actions */}
      <div class="flex items-center gap-1.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity ml-2">
        <Show when={props.cipher.uris?.[0]}>
          <a
            href={(() => { const u = uriStr(props.cipher.uris[0]); return u.startsWith("http") ? u : `https://${u}`; })()}
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
  const { viewCipher, setViewCipher, setActivePane, setNewCipher, setShowDeleteConfirm, setShowReprompt, setRepromptCallback, selectedCategory } = useApp();
  const { restoreCipher, archiveCipher, unarchiveCipher } = useActions();
  const { t } = useI18n();

  const [revealPass, setRevealPass] = createSignal(false);
  const [totpCode, setTotpCode] = createSignal(null); // { code, period_seconds, expires_at }
  const [attachLoading, setAttachLoading] = createSignal(false);
  const [totpCopied, setTotpCopied] = createSignal(false);

  // TOTP code auto-refresh timer (boundary-aligned)
  createEffect(() => {
    const cipher = viewCipher();
    if (!cipher) return;
    const totpUri = cipher.kind?.login?.totp_uri || cipher.totp_uri;
    if (!totpUri || !cipher.id) {
      setTotpCode(null);
      return;
    }
    let active = true;
    let timer = null;
    const fetchCode = async () => {
      if (!active) return;
      try {
        const data = JSON.parse(await daemon("cipher.totp_code", cipher.id));
        if (active) {
          setTotpCode(data);
          // Schedule next fetch just after window boundary
          if (data.expires_at) {
            const msLeft = data.expires_at * 1000 - Date.now();
            const delay = Math.max(200, msLeft + 200);
            timer = setTimeout(fetchCode, delay);
          } else {
            timer = setTimeout(fetchCode, 5000);
          }
        }
      } catch (e) {
        setTotpCode(null);
      }
    };
    fetchCode();
    onCleanup(() => { active = false; if (timer) clearTimeout(timer); });
  });

  function startEdit() {
    const c = viewCipher();
    if (!c) return;
    const kind = c.kind || {};
    const loginData = kind.login || kind.Login || {};
    const cardData = kind.card || kind.Card || {};
    const idData = kind.identity || kind.Identity || {};
    const cipherType = c.type || "login";
    setNewCipher({
      name: c.name || "",
      cipherType,
      username: loginData.username || idData.username || "",
      password: loginData.password || "",
      uris: (loginData.uris || c.uris || []).map(u => typeof u === "string" ? { uri: u, match_strategy: null } : u),
      notes: c.notes || "",
      favorite: c.favorite || false,
      folder_id: c.folder_id || null,
      custom_fields: c.custom_fields || [],
      totp_uri: loginData.totp_uri || "",
      // Card fields
      cardholder: cardData.cardholder_name || "",
      cardNumber: cardData.number || "",
      cardBrand: cardData.brand || "",
      expMonth: cardData.exp_month || "",
      expYear: cardData.exp_year || "",
      cvv: cardData.code || "",
      // Identity fields
      idTitle: idData.title || "",
      firstName: idData.first_name || "",
      middleName: idData.middle_name || "",
      lastName: idData.last_name || "",
      company: idData.company || "",
      email: idData.email || "",
      phone: idData.phone || "",
      address1: idData.address1 || "",
      address2: idData.address2 || "",
      address3: idData.address3 || "",
      city: idData.city || "",
      state: idData.state || "",
      postalCode: idData.postal_code || "",
      country: idData.country || "",
      ssn: idData.ssn || "",
      passportNumber: idData.passport_number || "",
      licenseNumber: idData.license_number || "",
      // SSH Key fields
      publicKey: (kind.sshKey || kind.SshKey || {}).public_key || "",
      privateKey: (kind.sshKey || kind.SshKey || {}).private_key || "",
      fingerprint: (kind.sshKey || kind.SshKey || {}).key_fingerprint || "",
      // Bank Account fields
      bankName: c.bank_name || "",
      nameOnAccount: c.name_on_account || "",
      accountType: c.account_type || "",
      accountNumber: c.account_number || "",
      routingNumber: c.routing_number || "",
      branchNumber: c.branch_number || "",
      bankPin: c.pin || "",
      swiftCode: c.swift_code || "",
      iban: c.iban || "",
      bankPhone: c.bank_contact_phone || "",
      // Driver License fields
      dlFirstName: c.first_name || "",
      dlMiddleName: c.middle_name || "",
      dlLastName: c.last_name || "",
      dlDob: c.date_of_birth || "",
      dlNumber: c.license_number || "",
      dlCountry: c.issuing_country || "",
      dlState: c.issuing_state || "",
      dlIssueDate: c.issue_date || "",
      dlExpDate: c.expiration_date || "",
      dlAuthority: c.issuing_authority || "",
      dlClass: c.license_class || "",
      // Passport fields
      ppSurname: c.surname || "",
      ppGivenName: c.given_name || "",
      ppDob: c.date_of_birth || "",
      ppSex: c.sex || "",
      ppBirthPlace: c.birth_place || "",
      ppNationality: c.nationality || "",
      ppCountry: c.issuing_country || "",
      ppNumber: c.passport_number || "",
      ppType: c.passport_type || "",
      ppNationalId: c.national_identification_number || "",
      ppAuthority: c.issuing_authority || "",
      ppIssueDate: c.issue_date || "",
      ppExpDate: c.expiration_date || "",
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
              {viewCipher()?.type === "card" ? "Card" : viewCipher()?.type === "identity" ? "Identity" : viewCipher()?.type === "secureNote" ? "Secure Note" : viewCipher()?.type === "sshKey" ? "SSH Key" : viewCipher()?.type === "bankAccount" ? "Bank Account" : viewCipher()?.type === "driversLicense" ? "Driver License" : viewCipher()?.type === "passport" ? "Passport & ID" : "Login"} Item
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

        {/* Login credentials */}
        <Show when={viewCipher()?.type === "login" || (!viewCipher()?.type && viewCipher()?.username)}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Login credentials</h4>
            <CopyableField label={t("entry.user")} value={viewCipher()?.username || viewCipher()?.kind?.login?.username} />
            <CopyableField
              label={t("entry.pass")}
              value={viewCipher()?.password || viewCipher()?.kind?.login?.password}
              isPassword={true}
              showPassword={revealPass()}
              onToggleShow={() => {
                if (!revealPass() && (viewCipher()?.reprompt || viewCipher()?._meta?.reprompt)) {
                  setRepromptCallback(() => () => setRevealPass(true));
                  setShowReprompt(true);
                } else {
                  setRevealPass(!revealPass());
                }
              }}
            />

            {/* TOTP code widget */}
            <Show when={totpCode()}>
              <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
                <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block mb-2">Verification Code</label>
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <span class="text-2xl font-mono font-bold tracking-[0.3em] text-[var(--color-text)] select-all">{totpCode()?.code?.match(/.{1,3}/g)?.join(" ") || totpCode()?.code}</span>
                    <button
                      onClick={() => { navigator.clipboard.writeText(totpCode()?.code || ""); setTotpCopied(true); setTimeout(() => setTotpCopied(false), 1500); }}
                      class="p-1.5 rounded-lg text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
                      title="Copy code"
                    >
                      <Show when={!totpCopied()} fallback={<span class="text-xs text-green-500">Copied</span>}>
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
                      </Show>
                    </button>
                  </div>
                  <span class="text-[10px] text-[var(--color-muted)]">{totpCode()?.period_seconds}s</span>
                </div>
              </div>
            </Show>
          </div>
        </Show>

        {/* Card fields */}
        <Show when={viewCipher()?.type === "card"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Card details</h4>
            <Show when={viewCipher()?.kind?.card?.brand}>
              <CardBrandDisplay number={viewCipher()?.kind?.card?.number || ""} />
            </Show>
            <CopyableField label="Cardholder" value={viewCipher()?.kind?.card?.cardholder_name} />
            <CopyableField label="Number" value={viewCipher()?.kind?.card?.number} />
            <CopyableField label="Expiration" value={viewCipher()?.kind?.card?.exp_month && viewCipher()?.kind?.card?.exp_year ? `${viewCipher()?.kind?.card?.exp_month}/${viewCipher()?.kind?.card?.exp_year}` : null} />
            <CopyableField label="CVV" value={viewCipher()?.kind?.card?.code} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Identity fields */}
        <Show when={viewCipher()?.type === "identity"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Identity details</h4>
            <CopyableField label="Full Name" value={[viewCipher()?.kind?.identity?.title, viewCipher()?.kind?.identity?.first_name, viewCipher()?.kind?.identity?.middle_name, viewCipher()?.kind?.identity?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label="Username" value={viewCipher()?.kind?.identity?.username} />
            <CopyableField label="Company" value={viewCipher()?.kind?.identity?.company} />
            <CopyableField label="Email" value={viewCipher()?.kind?.identity?.email} />
            <CopyableField label="Phone" value={viewCipher()?.kind?.identity?.phone} />
            <CopyableField label="Address" value={[viewCipher()?.kind?.identity?.address1, viewCipher()?.kind?.identity?.address2, viewCipher()?.kind?.identity?.address3].filter(Boolean).join(", ") || null} />
            <CopyableField label="City/State/Postal" value={[viewCipher()?.kind?.identity?.city, viewCipher()?.kind?.identity?.state, viewCipher()?.kind?.identity?.postal_code].filter(Boolean).join(", ") || null} />
            <CopyableField label="Country" value={viewCipher()?.kind?.identity?.country} />
            <CopyableField label="SSN" value={viewCipher()?.kind?.identity?.ssn} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="Passport #" value={viewCipher()?.kind?.identity?.passport_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="License #" value={viewCipher()?.kind?.identity?.license_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* SSH Key fields */}
        <Show when={viewCipher()?.type === "sshKey"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">SSH Key details</h4>
            <CopyableField label="Public Key" value={viewCipher()?.kind?.sshKey?.public_key} />
            <CopyableField label="Fingerprint" value={viewCipher()?.kind?.sshKey?.key_fingerprint} />
            <CopyableField label="Private Key" value={viewCipher()?.kind?.sshKey?.private_key} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Bank Account fields */}
        <Show when={viewCipher()?.type === "bankAccount"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Bank account details</h4>
            <CopyableField label="Bank Name" value={viewCipher()?.bank_name} />
            <CopyableField label="Name on Account" value={viewCipher()?.name_on_account} />
            <CopyableField label="Account Type" value={viewCipher()?.account_type} />
            <CopyableField label="Account Number" value={viewCipher()?.account_number} />
            <CopyableField label="Routing Number" value={viewCipher()?.routing_number} />
            <CopyableField label="Branch Number" value={viewCipher()?.branch_number} />
            <CopyableField label="SWIFT Code" value={viewCipher()?.swift_code} />
            <CopyableField label="IBAN" value={viewCipher()?.iban} />
            <CopyableField label="Bank Phone" value={viewCipher()?.bank_contact_phone} />
            <CopyableField label="PIN" value={viewCipher()?.pin} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Driver License fields */}
        <Show when={viewCipher()?.type === "driversLicense"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Driver license details</h4>
            <CopyableField label="Full Name" value={[viewCipher()?.first_name, viewCipher()?.middle_name, viewCipher()?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label="Date of Birth" value={viewCipher()?.date_of_birth} />
            <CopyableField label="License Number" value={viewCipher()?.license_number} />
            <CopyableField label="Issuing Country" value={viewCipher()?.issuing_country} />
            <CopyableField label="Issuing State" value={viewCipher()?.issuing_state} />
            <CopyableField label="Issue Date" value={viewCipher()?.issue_date} />
            <CopyableField label="Expiration Date" value={viewCipher()?.expiration_date} />
            <CopyableField label="Issuing Authority" value={viewCipher()?.issuing_authority} />
            <CopyableField label="License Class" value={viewCipher()?.license_class} />
          </div>
        </Show>

        {/* Passport fields */}
        <Show when={viewCipher()?.type === "passport"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Passport & ID details</h4>
            <CopyableField label="Full Name" value={[viewCipher()?.given_name, viewCipher()?.surname].filter(Boolean).join(" ") || null} />
            <CopyableField label="Date of Birth" value={viewCipher()?.date_of_birth} />
            <CopyableField label="Sex" value={viewCipher()?.sex} />
            <CopyableField label="Birth Place" value={viewCipher()?.birth_place} />
            <CopyableField label="Nationality" value={viewCipher()?.nationality} />
            <CopyableField label="Issuing Country" value={viewCipher()?.issuing_country} />
            <CopyableField label="Passport Number" value={viewCipher()?.passport_number} />
            <CopyableField label="Passport Type" value={viewCipher()?.passport_type} />
            <CopyableField label="National ID Number" value={viewCipher()?.national_identification_number} />
            <CopyableField label="Issuing Authority" value={viewCipher()?.issuing_authority} />
            <CopyableField label="Issue Date" value={viewCipher()?.issue_date} />
            <CopyableField label="Expiration Date" value={viewCipher()?.expiration_date} />
          </div>
        </Show>

        {/* Website URI group */}
        <Show when={viewCipher()?.uris?.length}>
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Website</h4>
            <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-between group hover:border-[var(--color-primary)] transition-all">
              <div class="min-w-0 flex-1">
                <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block">Website URL</label>
                <a
                  href={(() => { const u = uriStr(viewCipher()?.uris?.[0]); return u.startsWith("http") ? u : `https://${u}`; })()}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-sm text-[var(--color-accent)] hover:underline font-semibold mt-0.5 inline-block"
                >
                  {uriStr(viewCipher()?.uris?.[0])}
                </a>
              </div>
              <a
                href={(() => { const u = uriStr(viewCipher()?.uris?.[0]); return u.startsWith("http") ? u : `https://${u}`; })()}
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

        {/* Custom Fields */}
        <Show when={viewCipher()?.custom_fields?.length > 0}>
          <div class="space-y-3 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Custom Fields</h4>
            <For each={viewCipher()?.custom_fields || []}>
              {(field) => {
                const isLinked = () => typeof field.field_type === "object" && field.field_type?.Linked;
                const isHidden = () => field.field_type === "Hidden";
                const linkedType = () => isLinked() ? field.field_type.Linked : "";
                const resolved = () => {
                  if (isLinked()) {
                    const lt = linkedType();
                    const c = viewCipher();
                    if (!c) return field.value || "";
                    const map = {
                      // Login
                      LoginUsername: c.username,
                      LoginPassword: c.password,
                      // Card
                      CardCardholderName: c.cardholder_name,
                      CardNumber: c.number,
                      CardExpMonth: c.exp_month,
                      CardExpYear: c.exp_year,
                      CardCvv: c.code,
                      // Identity
                      IdentityTitle: c.title,
                      IdentityFirstName: c.first_name,
                      IdentityMiddleName: c.middle_name,
                      IdentityLastName: c.last_name,
                      IdentityUsername: c.username,
                      IdentityCompany: c.company,
                      IdentityEmail: c.email,
                      IdentityPhone: c.phone,
                      IdentityAddress1: c.address1,
                      IdentityAddress2: c.address2,
                      IdentityAddress3: c.address3,
                      IdentityCity: c.city,
                      IdentityState: c.state,
                      IdentityPostalCode: c.postal_code,
                      IdentityCountry: c.country,
                      // Bank Account
                      BankAccountBankName: c.bank_name,
                      BankAccountNameOnAccount: c.name_on_account,
                      BankAccountAccountType: c.account_type,
                      BankAccountAccountNumber: c.account_number,
                      BankAccountRoutingNumber: c.routing_number,
                      BankAccountBranchNumber: c.branch_number,
                      BankAccountPin: c.pin,
                      BankAccountSwiftCode: c.swift_code,
                      BankAccountIban: c.iban,
                      BankAccountBankContactPhone: c.bank_contact_phone,
                      // Driver License
                      DriversLicenseFirstName: c.first_name,
                      DriversLicenseMiddleName: c.middle_name,
                      DriversLicenseLastName: c.last_name,
                      DriversLicenseDateOfBirth: c.date_of_birth,
                      DriversLicenseLicenseNumber: c.license_number,
                      DriversLicenseIssuingCountry: c.issuing_country,
                      DriversLicenseIssuingState: c.issuing_state,
                      DriversLicenseIssueDate: c.issue_date,
                      DriversLicenseExpirationDate: c.expiration_date,
                      DriversLicenseIssuingAuthority: c.issuing_authority,
                      DriversLicenseLicenseClass: c.license_class,
                      // Passport
                      PassportSurname: c.surname,
                      PassportGivenName: c.given_name,
                      PassportDateOfBirth: c.date_of_birth,
                      PassportSex: c.sex,
                      PassportBirthPlace: c.birth_place,
                      PassportNationality: c.nationality,
                      PassportIssuingCountry: c.issuing_country,
                      PassportPassportNumber: c.passport_number,
                      PassportPassportType: c.passport_type,
                      PassportNationalIdNumber: c.national_identification_number,
                      PassportIssuingAuthority: c.issuing_authority,
                      PassportIssueDate: c.issue_date,
                      PassportExpirationDate: c.expiration_date,
                    };
                    return map[lt] || "(linked field)";
                  }
                  return field.value || "";
                };
                return (
                  <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
                    <label class="text-[10px] text-[var(--color-muted)] block uppercase tracking-wider font-extrabold">{field.name}{isLinked() ? " (linked)" : ""}</label>
                    <Show when={isHidden()} fallback={
                      <div class="text-sm text-[var(--color-text)] font-semibold mt-0.5 select-all">{resolved() || "\u2014"}</div>
                    }>
                      <div class="text-sm font-mono text-[var(--color-text)] tracking-widest mt-0.5 select-all">{"\u2022".repeat(8)}</div>
                    </Show>
                  </div>
                );
              }}
            </For>
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

        {/* Attachments */}
        <Show when={viewCipher()?.attachments?.length > 0}>
          <div class="space-y-3 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Attachments</h4>
            <For each={viewCipher()?.attachments || []}>
              {(attach) => {
                const sizeStr = () => {
                  const s = attach.size;
                  if (s > 1024*1024) return (s/(1024*1024)).toFixed(1) + " MB";
                  if (s > 1024) return (s/1024).toFixed(1) + " KB";
                  return s + " bytes";
                };
                async function handleDownload() {
                  try {
                    const result = await daemon("vault.attach_download", JSON.stringify({
                      cipher_id: viewCipher().id,
                      attachment_id: attach.id,
                    }));
                    const b64 = result.data_base64;
                    const binary = atob(b64);
                    const bytes = new Uint8Array(binary.length);
                    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                    const blob = new Blob([bytes]);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url; a.download = attach.filename; a.click();
                    URL.revokeObjectURL(url);
                  } catch(e) { alert("Download failed: " + e.message); }
                }
                return (
                  <div class="flex items-center justify-between p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
                    <div class="flex items-center gap-2 min-w-0">
                      <svg class="w-4 h-4 text-[var(--color-muted)] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/></svg>
                      <div class="min-w-0">
                        <div class="text-sm font-semibold text-[var(--color-text)] truncate">{attach.filename}</div>
                        <div class="text-[10px] text-[var(--color-muted)]">{sizeStr()}</div>
                      </div>
                    </div>
                    <div class="flex items-center gap-1 shrink-0 ml-2">
                      <button onClick={handleDownload} class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer" title="Download">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                      </button>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </div>

      {/* Footer Details Action bar */}
      <div class="p-6 bg-[var(--color-sidebar)] border-t border-[var(--color-border)] flex items-center justify-between gap-4">
        <Show when={selectedCategory() === "Trash"} fallback={
          <Show when={selectedCategory() === "Archive"} fallback={
            <>
              <button
                onClick={startEdit}
                class="flex-1 py-3 px-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                Edit
              </button>
              <button
                onClick={() => archiveCipher(viewCipher().id)}
                class="py-3 px-4 rounded-xl bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] hover:bg-[var(--color-card)] font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"/></svg>
                {t("entry.archive")}
              </button>
              <button
                onClick={() => setShowDeleteConfirm(true)}
                class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                {t("entry.delete")}
              </button>
            </>
          }>
            {/* Archive category: Unarchive + Delete (moves to trash) */}
            <button
              onClick={() => unarchiveCipher(viewCipher().id)}
              class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.706 9H17"/></svg>
              {t("entry.unarchive")}
            </button>
            <button
              onClick={() => setShowDeleteConfirm(true)}
              class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              {t("entry.delete")}
            </button>
          </Show>
        }>
          <button
            onClick={() => restoreCipher(viewCipher().id, t)}
            class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.706 9H17"/></svg>
            {t("entry.restore")}
          </button>
          <button
            onClick={() => setShowDeleteConfirm(true)}
            class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            {t("entry.deletePermanently")}
          </button>
        </Show>
      </div>
    </div>
  );
}

function AddEditCipherForm(props) {
  const { newCipher, setNewCipher, setActivePane, viewCipher } = useApp();
  const { addCipher, updateCipher } = useActions();
  const { t } = useI18n();

  const cipherType = () => newCipher().cipherType || "login";

  // Generator states
  const [genLen, setGenLen] = createSignal(16);
  const [showGen, setShowGen] = createSignal(false);
  const [genUpper, setGenUpper] = createSignal(true);
  const [genNums, setGenNums] = createSignal(true);
  const [genSyms, setGenSyms] = createSignal(true);

  // Mutable uris ref: no signal writes on keystroke.
  // Signal only updated on add/remove to re-render the list.
  // Synced back to newCipher on save.
  const initialUris = newCipher().uris || [];
  let urisRef = initialUris.map(u => ({ ...u }));
  const [uris, setUris] = createSignal([...urisRef]);

  // Mutable custom fields ref: same pattern.
  const initialFields = newCipher().custom_fields || [];
  let fieldsRef = initialFields.map(f => ({ ...f }));
  const [fields, setFields] = createSignal([...fieldsRef]);

  function handleGenerate() {
    const pw = generateSecurePassword(genLen(), genUpper(), genNums(), genSyms());
    setNewCipher({ ...newCipher(), password: pw });
  }

  function addUri() {
    urisRef = [...urisRef, { uri: "", match_strategy: null }];
    setUris([...urisRef]);
  }

  function removeUri(index) {
    urisRef = urisRef.filter((_, i) => i !== index);
    setUris([...urisRef]);
  }

  function updateUri(index, field, value) {
    Object.assign(urisRef[index], { [field]: value });
  }

  function toggleFavorite() {
    setNewCipher({ ...newCipher(), favorite: !newCipher().favorite });
  }

  function toggleReprompt() {
    setNewCipher({ ...newCipher(), reprompt: !newCipher().reprompt });
  }

  function handleSave() {
    // Sync local refs back to newCipher before saving
    setNewCipher({ ...newCipher(), uris: urisRef, custom_fields: fieldsRef });
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
          {/* Favorite toggle */}
          <div class="flex items-center justify-between">
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">Favorite</label>
            <button
              onClick={toggleFavorite}
              class={`p-1.5 rounded-lg transition-colors cursor-pointer ${newCipher().favorite ? "text-yellow-500" : "text-[var(--color-muted)] hover:text-yellow-500"}`}
            >
              <svg class="w-5 h-5" fill={newCipher().favorite ? "currentColor" : "none"} stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
              </svg>
            </button>
          </div>

          {/* Reprompt toggle */}
          <div class="flex items-center justify-between">
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">Require password to view</label>
            <button
              onClick={toggleReprompt}
              class={`p-1.5 rounded-lg transition-colors cursor-pointer ${newCipher().reprompt ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-primary)]"}`}
            >
              <svg class="w-5 h-5" fill={newCipher().reprompt ? "currentColor" : "none"} stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
            </button>
          </div>

          <div>
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Item Name</label>
            <input
              placeholder={t("entry.namePlaceholder")}
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
              value={newCipher().name}
              onInput={e => setNewCipher({ ...newCipher(), name: e.target.value })}
            />
          </div>

          {/* Login-specific fields */}
          <Show when={cipherType() === "login"}>
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
                    <button onClick={() => { setGenUpper(!genUpper()); handleGenerate(); }} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genUpper() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>A-Z</button>
                    <button onClick={() => { setGenNums(!genNums()); handleGenerate(); }} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genNums() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>0-9</button>
                    <button onClick={() => { setGenSyms(!genSyms()); handleGenerate(); }} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genSyms() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>!@#</button>
                  </div>
                  <button onClick={handleGenerate} class="w-full py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] hover:bg-[var(--color-sidebar)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer">Generate New</button>
                </div>
              </Show>
            </div>

            {/* Multi-URI list */}
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">URIs</label>
                <button onClick={addUri} class="text-xs font-bold text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer">+ Add URI</button>
              </div>
              <For each={uris()}>
                {(uriObj, index) => (
                  <div class="flex gap-2 mb-2">
                    <input
                      placeholder="https://example.com"
                      autocapitalize="off"
                      autocomplete="off"
                      spellcheck="false"
                      class="flex-1 px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                      value={uriObj.uri || ""}
                      onInput={e => updateUri(index(), "uri", e.target.value)}
                    />
                    <select
                      class="px-2 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-muted)] outline-none"
                      value={uriObj.match_strategy || ""}
                      onChange={e => updateUri(index(), "match_strategy", e.target.value || null)}
                    >
                      <option value="">Default</option>
                      <option value="domain">Domain</option>
                      <option value="host">Host</option>
                      <option value="startsWith">Starts with</option>
                      <option value="exact">Exact</option>
                      <option value="regex">Regex</option>
                      <option value="never">Never</option>
                    </select>
                    <button onClick={() => removeUri(index())} class="p-3 text-[var(--color-muted)] hover:text-red-500 transition-colors cursor-pointer">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                  </div>
                )}
              </For>
              <Show when={!uris().length}>
                <button onClick={addUri} class="w-full py-3 rounded-xl bg-[var(--color-card)] border border-dashed border-[var(--color-border)] text-sm text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] transition-all cursor-pointer">
                  + Add URI
                </button>
              </Show>
            </div>

            {/* TOTP URI */}
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">TOTP URI</label>
              <input
                placeholder="otpauth://totp/..."
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                value={newCipher().totp_uri || ""}
                onInput={e => setNewCipher({ ...newCipher(), totp_uri: e.target.value })}
              />
            </div>
          </Show>

          {/* Card fields */}
          <Show when={cipherType() === "card"}>
            {/* Brand auto-detect */}
            <CardBrandDisplay number={newCipher().cardNumber || ""} />

            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Cardholder Name</label>
              <input
                placeholder="Full name on card"
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                value={newCipher().cardholder_name || ""}
                onInput={e => setNewCipher({ ...newCipher(), cardholder: e.target.value })}
              />
            </div>

            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Card Number</label>
              <input
                placeholder="1234 5678 9012 3456"
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                value={newCipher().cardNumber || ""}
                onInput={e => setNewCipher({ ...newCipher(), cardNumber: e.target.value })}
              />
            </div>

            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Month</label>
                <select
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                  value={newCipher().expMonth || ""}
                  onChange={e => setNewCipher({ ...newCipher(), expMonth: e.target.value })}
                >
                  <option value="">MM</option>
                  {["01","02","03","04","05","06","07","08","09","10","11","12"].map(m => <option value={m}>{m}</option>)}
                </select>
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Year</label>
                <input
                  placeholder="2028"
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                  value={newCipher().expYear || ""}
                  onInput={e => setNewCipher({ ...newCipher(), expYear: e.target.value })}
                />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">CVV</label>
                <input
                  placeholder="123"
                  type="password"
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                  value={newCipher().cvv || ""}
                  onInput={e => setNewCipher({ ...newCipher(), cvv: e.target.value })}
                />
              </div>
            </div>
          </Show>

          {/* Identity fields */}
          <Show when={cipherType() === "identity"}>
            <div class="grid grid-cols-4 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Title</label>
                <select
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                  value={newCipher().idTitle || ""}
                  onChange={e => setNewCipher({ ...newCipher(), idTitle: e.target.value })}
                >
                  <option value="">--</option>
                  {["Mr","Mrs","Ms","Dr"].map(t => <option value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">First Name</label>
                <input placeholder="John" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().firstName || ""} onInput={e => setNewCipher({ ...newCipher(), firstName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Middle</label>
                <input placeholder="A" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().middleName || ""} onInput={e => setNewCipher({ ...newCipher(), middleName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Last Name</label>
                <input placeholder="Doe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().lastName || ""} onInput={e => setNewCipher({ ...newCipher(), lastName: e.target.value })} />
              </div>
            </div>

            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Username</label>
                <input placeholder="johndoe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().username || ""} onInput={e => setNewCipher({ ...newCipher(), username: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Company</label>
                <input placeholder="Acme Inc" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().company || ""} onInput={e => setNewCipher({ ...newCipher(), company: e.target.value })} />
              </div>
            </div>

            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Email</label>
                <input placeholder="john@example.com" type="email" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().email || ""} onInput={e => setNewCipher({ ...newCipher(), email: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Phone</label>
                <input placeholder="+1 555 123 4567" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().phone || ""} onInput={e => setNewCipher({ ...newCipher(), phone: e.target.value })} />
              </div>
            </div>

            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Address Line 1</label>
              <input placeholder="123 Main St" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().address1 || ""} onInput={e => setNewCipher({ ...newCipher(), address1: e.target.value })} />
            </div>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Address Line 2</label>
              <input placeholder="Apt 4B" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().address2 || ""} onInput={e => setNewCipher({ ...newCipher(), address2: e.target.value })} />
            </div>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Address Line 3</label>
              <input placeholder="Care of" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().address3 || ""} onInput={e => setNewCipher({ ...newCipher(), address3: e.target.value })} />
            </div>

            <div class="grid grid-cols-4 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">City</label>
                <input placeholder="New York" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().city || ""} onInput={e => setNewCipher({ ...newCipher(), city: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">State</label>
                <input placeholder="NY" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().state || ""} onInput={e => setNewCipher({ ...newCipher(), state: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Postal</label>
                <input placeholder="10001" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().postalCode || ""} onInput={e => setNewCipher({ ...newCipher(), postalCode: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Country</label>
                <input placeholder="US" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().country || ""} onInput={e => setNewCipher({ ...newCipher(), country: e.target.value })} />
              </div>
            </div>

            {/* Sensitive fields */}
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">SSN</label>
                <input placeholder="123-45-6789" type="password" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().ssn || ""} onInput={e => setNewCipher({ ...newCipher(), ssn: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Passport #</label>
                <input placeholder="AB1234567" type="password" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().passportNumber || ""} onInput={e => setNewCipher({ ...newCipher(), passportNumber: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">License #</label>
                <input placeholder="D123-456-78-901" type="password" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().licenseNumber || ""} onInput={e => setNewCipher({ ...newCipher(), licenseNumber: e.target.value })} />
              </div>
            </div>
          </Show>

          {/* SSH Key fields */}
          <Show when={cipherType() === "sshKey"}>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Public Key</label>
              <textarea
                placeholder="ssh-rsa AAAA..."
                rows="4"
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all resize-none font-mono"
                value={newCipher().publicKey || ""}
                onInput={e => setNewCipher({ ...newCipher(), publicKey: e.target.value })}
              />
            </div>
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">Private Key</label>
                <span class="text-[10px] text-[var(--color-muted)]">Hidden by default</span>
              </div>
              <textarea
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                rows="6"
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all resize-none font-mono"
                value={newCipher().privateKey || ""}
                onInput={e => setNewCipher({ ...newCipher(), privateKey: e.target.value })}
              />
            </div>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Fingerprint</label>
              <input
                placeholder="SHA256:abc123..."
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                value={newCipher().fingerprint || ""}
                onInput={e => setNewCipher({ ...newCipher(), fingerprint: e.target.value })}
              />
            </div>
          </Show>

          {/* Bank Account fields */}
          <Show when={cipherType() === "bankAccount"}>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Bank Name</label>
                <input placeholder="Chase" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().bankName || ""} onInput={e => setNewCipher({ ...newCipher(), bankName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Name on Account</label>
                <input placeholder="John Doe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().nameOnAccount || ""} onInput={e => setNewCipher({ ...newCipher(), nameOnAccount: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Account Type</label>
                <select class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]" value={newCipher().accountType || ""} onChange={e => setNewCipher({ ...newCipher(), accountType: e.target.value })}>
                  <option value="">Select...</option>
                  <option value="checking">Checking</option>
                  <option value="savings">Savings</option>
                  <option value="investment">Investment</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Account Number</label>
                <input placeholder="123456789" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().accountNumber || ""} onInput={e => setNewCipher({ ...newCipher(), accountNumber: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Routing Number</label>
                <input placeholder="987654321" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().routingNumber || ""} onInput={e => setNewCipher({ ...newCipher(), routingNumber: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Branch Number</label>
                <input placeholder="001" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().branchNumber || ""} onInput={e => setNewCipher({ ...newCipher(), branchNumber: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">SWIFT Code</label>
                <input placeholder="CHASUS33" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().swiftCode || ""} onInput={e => setNewCipher({ ...newCipher(), swiftCode: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">IBAN</label>
                <input placeholder="US12 3456 7890" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().iban || ""} onInput={e => setNewCipher({ ...newCipher(), iban: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Bank Phone</label>
                <input placeholder="+1 800 555 1234" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().bankPhone || ""} onInput={e => setNewCipher({ ...newCipher(), bankPhone: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">PIN</label>
                <input placeholder="****" type="password" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().bankPin || ""} onInput={e => setNewCipher({ ...newCipher(), bankPin: e.target.value })} />
              </div>
            </div>
          </Show>

          {/* Driver License fields */}
          <Show when={cipherType() === "driversLicense"}>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">First Name</label>
                <input placeholder="Jane" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlFirstName || ""} onInput={e => setNewCipher({ ...newCipher(), dlFirstName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Middle</label>
                <input placeholder="A" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlMiddleName || ""} onInput={e => setNewCipher({ ...newCipher(), dlMiddleName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Last Name</label>
                <input placeholder="Doe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlLastName || ""} onInput={e => setNewCipher({ ...newCipher(), dlLastName: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Date of Birth</label>
                <input placeholder="1990-01-15" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlDob || ""} onInput={e => setNewCipher({ ...newCipher(), dlDob: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">License Number</label>
                <input placeholder="D55555" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().dlNumber || ""} onInput={e => setNewCipher({ ...newCipher(), dlNumber: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing Country</label>
                <input placeholder="US" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlCountry || ""} onInput={e => setNewCipher({ ...newCipher(), dlCountry: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing State</label>
                <input placeholder="CA" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlState || ""} onInput={e => setNewCipher({ ...newCipher(), dlState: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issue Date</label>
                <input placeholder="2020-06-01" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlIssueDate || ""} onInput={e => setNewCipher({ ...newCipher(), dlIssueDate: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Expiration</label>
                <input placeholder="2028-06-01" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlExpDate || ""} onInput={e => setNewCipher({ ...newCipher(), dlExpDate: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Class</label>
                <input placeholder="C" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlClass || ""} onInput={e => setNewCipher({ ...newCipher(), dlClass: e.target.value })} />
              </div>
            </div>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing Authority</label>
              <input placeholder="DMV" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlAuthority || ""} onInput={e => setNewCipher({ ...newCipher(), dlAuthority: e.target.value })} />
            </div>
          </Show>

          {/* Passport fields */}
          <Show when={cipherType() === "passport"}>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Given Name</label>
                <input placeholder="John" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppGivenName || ""} onInput={e => setNewCipher({ ...newCipher(), ppGivenName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Surname</label>
                <input placeholder="Doe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppSurname || ""} onInput={e => setNewCipher({ ...newCipher(), ppSurname: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Date of Birth</label>
                <input placeholder="1990-01-15" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppDob || ""} onInput={e => setNewCipher({ ...newCipher(), ppDob: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Sex</label>
                <select class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]" value={newCipher().ppSex || ""} onChange={e => setNewCipher({ ...newCipher(), ppSex: e.target.value })}>
                  <option value="">--</option>
                  <option value="M">M</option>
                  <option value="F">F</option>
                  <option value="X">X</option>
                </select>
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Birth Place</label>
                <input placeholder="City" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppBirthPlace || ""} onInput={e => setNewCipher({ ...newCipher(), ppBirthPlace: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Nationality</label>
                <input placeholder="US" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppNationality || ""} onInput={e => setNewCipher({ ...newCipher(), ppNationality: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing Country</label>
                <input placeholder="US" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppCountry || ""} onInput={e => setNewCipher({ ...newCipher(), ppCountry: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Passport Number</label>
                <input placeholder="P1234567" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().ppNumber || ""} onInput={e => setNewCipher({ ...newCipher(), ppNumber: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Type</label>
                <input placeholder="P" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppType || ""} onInput={e => setNewCipher({ ...newCipher(), ppType: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">National ID Number</label>
                <input placeholder="123-45-6789" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().ppNationalId || ""} onInput={e => setNewCipher({ ...newCipher(), ppNationalId: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing Authority</label>
                <input placeholder="State Department" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppAuthority || ""} onInput={e => setNewCipher({ ...newCipher(), ppAuthority: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issue Date</label>
                <input placeholder="2020-01-01" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppIssueDate || ""} onInput={e => setNewCipher({ ...newCipher(), ppIssueDate: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Expiration</label>
                <input placeholder="2030-01-01" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppExpDate || ""} onInput={e => setNewCipher({ ...newCipher(), ppExpDate: e.target.value })} />
              </div>
            </div>
          </Show>

          {/* Notes (all types) */}
          <div>
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">{t("entry.notes")}</label>
            <textarea
              placeholder={t("entry.notesPlaceholder")}
              rows={cipherType() === "secureNote" ? "8" : "4"}
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all resize-none"
              value={newCipher().notes}
              onInput={e => setNewCipher({ ...newCipher(), notes: e.target.value })}
            />
          </div>

          {/* Custom Fields */}
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">Custom Fields</label>
              <button
                type="button"
                onClick={() => {
                  fieldsRef = [...fieldsRef, { name: "", value: "", field_type: "Text" }];
                  setFields([...fieldsRef]);
                }}
                class="text-[10px] font-bold text-[var(--color-primary)] hover:underline cursor-pointer"
              >+ Add field</button>
            </div>
            <For each={fields()}>
              {(field, i) => {
                const ft = () => {
                  const t = field.field_type;
                  if (typeof t === "string") return t;
                  if (t?.Linked) return "Linked";
                  return "Text";
                };
                const linkedVal = () => typeof field.field_type === "object" && field.field_type?.Linked ? field.field_type.Linked : "LoginUsername";
                return (
                <div class="flex gap-2 mb-2 items-center">
                  <input
                    placeholder="Name"
                    class="w-1/3 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                    value={field.name}
                    onInput={e => {
                      Object.assign(fieldsRef[i()], { name: e.target.value });
                    }}
                  />
                  <select
                    class="px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer"
                    value={ft()}
                    onChange={e => {
                      const v = e.target.value;
                      fieldsRef[i()] = { ...fieldsRef[i()], field_type: v === "Linked" ? { Linked: "LoginUsername" } : v };
                      setFields([...fieldsRef]);
                    }}
                  >
                    <option value="Text">Text</option>
                    <option value="Hidden">Hidden</option>
                    <option value="Boolean">Boolean</option>
                    <option value="Linked">Linked</option>
                  </select>
                  <Show when={ft() !== "Linked"} fallback={
                    <select
                      class="flex-1 px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer"
                      value={linkedVal()}
                      onChange={e => {
                        fieldsRef[i()] = { ...fieldsRef[i()], field_type: { Linked: e.target.value }, value: "" };
                        setFields([...fieldsRef]);
                      }}
                    >
                      <optgroup label="Login">
                        <option value="LoginUsername">Username</option>
                        <option value="LoginPassword">Password</option>
                      </optgroup>
                      <optgroup label="Card">
                        <option value="CardCardholderName">Cardholder</option>
                        <option value="CardNumber">Card Number</option>
                        <option value="CardExpMonth">Exp Month</option>
                        <option value="CardExpYear">Exp Year</option>
                        <option value="CardCvv">CVV</option>
                      </optgroup>
                      <optgroup label="Identity">
                        <option value="IdentityTitle">Title</option>
                        <option value="IdentityFirstName">First Name</option>
                        <option value="IdentityMiddleName">Middle Name</option>
                        <option value="IdentityLastName">Last Name</option>
                        <option value="IdentityUsername">Username</option>
                        <option value="IdentityCompany">Company</option>
                        <option value="IdentityEmail">Email</option>
                        <option value="IdentityPhone">Phone</option>
                        <option value="IdentityAddress1">Address 1</option>
                        <option value="IdentityAddress2">Address 2</option>
                        <option value="IdentityAddress3">Address 3</option>
                        <option value="IdentityCity">City</option>
                        <option value="IdentityState">State</option>
                        <option value="IdentityPostalCode">Postal Code</option>
                        <option value="IdentityCountry">Country</option>
                      </optgroup>
                      <optgroup label="Bank Account">
                        <option value="BankAccountBankName">Bank Name</option>
                        <option value="BankAccountNameOnAccount">Name on Account</option>
                        <option value="BankAccountAccountType">Account Type</option>
                        <option value="BankAccountAccountNumber">Account Number</option>
                        <option value="BankAccountRoutingNumber">Routing Number</option>
                        <option value="BankAccountBranchNumber">Branch Number</option>
                        <option value="BankAccountPin">PIN</option>
                        <option value="BankAccountSwiftCode">SWIFT Code</option>
                        <option value="BankAccountIban">IBAN</option>
                        <option value="BankAccountBankContactPhone">Bank Phone</option>
                      </optgroup>
                      <optgroup label="Driver License">
                        <option value="DriversLicenseFirstName">First Name</option>
                        <option value="DriversLicenseMiddleName">Middle Name</option>
                        <option value="DriversLicenseLastName">Last Name</option>
                        <option value="DriversLicenseDateOfBirth">Date of Birth</option>
                        <option value="DriversLicenseLicenseNumber">License Number</option>
                        <option value="DriversLicenseIssuingCountry">Issuing Country</option>
                        <option value="DriversLicenseIssuingState">Issuing State</option>
                        <option value="DriversLicenseIssueDate">Issue Date</option>
                        <option value="DriversLicenseExpirationDate">Expiration Date</option>
                        <option value="DriversLicenseIssuingAuthority">Issuing Authority</option>
                        <option value="DriversLicenseLicenseClass">License Class</option>
                      </optgroup>
                      <optgroup label="Passport">
                        <option value="PassportSurname">Surname</option>
                        <option value="PassportGivenName">Given Name</option>
                        <option value="PassportDateOfBirth">Date of Birth</option>
                        <option value="PassportSex">Sex</option>
                        <option value="PassportBirthPlace">Birth Place</option>
                        <option value="PassportNationality">Nationality</option>
                        <option value="PassportIssuingCountry">Issuing Country</option>
                        <option value="PassportPassportNumber">Passport Number</option>
                        <option value="PassportPassportType">Passport Type</option>
                        <option value="PassportNationalIdNumber">National ID Number</option>
                        <option value="PassportIssuingAuthority">Issuing Authority</option>
                        <option value="PassportIssueDate">Issue Date</option>
                        <option value="PassportExpirationDate">Expiration Date</option>
                      </optgroup>
                    </select>
                  }>
                    <input
                      placeholder="Value"
                      class="flex-1 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                      value={field.value}
                      onInput={e => {
                        Object.assign(fieldsRef[i()], { value: e.target.value });
                      }}
                    />
                  </Show>
                  <button
                    type="button"
                    onClick={() => {
                      fieldsRef = fieldsRef.filter((_, j) => j !== i());
                      setFields([...fieldsRef]);
                    }}
                    class="p-1.5 rounded-lg text-red-400 hover:bg-red-950/20 cursor-pointer shrink-0"
                    title="Remove"
                  >
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                  </button>
                </div>
              );
              }}
            </For>
          </div>
        </div>
      </div>
      <div class="flex gap-3 p-8 pt-0">
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

function RepromptModal() {
  const { showReprompt, setShowReprompt, repromptCallback } = useApp();
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal("");
  const [loading, setLoading] = createSignal(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!password()) return;
    setLoading(true);
    setError("");
    try {
      await daemon("vault.reprompt_verify", password());
      setShowReprompt(false);
      const cb = repromptCallback();
      if (cb) cb();
      setPassword("");
    } catch (e) {
      setError("Incorrect password");
    }
    setLoading(false);
  }

  return (
    <Show when={showReprompt()}>
      <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
        <div class="w-full max-w-sm p-6 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative animate-scale-in">
          <div class="flex items-center gap-3 mb-4">
            <div class="w-10 h-10 rounded-full bg-[var(--color-primary)]/10 text-[var(--color-primary)] flex items-center justify-center">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            </div>
            <div>
              <div class="text-sm font-bold text-[var(--color-text)]">Verify your identity</div>
              <div class="text-xs text-[var(--color-muted)]">Enter your master password to continue</div>
            </div>
          </div>
          <form onSubmit={handleSubmit}>
            <input
              type="password"
              placeholder="Master password"
              value={password()}
              onInput={e => setPassword(e.target.value)}
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all mb-3"
              autofocus
            />
            <Show when={error()}>
              <div class="text-xs text-red-400 mb-3">{error()}</div>
            </Show>
            <div class="flex gap-2">
              <button
                type="button"
                onClick={() => { setShowReprompt(false); setPassword(""); }}
                class="flex-1 py-2.5 rounded-xl text-xs font-bold text-[var(--color-muted)] border border-[var(--color-border)] hover:bg-[var(--color-card)] transition-all cursor-pointer"
              >Cancel</button>
              <button
                type="submit"
                disabled={loading() || !password()}
                class="flex-1 py-2.5 rounded-xl bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold disabled:opacity-50 transition-all cursor-pointer"
              >{loading() ? "Verifying..." : "Verify"}</button>
            </div>
          </form>
        </div>
      </div>
    </Show>
  );
}

function FolderTree(props) {
  // Build tree from flat list
  const tree = () => {
    const folders = props.folders || [];
    const roots = folders.filter(f => !f.parent_id);
    return roots.map(r => buildNode(r, folders));
  };

  function buildNode(folder, allFolders) {
    const children = allFolders.filter(f => f.parent_id === folder.id);
    return { ...folder, children: children.map(c => buildNode(c, allFolders)) };
  }

  return <For each={tree()}>
    {(node) => <FolderNode node={node} depth={0} selectedFolder={props.selectedFolder} setSelectedFolder={props.setSelectedFolder} />}
  </For>;
}

function FolderNode(props) {
  const [expanded, setExpanded] = createSignal(true);
  const hasChildren = () => (props.node.children || []).length > 0;

  return (
    <div>
      <div
        class={`flex items-center gap-1 px-3.5 py-1.5 rounded-xl text-xs font-bold cursor-pointer ${props.selectedFolder?.() === props.node.id ? "bg-[var(--color-sidebar)] text-[var(--color-text)]" : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"}`}
        style={{ "padding-left": `${12 + props.depth * 16}px` }}
        onClick={() => props.setSelectedFolder?.(props.node.id)}
      >
        {hasChildren() ? (
          <button
            onClick={e => { e.stopPropagation(); setExpanded(!expanded()); }}
            class="p-0.5 rounded hover:bg-black/10 cursor-pointer shrink-0"
          >
            <svg class={`w-3 h-3 transition-transform ${expanded() ? "rotate-90" : ""}`} fill="currentColor" viewBox="0 0 20 20"><path d="M6 4l8 6-8 6V4z"/></svg>
          </button>
        ) : <span class="w-4 shrink-0" />}
        <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
        <span class="truncate">{props.node.name}</span>
      </div>
      <Show when={hasChildren() && expanded()}>
        <For each={props.node.children || []}>
          {(child) => <FolderNode node={child} depth={props.depth + 1} selectedFolder={props.selectedFolder} setSelectedFolder={props.setSelectedFolder} />}
        </For>
      </Show>
    </div>
  );
}

function VaultView() {
  const { ciphers, trashCiphers, archivedCiphers, vaultInfo, error, selectedCategory, setSelectedCategory, selectedFolder, setSelectedFolder, folders, searchQuery, setSearchQuery, activePane, setActivePane, viewCipher, setNewCipher, theme, setTheme, showGenerator, setShowGenerator, showSettingsModal, setShowSettingsModal } = useApp();
  const { lock } = useActions();
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
                        await daemon("folder.create", JSON.stringify({ name }));
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
            <p class="text-xs text-[var(--color-muted)] mt-2 max-w-xs text-center leading-relaxed font-semibold">
              {t("entry.selectPrompt")}
            </p>
          </div>
        </Show>
      </div>
    </div>
  );
}

function DeviceFleetPanel() {
  const app = useApp();
  const { t } = useI18n();

  onMount(() => {
    app.refreshDeviceFleet?.();
  });

  const fleet = () => app.deviceFleet() || [];

  function getStatusBadge(lastPush) {
    if (!lastPush) return { label: "Unknown", color: "bg-slate-600", textColor: "text-slate-300" };
    const diff = Date.now() - new Date(lastPush).getTime();
    const days = diff / (1000 * 60 * 60 * 24);
    if (days < 7) return { label: "Active", color: "bg-emerald-600", textColor: "text-emerald-200" };
    if (days < 30) return { label: "Idle", color: "bg-yellow-600", textColor: "text-yellow-200" };
    if (days < 90) return { label: "Stale", color: "bg-orange-600", textColor: "text-orange-200" };
    return { label: "Dormant", color: "bg-red-600", textColor: "text-red-200" };
  }

  async function revokeDevice(deviceId, deviceName) {
    if (!confirm(`Revoke "${deviceName}"? This will rotate vault keys. This cannot be undone.`)) return;
    try {
      await invoke("daemon_request", { action: "device.revoke", payload: deviceId });
      app.setRevokeWarning({ name: deviceName });
      // Refresh fleet to reflect revocation
      refreshDeviceFleet();
    } catch (e) {
      alert(`Revocation failed: ${e}. Try CLI: idtty --direct devices revoke ${deviceId}`);
    }
  }

  return (
    <div class="flex-1 overflow-y-auto p-8 space-y-6">
      <h2 class="text-xl font-extrabold text-[var(--color-text)]">Devices</h2>
      <p class="text-xs text-[var(--color-muted)]">Devices that have synced with this vault.</p>

      <Show when={app.revokeWarning()}>
        <div class="p-4 rounded-xl bg-red-950/30 border border-red-900/30 space-y-3">
          <h4 class="text-xs font-bold text-red-400 uppercase tracking-wider">Device Revoked</h4>
          <p class="text-xs text-red-300 leading-relaxed">
            <strong>{app.revokeWarning().name}</strong> has been revoked. To fully secure your vault:
          </p>
          <ol class="text-xs text-red-300 list-decimal list-inside space-y-1">
            <li>Go to your GitHub/GitLab repository settings</li>
            <li>Remove the revoked device's deploy key or PAT</li>
            <li>Optionally regenerate your remaining device's key</li>
          </ol>
          <label class="flex items-center gap-2 mt-3 cursor-pointer">
            <input type="checkbox" onChange={(e) => { if (e.target.checked) app.setRevokeWarning(null); }} class="accent-red-500" />
            <span class="text-xs text-red-300">I have rotated the git credentials</span>
          </label>
        </div>
      </Show>

      <Show when={fleet().length === 0}>
        <div class="text-center py-12 text-[var(--color-muted)]">
          <p class="text-sm">No device activity recorded yet.</p>
          <p class="text-xs mt-2">Devices will appear here after syncing.</p>
        </div>
      </Show>

      <div class="space-y-3">
        <For each={fleet()}>
          {(device) => {
            const badge = getStatusBadge(device.last_push);
            return (
              <div class="p-4 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] hover:border-[var(--color-primary)] transition-all space-y-3">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] flex items-center justify-center">
                      <svg class="w-5 h-5 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                    </div>
                    <div>
                      <p class="text-sm font-bold text-[var(--color-text)]">{device.name} <Show when={device.id === app.selfDeviceId()}><span class="text-[10px] font-normal text-[var(--color-primary)] bg-[var(--color-primary)]/10 px-1.5 py-0.5 rounded-md ml-1">This device</span></Show></p>
                      <p class="text-xs text-[var(--color-muted)] font-mono">{device.id?.substring(0, 8)}...</p>
                    </div>
                  </div>
                  <span class={`px-2 py-1 rounded-lg text-xs font-bold ${badge.color} ${badge.textColor}`}>{badge.label}</span>
                </div>
                <div class="grid grid-cols-3 gap-3 text-xs">
                  <div>
                    <p class="text-[var(--color-muted)]">Last sync</p>
                    <p class="text-[var(--color-text)] font-medium">{device.last_push ? new Date(device.last_push).toLocaleDateString() : "Never"}</p>
                  </div>
                  <div>
                    <p class="text-[var(--color-muted)]">Epoch</p>
                    <p class="text-[var(--color-text)] font-medium">{device.epoch ?? "-"}</p>
                  </div>
                  <div>
                    <p class="text-[var(--color-muted)]">Last commit</p>
                    <p class="text-[var(--color-text)] font-mono">{device.last_commit?.substring(0, 7) || "-"}</p>
                  </div>
                </div>
                <div class="flex justify-end pt-1">
                  <Show when={app.selfDeviceId() && device.id !== app.selfDeviceId()}>
                    <button
                      onClick={() => revokeDevice(device.id, device.name)}
                      class="px-3 py-1.5 rounded-lg text-xs font-bold bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 transition-all cursor-pointer"
                    >
                      Revoke
                    </button>
                  </Show>
                </div>
              </div>
            );
          }}
        </For>
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
