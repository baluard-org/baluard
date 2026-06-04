import { createSignal, createContext, useContext, createEffect } from "solid-js";
import { daemon } from "../lib/daemon.js";

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
  const [activePane, setActivePane] = createSignal("welcome");
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

export { AppContext, AppProvider, useApp };
