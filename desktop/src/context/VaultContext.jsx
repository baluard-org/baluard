import { createSignal, createContext, useContext } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildAddPayload, buildUpdatePayload, buildGetPayload } from "../lib/payload.js";
import { consumeVaultPrefetch } from "../lib/vaultPrefetch.js";
import { setError } from "./errorSignal.js";

const VaultContext = createContext();

// Valid pane transitions. Dev-only guard.
const VALID_PANE_TRANSITIONS = {
  welcome: ["detail", "add"],
  detail:  ["welcome", "edit"],
  edit:    ["detail", "welcome"],
  add:     ["welcome", "detail"],
};

function guardedSetPane(setActivePane, from, to) {
  if (!VALID_PANE_TRANSITIONS[from]?.includes(to)) {
    console.warn(`[vault] Invalid pane transition: ${from} → ${to}`);
  }
  setActivePane(to);
}

const EMPTY_CIPHER = {
  name: "", username: "", password: "", uris: [], notes: "",
  cipherType: "login", favorite: false, reprompt: false,
  attachments: [], folder_id: null, custom_fields: [], totp_uri: "",
};

function VaultProvider(props) {
  // Cipher data
  const [ciphers, setCiphers] = createSignal([]);
  const [trashCiphers, setTrashCiphers] = createSignal([]);
  const [archivedCiphers, setArchivedCiphers] = createSignal([]);
  const [folders, setFolders] = createSignal([]);

  // Device fleet
  const [deviceFleet, setDeviceFleet] = createSignal([]);
  const [selfDeviceId, setSelfDeviceId] = createSignal(null);
  const [revokeWarning, setRevokeWarning] = createSignal(null);

  // Navigation & filters
  const [selectedCategory, setSelectedCategory] = createSignal("All items");
  const [selectedFolder, setSelectedFolder] = createSignal(null);
  const [searchQuery, setSearchQuery] = createSignal("");
  const [activePane, setActivePane] = createSignal("welcome");

  // Settings modal (only accessible while unlocked)
  const [showSettingsModal, setShowSettingsModal] = createSignal(false);

  // ── Data fetchers ──

  async function refreshCiphers(t) {
    try {
      const prefetch = consumeVaultPrefetch();
      const data = prefetch
        ? (await prefetch)
        : JSON.parse(await daemon("vault.list_full"));

      if (!data) throw new Error("empty response");
      setCiphers(data.ciphers || []);
      setFolders(Array.isArray(data.folders) ? data.folders : []);
      setTrashCiphers(data.trash || []);
      setArchivedCiphers(data.archived || []);
    } catch (e) {
      setError(sanitizeError(e, t));
    }
  }

  async function refreshDeviceFleet() {
    try {
      const data = JSON.parse(await daemon("vault.device_activity"));
      setDeviceFleet(data.devices || []);
      if (data.self_device_id) setSelfDeviceId(data.self_device_id);
    } catch { /* non-critical */ }
  }

  // ── Cipher CRUD ──
  // These accept viewCipher/setViewCipher/newCipher/setNewCipher as args
  // because those are local state in VaultView, not global context.

  async function addCipher(cipherData, t) {
    if (!cipherData.name) { setError(t("entry.namePlaceholder") + " required"); return null; }
    try {
      const id = await daemon("vault.add", JSON.stringify(buildAddPayload(cipherData)));
      await refreshCiphers(t);
      return id; // new cipher ID as string
    } catch (e) {
      setError(sanitizeError(e, t));
      return null;
    }
  }

  async function updateCipher(id, cipherData, t) {
    if (!cipherData.name) { setError(t("entry.namePlaceholder") + " required"); return; }
    try {
      await daemon("vault.update", JSON.stringify(buildUpdatePayload(id, cipherData)));
      await refreshCiphers(t);
      const updated = JSON.parse(await daemon("vault.get", JSON.stringify(buildGetPayload(id))));
      return updated;
    } catch (e) {
      setError(sanitizeError(e, t));
      return null;
    }
  }

  async function getCipher(id, t) {
    try {
      return JSON.parse(await daemon("vault.get", JSON.stringify(buildGetPayload(id))));
    } catch (e) {
      setError(sanitizeError(e, t));
      return null;
    }
  }

  async function deleteCipher(id, t) {
    try {
      await daemon("vault.delete", id);
      guardedSetPane(setActivePane, activePane(), "welcome");
      await refreshCiphers(t);
      return true;
    } catch (e) {
      setError(sanitizeError(e, t));
      return false;
    }
  }

  async function restoreCipher(id, t) {
    try {
      await daemon("vault.trash.restore", id);
      guardedSetPane(setActivePane, activePane(), "welcome");
      await refreshCiphers(t);
      return true;
    } catch (e) {
      setError(sanitizeError(e, t));
      return false;
    }
  }

  async function archiveCipher(id, t) {
    try {
      await daemon("vault.archive", id);
      guardedSetPane(setActivePane, activePane(), "welcome");
      await refreshCiphers(t);
      // refreshCiphers fetches everything via vault.list_full batch call
      return true;
    } catch (e) {
      setError(sanitizeError(e, t));
      return false;
    }
  }

  async function unarchiveCipher(id, t) {
    try {
      await daemon("vault.unarchive", id);
      guardedSetPane(setActivePane, activePane(), "welcome");
      await refreshCiphers(t);
      // refreshCiphers fetches everything via vault.list_full batch call
      return true;
    } catch (e) {
      setError(sanitizeError(e, t));
      return false;
    }
  }

  const store = {
    // Cipher data
    ciphers, setCiphers,
    trashCiphers, setTrashCiphers,
    archivedCiphers, setArchivedCiphers,
    folders, setFolders,
    // Device fleet
    deviceFleet, setDeviceFleet,
    selfDeviceId, setSelfDeviceId,
    revokeWarning, setRevokeWarning,
    // Navigation
    selectedCategory, setSelectedCategory,
    selectedFolder, setSelectedFolder,
    searchQuery, setSearchQuery,
    activePane, setActivePane,
    // Settings
    showSettingsModal, setShowSettingsModal,
    // Actions
    refreshCiphers, refreshDeviceFleet,
    addCipher, updateCipher, getCipher,
    deleteCipher, restoreCipher, archiveCipher, unarchiveCipher,
  };

  return (
    <VaultContext.Provider value={store}>
      {props.children}
    </VaultContext.Provider>
  );
}

function useVault() {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be used within VaultProvider");
  return ctx;
}

export { VaultContext, VaultProvider, useVault, EMPTY_CIPHER };
