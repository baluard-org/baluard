import { createSignal, createContext, useContext } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildAddPayload, buildUpdatePayload, buildGetPayload } from "../lib/payload.js";
import { setError } from "./errorSignal.js";

const VaultContext = createContext();

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

  async function refreshTrashCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.trash.list"));
      const ids = data.cipher_ids || [];
      const full = await Promise.all(
        ids.map(async (id) => {
          try {
            return JSON.parse(await daemon("vault.get", JSON.stringify(buildGetPayload(id))));
          } catch { return { id, name: "Decryption Error", username: "", uris: [] }; }
        })
      );
      setTrashCiphers(full);
    } catch { /* non-critical */ }
  }

  async function refreshArchivedCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.list_archived"));
      const metas = data.ciphers || [];
      const full = await Promise.all(
        metas.map(async (meta) => {
          try {
            return JSON.parse(await daemon("vault.get", JSON.stringify(buildGetPayload(meta.id))));
          } catch { return { id: meta.id, name: "Decryption Error", username: "", uris: [] }; }
        })
      );
      setArchivedCiphers(full);
    } catch { /* non-critical */ }
  }

  async function refreshCiphers(t) {
    try {
      const data = JSON.parse(await daemon("vault.list"));
      const metas = data.ciphers || [];
      const full = await Promise.all(
        metas.map(async (meta) => {
          try {
            const detailStr = await daemon("vault.get", JSON.stringify(buildGetPayload(meta.id)));
            return { ...JSON.parse(detailStr), _meta: meta };
          } catch { return { ...meta, name: meta.name || "Decryption Error", username: "", uris: [] }; }
        })
      );
      setCiphers(full);

      try {
        const folderData = JSON.parse(await daemon("folder.list"));
        setFolders(Array.isArray(folderData) ? folderData : []);
      } catch {}

      await refreshTrashCiphers();
      await refreshArchivedCiphers();
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
    if (!cipherData.name) { setError(t("entry.namePlaceholder") + " required"); return; }
    try {
      await daemon("vault.add", JSON.stringify(buildAddPayload(cipherData)));
      setActivePane("welcome");
      await refreshCiphers(t);
      return true;
    } catch (e) {
      setError(sanitizeError(e, t));
      return false;
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
      setActivePane("welcome");
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
      setActivePane("welcome");
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
      setActivePane("welcome");
      await refreshCiphers(t);
      // refreshCiphers already calls refreshArchivedCiphers internally
      return true;
    } catch (e) {
      setError(sanitizeError(e, t));
      return false;
    }
  }

  async function unarchiveCipher(id, t) {
    try {
      await daemon("vault.unarchive", id);
      setActivePane("welcome");
      await refreshCiphers(t);
      // refreshCiphers already calls refreshArchivedCiphers internally
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
