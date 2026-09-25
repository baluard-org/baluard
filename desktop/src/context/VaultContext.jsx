import { createSignal, createContext, useContext, onSettled } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildAddPayload, buildUpdatePayload, buildGetPayload } from "../lib/payload.js";
import { consumeVaultPrefetch } from "../lib/vaultPrefetch.js";
import { toastError, toastWarning } from "./toastSignal.js";
import { setTheme as setAppTheme } from "./themeSignal.js";
import { makeTransitionGuard } from "../lib/transitionGuard.js";

const VaultContext = createContext(null);

// Valid pane transitions. Dev-only guard.
const VALID_PANE_TRANSITIONS = {
  welcome: ["detail", "add"],
  detail:  ["welcome", "edit", "add"],
  edit:    ["detail", "welcome"],
  add:     ["welcome", "detail"],
};

// DEV-only diagnostics; the state write always runs (see transitionGuard.js).
const guardPane = makeTransitionGuard(VALID_PANE_TRANSITIONS, "vault");

const EMPTY_CIPHER = {
  name: "", username: "", password: "", uris: [], notes: "",
  cipherType: "login", favorite: false, reprompt: false,
  attachments: [], folder_id: null, custom_fields: [], totp_uri: "", tags: [],
};

function VaultProvider(props) {
  // Cipher data
  const [ciphers, setCiphers] = createSignal([]);
  // S2-5 merged multi-vault view: envelopes of OTHER open+unlocked vaults
  // (each already filtered to non-active rows server-side). Refreshed
  // alongside the active vault's list; non-critical on failure.
  const [otherVaults, setOtherVaults] = createSignal([]);
  const [trashCiphers, setTrashCiphers] = createSignal([]);
  const [archivedCiphers, setArchivedCiphers] = createSignal([]);
  const [folders, setFolders] = createSignal([]);
  const [tags, setTags] = createSignal([]);

  // Device fleet
  const [deviceFleet, setDeviceFleet] = createSignal([]);
  const [selfDeviceId, setSelfDeviceId] = createSignal(null);
  const [revokeWarning, setRevokeWarning] = createSignal(null);

  // Navigation & filters
  const [selectedCategory, setSelectedCategory] = createSignal("All items");
  const [selectedFolder, setSelectedFolder] = createSignal(null);
  const [selectedTag, setSelectedTag] = createSignal(null);
  // S3-7c / 4.8: shared collections (role-aware) + the selected one.
  const [collections, setCollections] = createSignal([]);
  const [selectedCollection, setSelectedCollection] = createSignal(null);
  const [searchQuery, setSearchQuery] = createSignal("");
  const [activePane, setActivePane] = createSignal("welcome");

  // Settings modal (only accessible while unlocked)
  const [showSettingsModal, setShowSettingsModal] = createSignal(false);

  // Profile (loaded from settings)
  const [displayName, setDisplayName] = createSignal("");
  const [profileSubtitle, setProfileSubtitle] = createSignal("");
  const [avatarB64, setAvatarB64] = createSignal("");
  const [avatarExt, setAvatarExt] = createSignal("png");

  // ── Data fetchers ──

  // Reset vault-scoped navigation + filters. Called when the active vault
  // changes (switcher) so a stale category/folder/tag/search selection or
  // pane from the previous vault doesn't carry over. VaultView resets its
  // own local state (viewCipher/newCipher) separately.
  function resetNavigation() {
    setSelectedCategory("All items");
    setSelectedFolder(null);
    setSelectedTag(null);
    setSelectedCollection(null);
    setSearchQuery("");
    setActivePane("welcome");
  }

  async function refreshCiphers(t) {
    try {
      const prefetch = consumeVaultPrefetch();
      const data = prefetch
        ? (await prefetch)
        : JSON.parse(await daemon("vault.list_full"));

      if (!data) throw new Error("empty response");
      setCiphers(data.ciphers || []);
      setFolders(Array.isArray(data.folders) ? data.folders : []);
      setTags(Array.isArray(data.tags) ? data.tags : []);
      setTrashCiphers(data.trash || []);
      setArchivedCiphers(data.archived || []);
      await refreshOtherVaults();
      refreshCollections();
      // Profile loads alongside cipher data
      refreshProfile();
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  // S3-7c / 4.8: role-aware shared collections. Best-effort — a vault
  // without collections support simply shows an empty section.
  async function refreshCollections() {
    try {
      const data = JSON.parse(await daemon("collections.list"));
      setCollections(Array.isArray(data.collections) ? data.collections : []);
    } catch {
      setCollections([]);
    }
  }

  // S2-5: pull the merged multi-vault payload. Active and locked/closed
  // rows are dropped here; each remaining cipher gets tagged with its
  // source vault for the list badge + read-only detail.
  async function refreshOtherVaults() {
    try {
      const data = JSON.parse(await daemon("vaults.list_full_all"));
      const rows = (data.vaults || []).filter(
        (v) => !v.active && v.presence === "unlocked" && Array.isArray(v.ciphers)
      );
      setOtherVaults(
        rows.map((v) => ({
          slug: v.slug,
          name: v.display_name,
          space: v.space,
          ciphers: v.ciphers,
        }))
      );
    } catch {
      // Non-critical surface: the merged view just stays empty.
      setOtherVaults([]);
    }
  }

  // Foreign ciphers (other vaults) tagged for the list + detail.
  const otherVaultCiphers = () =>
    otherVaults().flatMap((v) =>
      (v.ciphers || []).map((c) => ({
        ...c,
        _vault: { slug: v.slug, name: v.name, space: v.space },
      }))
    );

  // Staleness bound (S2-5 review): a sibling vault can lock (auto-lock
  // timer, blur policy, close) without this context hearing about it.
  // The daemon stays authoritative; re-pull on focus regain and on a 30s
  // heartbeat — same design as the vault switcher's presence refresh.
  let otherVaultHeartbeat;
  function onFocusOrVisible() {
    refreshOtherVaults();
  }
  onSettled(() => {
    otherVaultHeartbeat = setInterval(refreshOtherVaults, 30_000);
    window.addEventListener("focus", onFocusOrVisible);
    document.addEventListener("visibilitychange", onFocusOrVisible);
    return () => {
      clearInterval(otherVaultHeartbeat);
      window.removeEventListener("focus", onFocusOrVisible);
      document.removeEventListener("visibilitychange", onFocusOrVisible);
    };
  });

  async function refreshDeviceFleet() {
    try {
      const data = JSON.parse(await daemon("vault.device_activity"));
      setDeviceFleet(data.devices || []);
      if (data.self_device_id) setSelfDeviceId(data.self_device_id);
    } catch { /* non-critical */ }
  }

  async function refreshProfile() {
    try {
      const data = JSON.parse(await daemon("settings.get"));
      setDisplayName(data.display_name || "");
      setProfileSubtitle(data.subtitle || "");
      setAvatarExt(data.avatar_ext || "png");
      if (data.theme) {
        setAppTheme(data.theme);
      }
    } catch (e) {
      if (import.meta.env.DEV) console.warn("refreshProfile settings:", e);
    }
    try {
      const b64 = await daemon("vault.avatar.get");
      setAvatarB64(b64 || "");
    } catch (e) {
      if (import.meta.env.DEV) console.warn("refreshProfile avatar:", e);
    }
  }

  // ── Cipher CRUD ──
  // These accept viewCipher/setViewCipher/newCipher/setNewCipher as args
  // because those are local state in VaultView, not global context.

  async function addCipher(cipherData, t) {
    if (!cipherData.name) { toastWarning(t("entry.namePlaceholder") + " required"); return null; }
    try {
      const id = await daemon("vault.add", JSON.stringify(buildAddPayload(cipherData)));
      await refreshCiphers(t);
      return id; // new cipher ID as string
    } catch (e) {
      toastError(sanitizeError(e, t));
      return null;
    }
  }

  async function updateCipher(id, cipherData, t) {
    if (!cipherData.name) { toastWarning(t("entry.namePlaceholder") + " required"); return; }
    try {
      await daemon("vault.update", JSON.stringify(buildUpdatePayload(id, cipherData)));
      await refreshCiphers(t);
      // list_full already carries the fresh cipher (K3): skip the extra
      // vault.get round-trip and serve the updated item from the list.
      return ciphers().find((c) => c.id === id) || null;
    } catch (e) {
      toastError(sanitizeError(e, t));
      return null;
    }
  }

  async function getCipher(id, t) {
    try {
      return JSON.parse(await daemon("vault.get", JSON.stringify(buildGetPayload(id))));
    } catch (e) {
      toastError(sanitizeError(e, t));
      return null;
    }
  }

  async function deleteCipher(id, t) {
    try {
      await daemon("vault.delete", id);
      guardPane(activePane(), "welcome", setActivePane);
      await refreshCiphers(t);
      return true;
    } catch (e) {
      toastError(sanitizeError(e, t));
      return false;
    }
  }

  async function restoreCipher(id, t) {
    try {
      await daemon("vault.trash.restore", id);
      guardPane(activePane(), "welcome", setActivePane);
      await refreshCiphers(t);
      return true;
    } catch (e) {
      toastError(sanitizeError(e, t));
      return false;
    }
  }

  async function archiveCipher(id, t) {
    try {
      await daemon("vault.archive", id);
      guardPane(activePane(), "welcome", setActivePane);
      await refreshCiphers(t);
      return true;
    } catch (e) {
      toastError(sanitizeError(e, t));
      return false;
    }
  }

  async function deleteTag(name, t) {
    try {
      await daemon("tag.delete", name);
      if (selectedTag() === name) setSelectedTag(null);
      await refreshCiphers(t);
      return true;
    } catch (e) {
      toastError(sanitizeError(e, t));
      return false;
    }
  }

  async function unarchiveCipher(id, t) {
    try {
      await daemon("vault.unarchive", id);
      guardPane(activePane(), "welcome", setActivePane);
      await refreshCiphers(t);
      return true;
    } catch (e) {
      toastError(sanitizeError(e, t));
      return false;
    }
  }

  const store = {
    // Cipher data
    ciphers, setCiphers,
    otherVaults, otherVaultCiphers,
    trashCiphers, setTrashCiphers,
    archivedCiphers, setArchivedCiphers,
    folders, setFolders,
    tags, setTags,
    // Device fleet
    deviceFleet, setDeviceFleet,
    selfDeviceId, setSelfDeviceId,
    revokeWarning, setRevokeWarning,
    // Navigation
    selectedCategory, setSelectedCategory,
    selectedFolder, setSelectedFolder,
    selectedTag, setSelectedTag,
    collections, refreshCollections,
    selectedCollection, setSelectedCollection,
    searchQuery, setSearchQuery,
    activePane, setActivePane,
    // Settings
    showSettingsModal, setShowSettingsModal,
    // Profile
    displayName, profileSubtitle, avatarB64, avatarExt,
    // Actions
    refreshCiphers, refreshDeviceFleet, refreshProfile,
    resetNavigation,
    addCipher, updateCipher, getCipher,
    deleteCipher, restoreCipher, archiveCipher, unarchiveCipher, deleteTag,
  };

  return (
    <VaultContext value={store}>
      {props.children}
    </VaultContext>
  );
}

function useVault() {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be used within VaultProvider");
  return ctx;
}

export { VaultContext, VaultProvider, useVault, EMPTY_CIPHER };
