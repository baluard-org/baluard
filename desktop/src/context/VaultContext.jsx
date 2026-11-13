import { createSignal, createContext, useContext, onSettled } from "solid-js";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildAddPayload, buildUpdatePayload, buildGetPayload } from "../lib/payload.js";
import { fetchVaultFull, consumeVaultPrefetch } from "../lib/vaultPrefetch.js";
import { toastError, toastWarning } from "./toastSignal.js";
import { setTheme as setAppTheme } from "./themeSignal.js";
import { makeTransitionGuard } from "../lib/transitionGuard.js";
import { clearHeldPhrase } from "../lib/heldPhrase.js";

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
  // The precise admin marker from the daemon (holds_root), not a
  // row-counting proxy: holds for zero-collection vaults. null =
  // unknown (still loading or load failed).
  const [isAdmin, setIsAdmin] = createSignal(null);
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
    // A shown-once phrase held for one vault must never resurface on
    // another; the ceremony re-holds it if the user switches back.
    clearHeldPhrase();
    // Vault-scoped data must not bleed across switches: stale admin
    // state would show admin controls on a member vault (and the ask
    // button on an admin vault) until the refresh lands.
    setCollections([]);
    setIsAdmin(null);
    // Decrypted entries from the previous vault must not render under the
    // new vault's header while the next list_full is in flight.
    setCiphers([]);
    setFolders([]);
    setTags([]);
    setTrashCiphers([]);
    setArchivedCiphers([]);
  }

  async function refreshCiphers(t) {
    try {
      const prefetch = consumeVaultPrefetch();
      // A failed prefetch resolves null: fall through to a direct fetch
      // instead of erroring out.
      const data =
        (prefetch ? await prefetch : null) ||
        (await fetchVaultFull());
      if (!data) throw new Error("empty response");
      setCiphers(data.ciphers || []);
      setFolders(Array.isArray(data.folders) ? data.folders : []);
      setTags(Array.isArray(data.tags) ? data.tags : []);
      setTrashCiphers(data.trash || []);
      setArchivedCiphers(data.archived || []);
      // Entries this build cannot decrypt stay hidden from the list; the
      // count says they exist and an app update is needed.
      if (Number(data.unreadable) > 0) {
        toastWarning(t("vault.unreadableEntries", { count: Number(data.unreadable) }));
      }
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
    try {
      const r = JSON.parse(await daemon("vault.is_admin_device"));
      setIsAdmin(r.is_admin === true);
    } catch {
      setIsAdmin(null);
    }
  }

  // S2-5: pull the merged multi-vault payload. Active and locked/closed
  // rows are dropped here; each remaining cipher gets tagged with its
  // source vault for the list badge + read-only detail.
  async function refreshOtherVaults() {
    try {
      const data = JSON.parse(
        await daemon("vaults.list_full_all", JSON.stringify({ exclude_active: true }))
      );
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

  function withMergedMeta(cipher, existingMeta = null, metaPatch = null) {
    if (!cipher) return cipher;
    const id = cipher.id || existingMeta?.id || "";
    const meta = {
      ...(existingMeta || {}),
      id,
      name: cipher.name ?? existingMeta?.name ?? "",
      cipher_type: cipher.type ?? existingMeta?.cipher_type ?? "login",
      favorite: Boolean(cipher.favorite),
      username: cipher.username ?? null,
      collection_id: existingMeta?.collection_id ?? null,
      ...(metaPatch || {}),
    };
    return { ...cipher, _meta: meta };
  }

  function syncTagsFromLists(activeList, archivedList, trashList) {
    const unique = new Set();
    for (const list of [activeList, archivedList, trashList]) {
      for (const c of list) {
        if (!Array.isArray(c?.tags)) continue;
        for (const tag of c.tags) {
          if (tag) unique.add(tag);
        }
      }
    }
    setTags(Array.from(unique).sort());
  }

  async function refreshCipher(id, t, metaPatch = null) {
    const fresh = await getCipher(id, t);
    if (!fresh) return null;
    const existingActive = ciphers().find((c) => (c.id || c._meta?.id) === id);
    const existingArchived = archivedCiphers().find((c) => (c.id || c._meta?.id) === id);
    const existing = existingActive || existingArchived;
    const updated = withMergedMeta(fresh, existing?._meta, metaPatch);
    let nextActive = ciphers();
    let nextArchived = archivedCiphers();
    if (existingArchived && !existingActive) {
      nextArchived = nextArchived.map((c) => ((c.id || c._meta?.id) === id ? updated : c));
      setArchivedCiphers(nextArchived);
    } else if (existingActive) {
      nextActive = nextActive.map((c) => ((c.id || c._meta?.id) === id ? updated : c));
      setCiphers(nextActive);
    } else {
      nextActive = [updated, ...nextActive];
      setCiphers(nextActive);
    }
    syncTagsFromLists(nextActive, nextArchived, trashCiphers());
    return updated;
  }

  async function addCipher(cipherData, t) {
    if (!cipherData.name) { toastWarning(t("entry.nameRequired")); return null; }
    try {
      const id = await daemon("vault.add", JSON.stringify(buildAddPayload(cipherData)));
      const fresh = await getCipher(id, t);
      if (fresh) {
        const entry = withMergedMeta(fresh);
        const nextActive = [entry, ...ciphers()];
        setCiphers(nextActive);
        syncTagsFromLists(nextActive, archivedCiphers(), trashCiphers());
      }
      return id; // new cipher ID as string
    } catch (e) {
      toastError(sanitizeError(e, t));
      return null;
    }
  }

  async function updateCipher(id, cipherData, t) {
    if (!cipherData.name) { toastWarning(t("entry.nameRequired")); return; }
    try {
      await daemon("vault.update", JSON.stringify(buildUpdatePayload(id, cipherData)));
      return await refreshCipher(id, t);
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
      const fromActive = ciphers().find((c) => (c.id || c._meta?.id) === id);
      const fromArchived = archivedCiphers().find((c) => (c.id || c._meta?.id) === id);
      const target = fromActive || fromArchived;
      if (fromActive) {
        setCiphers((prev) => prev.filter((c) => (c.id || c._meta?.id) !== id));
      }
      if (fromArchived) {
        setArchivedCiphers((prev) => prev.filter((c) => (c.id || c._meta?.id) !== id));
      }
      if (target) {
        setTrashCiphers((prev) => [target, ...prev.filter((c) => (c.id || c._meta?.id) !== id)]);
      } else {
        setTrashCiphers((prev) => prev.filter((c) => (c.id || c._meta?.id) !== id));
      }
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
      const target = trashCiphers().find((c) => (c.id || c._meta?.id) === id);
      setTrashCiphers((prev) => prev.filter((c) => (c.id || c._meta?.id) !== id));
      if (target) {
        setCiphers((prev) => [target, ...prev]);
      } else {
        await refreshCipher(id, t);
      }
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
      const target = ciphers().find((c) => (c.id || c._meta?.id) === id);
      setCiphers((prev) => prev.filter((c) => (c.id || c._meta?.id) !== id));
      if (target) {
        setArchivedCiphers((prev) => [target, ...prev]);
      }
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
      setTags((prev) => prev.filter((tag) => tag !== name));
      const stripTag = (list) =>
        list.map((c) =>
          Array.isArray(c.tags) && c.tags.includes(name)
            ? { ...c, tags: c.tags.filter((tag) => tag !== name) }
            : c
        );
      setCiphers(stripTag);
      setArchivedCiphers(stripTag);
      setTrashCiphers(stripTag);
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
      const target = archivedCiphers().find((c) => (c.id || c._meta?.id) === id);
      setArchivedCiphers((prev) => prev.filter((c) => (c.id || c._meta?.id) !== id));
      if (target) {
        setCiphers((prev) => [target, ...prev]);
      }
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
    isAdmin,
    selectedCollection, setSelectedCollection,
    searchQuery, setSearchQuery,
    activePane, setActivePane,
    // Settings
    showSettingsModal, setShowSettingsModal,
    // Profile
    displayName, profileSubtitle, avatarB64, avatarExt,
    // Actions
    refreshCiphers, refreshCipher, refreshDeviceFleet, refreshProfile,
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
