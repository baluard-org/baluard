import { useI18n } from "../i18n/index.jsx";
import { useApp } from "../context/AppContext.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildAddPayload, buildUpdatePayload, buildGetPayload, buildCreatePayload } from "../lib/payload.js";
import { invoke } from "@tauri-apps/api/core";

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
      const result = JSON.parse(await daemon("vault.create", JSON.stringify(buildCreatePayload(pw))));
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
            const detailStr = await daemon("vault.get", JSON.stringify(buildGetPayload(id)));
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
            const detailStr = await daemon("vault.get", JSON.stringify(buildGetPayload(meta.id)));
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
      const metas = data.ciphers || [];

      const fullCiphers = await Promise.all(
        metas.map(async (meta) => {
          try {
            const detailStr = await daemon("vault.get", JSON.stringify(buildGetPayload(meta.id)));
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
      await daemon("vault.add", JSON.stringify(buildAddPayload(c)));
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
      await daemon("vault.update", JSON.stringify(buildUpdatePayload(id, c)));
      app.setActivePane("welcome");
      await refreshCiphers();

      const updatedData = JSON.parse(await daemon("vault.get", JSON.stringify(buildGetPayload(id))));
      app.setViewCipher(updatedData);
      app.setActivePane("detail");
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function getCipher(id, t) {
    try {
      const data = JSON.parse(await daemon("vault.get", JSON.stringify(buildGetPayload(id))));
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

export { useActions };
