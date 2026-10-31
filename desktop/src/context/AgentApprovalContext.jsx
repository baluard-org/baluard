import { createSignal, createContext, useContext, onSettled } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { daemon } from "../lib/daemon.js";
import { useVault } from "./VaultContext.jsx";
import { useVaultSwitcher } from "./VaultSwitcherContext.jsx";
import { toastError, toastSuccess } from "./toastSignal.js";
import { useI18n } from "../i18n/index.jsx";
import AgentApprovalModal from "../components/AgentApprovalModal.jsx";

const AgentApprovalContext = createContext(null);

export function AgentApprovalProvider(props) {
  const vault = useVault();
  const switcher = useVaultSwitcher();
  const { t } = useI18n();
  const [pending, setPending] = createSignal([]);
  const [grants, setGrants] = createSignal([]);
  const [events, setEvents] = createSignal([]);
  const [yolo, setYoloState] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const knownRequests = new Set();
  let disposed = false;

  async function refresh() {
    const slug = switcher.activeSlug();
    try {
      const [pendingData, grantData] = await Promise.all([
        daemon("agents.pending").then(JSON.parse),
        daemon("agents.list").then(JSON.parse),
      ]);
      if (disposed || slug !== switcher.activeSlug()) return;
      const rows = Array.isArray(pendingData.pending) ? pendingData.pending : [];
      setPending(rows);
      setGrants(Array.isArray(grantData.grants) ? grantData.grants : []);
      setYoloState(grantData.yolo === true);
      const activeIds = new Set(rows.map((row) => row.request_id));
      for (const id of knownRequests) {
        if (!activeIds.has(id)) knownRequests.delete(id);
      }
      for (const row of rows) {
        if (!knownRequests.has(row.request_id)) {
          knownRequests.add(row.request_id);
          if (document.hidden) {
            invoke("notify_agent_request", {
              title: t("agents.notifyTitle"),
              body: t("agents.notifyBody", { name: row.claimed_name }),
            }).catch(() => {});
          }
        }
      }
    } catch {
      // Lock, switch, and daemon shutdown all make the next poll irrelevant.
    }
  }

  async function refreshAudit() {
    const slug = switcher.activeSlug();
    try {
      const data = await daemon("agents.audit").then(JSON.parse);
      if (disposed || slug !== switcher.activeSlug()) return;
      setEvents(Array.isArray(data.events) ? data.events.slice(-10).reverse() : []);
    } catch {
      // The next settings refresh retries without interrupting approvals.
    }
  }

  onSettled(() => {
    refresh();
    refreshAudit();
    const timer = setInterval(refresh, 2000);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
  });

  async function decide(action, requestId) {
    if (busy()) return;
    setBusy(true);
    try {
      await daemon(action, { request_id: requestId });
      setPending((rows) => rows.filter((row) => row.request_id !== requestId));
      refreshAudit();
      toastSuccess(t(action === "agents.approve" ? "agents.approved" : "agents.denied"));
    } catch (e) {
      toastError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function approveAll() {
    if (busy()) return;
    setBusy(true);
    try {
      for (const row of pending()) {
        await daemon("agents.approve", { request_id: row.request_id });
      }
      setPending([]);
      refreshAudit();
      toastSuccess(t("agents.approved"));
    } catch (e) {
      toastError(e.message);
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    try {
      await daemon("agents.revoke");
      setGrants([]);
      refreshAudit();
      toastSuccess(t("agents.revoked"));
    } catch (e) {
      toastError(e.message);
    }
  }

  async function setYolo(enabled, masterPassword = null) {
    try {
      await daemon("agents.set_yolo", {
        enabled,
        ...(enabled ? { master_password: masterPassword } : {}),
      });
      setYoloState(enabled);
      refreshAudit();
      toastSuccess(t(enabled ? "agents.yoloEnabled" : "agents.yoloDisabled"));
    } catch (e) {
      toastError(e.message);
      throw e;
    }
  }

  function itemName(id) {
    const cipher = vault.ciphers().find((row) => row.id === id || row._meta?.id === id);
    return cipher?.name || cipher?._meta?.name || id;
  }

  const store = {
    pending,
    grants,
    events,
    yolo,
    busy,
    approve: (id) => decide("agents.approve", id),
    deny: (id) => decide("agents.deny", id),
    approveAll,
    revoke,
    setYolo,
    refresh,
    refreshAudit,
  };

  return (
    <AgentApprovalContext value={store}>
      {props.children}
      <AgentApprovalModal
        request={pending()[0] || null}
        requests={pending()}
        itemName={itemName}
        busy={busy()}
        onApprove={store.approve}
        onDeny={store.deny}
        onApproveAll={approveAll}
      />
    </AgentApprovalContext>
  );
}

export function useAgentApprovals() {
  return useContext(AgentApprovalContext);
}
