import { Show, For, createSignal, onSettled } from "solid-js";
import { useAgentApprovals } from "../context/AgentApprovalContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { Button } from "./Primitives.jsx";
import ConfirmModal from "./ConfirmModal.jsx";

export default function AgentSettingsRow() {
  const agents = useAgentApprovals();
  const { t } = useI18n();
  const [confirmYolo, setConfirmYolo] = createSignal(false);
  if (!agents) return null;

  onSettled(() => {
    agents.refreshAudit();
  });

  function enableYolo() {
    setConfirmYolo(false);
    window.__baluardReprompt?.show((password) => {
      agents.setYolo(true, password).catch(() => {});
    });
  }

  return (
    <section class="space-y-3 border-t border-[var(--color-border)] pt-4" data-testid="agent-settings">
      <div>
        <h3 class="text-sm font-semibold text-[var(--color-text)]">{t("agents.settingsTitle")}</h3>
        <p class="text-xs text-[var(--color-muted)] mt-1">{t("agents.settingsDesc")}</p>
      </div>
      <Show when={agents.grants().length > 0}>
        <div class="space-y-2">
          <div class="text-xs font-semibold">{t("agents.activeGrants")}</div>
          {agents.grants().map((grant) => (
            <div class="rounded border border-[var(--color-border)] p-2 text-[10px] font-mono break-all">
              {grant.exe_path}
            </div>
          ))}
          <Button data-testid="agent-revoke" onClick={agents.revoke} class="py-2 text-xs">
            {t("agents.revokeAll")}
          </Button>
        </div>
      </Show>
      <Show when={agents.events().length > 0}>
        <div class="space-y-2">
          <div class="text-xs font-semibold">{t("agents.recentActivity")}</div>
          <For each={agents.events().slice(0, 5)}>
            {(event) => (
              <div class="rounded border border-[var(--color-border)] p-2 text-[10px]">
                <div>{t(`agents.event.${event.event}`)}</div>
                <div class="text-[var(--color-muted)] break-all font-mono mt-1">{event.exe_path}</div>
              </div>
            )}
          </For>
        </div>
      </Show>
      <label class="flex items-start gap-2 text-xs cursor-pointer">
        <input
          data-testid="agent-yolo"
          type="checkbox"
          checked={agents.yolo()}
          onChange={(e) => {
            if (e.currentTarget.checked) setConfirmYolo(true);
            else agents.setYolo(false).catch(() => {});
          }}
        />
        <span>
          <span class="block font-semibold">{t("agents.yolo")}</span>
          <span class="block text-[var(--color-muted)] mt-1">{t("agents.yoloDesc")}</span>
        </span>
      </label>
      <ConfirmModal
        show={confirmYolo()}
        idPrefix="agent-yolo-warning"
        title={t("agents.yolo")}
        body={t("agents.yoloWarning")}
        confirmLabel={t("agents.approve")}
        onConfirm={enableYolo}
        onClose={() => setConfirmYolo(false)}
      />
    </section>
  );
}
