import { Show, For } from "solid-js";
import ConsolePanel from "./ConsolePanel.jsx";
import { Button } from "./Primitives.jsx";
import { useI18n } from "../i18n/index.jsx";

export default function AgentApprovalModal(props) {
  const { t } = useI18n();
  return (
    <ConsolePanel
      show={Boolean(props.request)}
      accentClass="border-amber-500"
      minHeightClass="min-h-[22rem]"
      ariaLabelledby="agent-approval-title"
    >
      <Show when={props.request}>
        {(request) => (
          <div class="w-full max-w-lg mx-auto flex flex-col">
            <h3 id="agent-approval-title" class="text-sm font-bold uppercase tracking-wider text-[var(--color-text)] mb-1 font-mono">
              {t("agents.title")}
            </h3>
            <p class="text-xs text-[var(--color-muted)] mb-4 font-mono">{request().claimed_name}</p>
            <div class="rounded border border-[var(--color-border)] bg-black/20 p-3 mb-4">
              <div class="text-[10px] uppercase text-[var(--color-muted)] mb-1">{t("agents.requester")}</div>
              <div class="text-xs break-all font-mono" data-testid="agent-exe-path">{request().exe_path}</div>
            </div>
            <p class="text-sm mb-3">{request().need}</p>
            <div class="text-[10px] uppercase text-[var(--color-muted)] mb-2">{t("agents.items")}</div>
            <ul class="mb-5 max-h-36 overflow-y-auto space-y-1">
              <For each={request().item_ids}>
                {(id) => (
                  <li class="text-sm rounded bg-[var(--color-bg)] px-3 py-2">{props.itemName(id)}</li>
                )}
              </For>
            </ul>
            <div class="flex gap-3">
              <Button
                data-testid="agent-deny"
                disabled={props.busy}
                onClick={() => props.onDeny?.(request().request_id)}
                class="flex-1 py-2.5 font-mono text-xs uppercase"
              >{t("agents.deny")}</Button>
              <Button
                data-testid="agent-approve"
                disabled={props.busy}
                onClick={() => props.onApprove?.(request().request_id)}
                class="flex-1 py-2.5 font-mono text-xs uppercase"
              >{t("agents.approve")}</Button>
            </div>
            <Show when={(props.requests?.length || 0) > 1}>
              <Button
                data-testid="agent-approve-all"
                disabled={props.busy}
                onClick={() => props.onApproveAll?.()}
                class="mt-3 py-2 font-mono text-xs uppercase"
              >{t("agents.approveAll")}</Button>
            </Show>
          </div>
        )}
      </Show>
    </ConsolePanel>
  );
}
