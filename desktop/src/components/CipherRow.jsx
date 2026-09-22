import { Show } from "solid-js";
import { useVault } from "../context/VaultContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import CipherAvatar from "./CipherAvatar.jsx";
import { uriStr } from "../lib/utils.js";

export default function CipherRow(props) {
  const vault = useVault();
  const { t } = useI18n();
  const firstUri = () => {
    const uris = props.cipher.uris || props.cipher._meta?.uris;
    return uris?.length ? uriStr(uris[0]) : null;
  };

  return (
    <button
      onClick={() => props.onSelect?.(props.cipher)}
      class={`w-full px-4 py-3 rounded-xl text-left transition-all cursor-pointer flex items-center gap-3 ${
        props.active
          ? "bg-[var(--color-card)] border border-[var(--color-border)] shadow-sm"
          : "hover:bg-[var(--color-sidebar)]"
      }`}
    >
      <CipherAvatar name={props.cipher.name} uri={firstUri()} favicon={props.cipher.favicon} />
      <div class="min-w-0 flex-1">
        <div class="text-sm font-semibold text-[var(--color-text)] truncate">{props.cipher.name || t("entry.untitled")}</div>
        <div class="flex items-center gap-2 text-xs text-[var(--color-muted)] truncate">
          <span class="truncate">{props.cipher.username || props.cipher._meta?.username || ""}</span>
          <Show when={props.cipher._vault}>
            <span class="shrink-0 px-1.5 py-px rounded-full bg-[var(--color-sidebar)] text-[10px] text-[var(--color-muted)] border border-[var(--color-border)]">
              {props.cipher._vault.name}
            </span>
          </Show>
        </div>
      </div>
    </button>
  );
}
