import { useVault } from "../context/VaultContext.jsx";
import CipherAvatar, { invalidateFaviconCache } from "./CipherAvatar.jsx";
import { uriStr } from "../lib/utils.js";

export default function CipherRow(props) {
  const vault = useVault();
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
      <CipherAvatar name={props.cipher.name} uri={firstUri()} />
      <div class="min-w-0 flex-1">
        <div class="text-sm font-semibold text-[var(--color-text)] truncate">{props.cipher.name || "Untitled"}</div>
        <div class="text-xs text-[var(--color-muted)] truncate">{props.cipher.username || props.cipher._meta?.username || ""}</div>
      </div>
    </button>
  );
}
