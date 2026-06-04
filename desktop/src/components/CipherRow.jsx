import { Show } from "solid-js";
import { useApp } from "../context/AppContext.jsx";
import { useActions } from "../hooks/useActions.js";
import { useI18n } from "../i18n/index.jsx";
import { getCuratedColor, getDomainInitials, uriStr } from "../lib/utils.js";

export default function CipherRow(props) {
  const { getCipher } = useActions();
  const { viewCipher, activePane } = useApp();
  const { t } = useI18n();

  const isSelected = () => viewCipher()?.id === props.cipher.id && activePane() === "detail";
  const cipherType = () => props.cipher.type || props.cipher._meta?.type || "login";
  const isFav = () => props.cipher.favorite || props.cipher._meta?.favorite || false;

  return (
    <div
      class={`flex items-center justify-between p-3.5 rounded-xl cursor-pointer transition-all-fast group ${
        isSelected()
          ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] shadow-md"
          : "bg-transparent hover:bg-slate-800/20 border border-transparent hover:border-[var(--color-border)] text-[var(--color-text)]"
      }`}
      onClick={() => getCipher(props.cipher.id, t)}
    >
      <div class="flex items-center gap-3.5 min-w-0 flex-1">
        <div class={`w-10 h-10 rounded-xl flex items-center justify-center text-white font-bold shrink-0 shadow-md ${
          isSelected() ? "bg-[var(--color-primary-text)]/20" : getCuratedColor(props.cipher.name)
        }`}>
          {getDomainInitials(props.cipher.name)}
        </div>
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-1.5">
            <span class={`text-sm font-semibold truncate ${isSelected() ? "text-[var(--color-primary-text)]" : "text-[var(--color-text)]"}`}>
              {props.cipher.name || "Untitled"}
            </span>
            {isFav() && (
              <svg class={`w-3.5 h-3.5 shrink-0 ${isSelected() ? "text-yellow-300" : "text-yellow-500"}`} fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
              </svg>
            )}
            {(props.cipher.reprompt || props.cipher._meta?.reprompt) && (
              <svg class="w-3.5 h-3.5 shrink-0 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            )}
          </div>
          <div class={`text-xs truncate mt-0.5 ${isSelected() ? "text-[var(--color-primary-text)]/75" : "text-[var(--color-muted)]"}`}>
            {props.cipher.username || (cipherType() === "login" ? "No username" : cipherType() === "secureNote" ? "Secure note" : cipherType())}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div class="flex items-center gap-1.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity ml-2">
        <Show when={props.cipher.uris?.[0]}>
          <a
            href={(() => { const u = uriStr(props.cipher.uris[0]); return u.startsWith("http") ? u : `https://${u}`; })()}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            title="Launch website"
            class={`p-1.5 rounded-lg transition-colors ${
              isSelected() ? "hover:bg-black/10 text-[var(--color-primary-text)]" : "hover:bg-[var(--color-sidebar)] text-[var(--color-muted)] hover:text-[var(--color-text)]"
            }`}
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        </Show>
        <button
          onClick={(e) => {
            e.stopPropagation();
            navigator.clipboard.writeText(props.cipher.password || "");
          }}
          title="Copy password"
          class={`p-1.5 rounded-lg transition-colors cursor-pointer ${
            isSelected() ? "hover:bg-black/10 text-[var(--color-primary-text)]" : "hover:bg-[var(--color-sidebar)] text-[var(--color-muted)] hover:text-[var(--color-text)]"
          }`}
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
          </svg>
        </button>
      </div>
    </div>
  );
}
