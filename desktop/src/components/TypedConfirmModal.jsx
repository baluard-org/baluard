import { createSignal, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import FocusTrap from "./FocusTrap.jsx";
import { Transition } from "../lib/transition";

/**
 * §4.8-3: typed confirmation for destructive member actions. The user
 * must type the member's display name before the confirm button
 * enables — a click alone is weak proof for an irreversible action.
 *
 * Props:
 *   show          — visibility
 *   title, body   — already-translated strings
 *   confirmWord   — the exact string the user must type (member name)
 *   confirmLabel  — already-translated confirm button text
 *   extra         — optional node under the input (warnings, override)
 *   danger        — red confirm button (default true)
 *   onConfirm     — fired when confirmed with a matching word
 *   onClose       — fired on cancel / overlay click / Escape
 */
export default function TypedConfirmModal(props) {
  const { t } = useI18n();
  let dialogRef;
  const [typed, setTyped] = createSignal("");

  const matches = () =>
    props.confirmWord != null &&
    props.confirmWord !== "" &&
    typed().trim() === props.confirmWord;

  return (
    <Transition name="fade">
      <Show when={props.show}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="typed-confirm-title"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => props.onClose?.()}
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => props.onClose?.()} />
          <div
            class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 id="typed-confirm-title" class="text-lg font-bold text-[var(--color-text)] mb-2">
              {props.title}
            </h3>
            <p class="text-sm text-[var(--color-muted)] mb-4">{props.body}</p>
            <input
              value={typed()}
              onInput={(e) => setTyped(e.currentTarget.value)}
              autocomplete="off"
              spellcheck="false"
              autofocus
              class="w-full px-3 py-2.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] mb-3"
              placeholder={props.confirmWord}
            />
            <Show when={props.extra}>{props.extra}</Show>
            <div class="flex gap-3">
              <button
                onClick={() => props.onClose?.()}
                class="flex-1 py-2.5 rounded-xl border border-[var(--color-border)] text-sm font-semibold text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer"
              >
                {t("common.cancel")}
              </button>
              <button
                onClick={() => matches() && props.onConfirm?.()}
                disabled={!matches()}
                class={`flex-1 py-2.5 rounded-xl text-sm font-semibold text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer ${
                  props.danger === false
                    ? "bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)]"
                    : "bg-red-600 hover:bg-red-700"
                }`}
              >
                {props.confirmLabel}
              </button>
            </div>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
