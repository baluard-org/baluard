import { createSignal, createEffect, For, Show } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import FocusTrap from "./FocusTrap.jsx";
import { Button, Input } from "./Primitives.jsx";
import { Transition } from "../lib/transition";

/**
 * S3-7c / 4.8: ask an admin for access to a shared collection. Lists the
 * published catalog (admin-curated names) plus a paste-an-id fallback,
 * the requested access level, and a short note. Pending own asks render
 * below with withdraw.
 *
 * Props: show, setShow
 */
export default function AskAccessModal(props) {
  const { t } = useI18n();
  const [catalog, setCatalog] = createSignal([]);
  const [mine, setMine] = createSignal([]);
  const [collectionId, setCollectionId] = createSignal("");
  const [access, setAccess] = createSignal("read");
  const [note, setNote] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [pasteMode, setPasteMode] = createSignal(false);
  let dialogRef;

  createEffect(
    () => props.show,
    (show) => {
      if (show) void refresh();
    },
  );

  async function refresh() {
    try {
      const cat = JSON.parse(await daemon("collections.catalog_list"));
      setCatalog(Array.isArray(cat.catalog) ? cat.catalog : []);
    } catch {
      setCatalog([]);
    }
    try {
      const data = JSON.parse(await daemon("collections.requests_mine"));
      setMine(Array.isArray(data.requests) ? data.requests : []);
    } catch {
      setMine([]);
    }
  }

  async function submit() {
    // The daemon refuses unknown collections, so an unpasteable id is
    // safe to submit — keep the paste fallback gate-free.
    if (!collectionId()) {
      toastError(t("shared.askNeedsCollection"));
      return;
    }
    setBusy(true);
    try {
      await daemon("collections.request_access", {
        collection_id: collectionId(),
        access: access(),
        note: note(),
      });
      toastSuccess(t("shared.askSent"));
      setNote("");
      await refresh();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function withdraw(id) {
    try {
      await daemon("collections.requests_withdraw", { request_id: id });
      await refresh();
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  return (
    <Transition name="fade">
      <Show when={props.show}>
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby="ask-access-title"
          class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => props.setShow(false)}
        >
          <FocusTrap containerRef={dialogRef} onEscape={() => props.setShow(false)} />
          <div
            class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-md w-full shadow-2xl max-h-[85vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="ask-access-title" class="text-base font-bold text-[var(--color-text)] mb-1">
              {t("shared.askTitle")}
            </h2>
            <p class="text-xs text-[var(--color-muted)] mb-4">{t("shared.askSubtitle")}</p>

            <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="ask-collection">
              {t("shared.collection")}
            </label>
            <Show
              when={catalog().length > 0 && !pasteMode()}
              fallback={
                <Input
                  id="ask-collection"
                  placeholder={t("shared.collectionIdPlaceholder")}
                  value={collectionId()}
                  onInput={(e) => setCollectionId(e.currentTarget.value.trim())}
                />
              }
            >
              <select
                id="ask-collection"
                class="w-full text-sm rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-[var(--color-text)] mb-3 cursor-pointer"
                value={collectionId()}
                onChange={(e) => setCollectionId(e.currentTarget.value)}
              >
                <option value="">{t("shared.pickCollection")}</option>
                <For each={catalog()}>
                  {(c) => <option value={c.collection_id}>{c.name}</option>}
                </For>
              </select>
            </Show>

            <Show when={catalog().length > 0}>
              <button
                type="button"
                class="text-[11px] text-[var(--color-muted)] hover:text-[var(--color-text)] underline cursor-pointer mb-3"
                onClick={() => setPasteMode(!pasteMode())}
              >
                {pasteMode() ? t("shared.pickFromList") : t("shared.pasteIdToggle")}
              </button>
            </Show>

            <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="ask-access-level">
              {t("shared.accessLevel")}
            </label>
            <select
              id="ask-access-level"
              class="w-full text-sm rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] px-3 py-2 text-[var(--color-text)] mb-3 cursor-pointer"
              value={access()}
              onChange={(e) => setAccess(e.currentTarget.value)}
            >
              <option value="read">{t("shared.readAccess")}</option>
              <option value="write">{t("shared.writeAccess")}</option>
            </select>

            <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="ask-note">
              {t("shared.note")}
            </label>
            <Input
              id="ask-note"
              placeholder={t("shared.notePlaceholder")}
              value={note()}
              onInput={(e) => setNote(e.currentTarget.value)}
            />

            <div class="flex justify-end gap-2 mt-5">
              <Button onClick={() => props.setShow(false)}>
                {t("common.close")}
              </Button>
              <Button onClick={() => void submit()} disabled={busy()}>
                {busy() ? t("common.sending") : t("shared.sendAsk")}
              </Button>
            </div>

            <Show when={mine().length > 0}>
              <div class="mt-5 pt-4 border-t border-[var(--color-border)]">
                <h3 class="text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)] mb-2">
                  {t("shared.myAsks")}
                </h3>
                <For each={mine()}>
                  {(r) => (
                    <div class="flex items-center gap-2 py-1.5 text-xs">
                      <span class="text-[var(--color-text)] truncate">
                        {catalog().find((c) => c.collection_id === r.collection_id)?.name || t("shared.unknownFolder")}
                      </span>
                      <span class="text-[var(--color-muted)]">
                        {r.access === "write" ? t("shared.writeAccess") : t("shared.readAccess")}
                      </span>
                      <span class="ml-auto text-[var(--color-muted)]">{t("shared.pending")}</span>
                      <button
                        onClick={() => void withdraw(r.id)}
                        class="text-[var(--color-primary)] hover:text-[var(--color-primary-hover)] cursor-pointer font-semibold"
                      >
                        {t("shared.withdraw")}
                      </button>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </Transition>
  );
}
