import { createSignal, For, Show, onSettled } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { toastError, toastSuccess } from "../context/toastSignal.js";
import { recipientOutboxPath } from "../lib/outbox.js";
import { copyToClipboard } from "../lib/clipboard.js";
import FocusTrap from "./FocusTrap.jsx";
import { useVault } from "../context/VaultContext.jsx";
import ConfirmModal from "./ConfirmModal.jsx";
import { Button, Input } from "./Primitives.jsx";
import SearchableTagSelect from "./SearchableTagSelect.jsx";

/**
 * S2 UI: the outbox owner + recipient surfaces. Owner side mirrors
 * items into a folder a recipient carries around (live: edits
 * re-mirror on sync). Recipient side links such a folder and reads
 * entries view-only. The daemon is the validator; this tab wires
 * flows, not policy.
 */
export default function OutboxesTab() {
  const { t } = useI18n();
  const vault = useVault();
  const [outboxes, setOutboxes] = createSignal([]);
  const [contacts, setContacts] = createSignal([]);
  const [links, setLinks] = createSignal([]);
  const [busy, setBusy] = createSignal(false);
  // Publish form
  const [pubCiphers, setPubCiphers] = createSignal([]);
  const [pubContacts, setPubContacts] = createSignal([]);
  const [pubPath, setPubPath] = createSignal("");
  // Link form
  const [linkPath, setLinkPath] = createSignal("");
  const [openEntries, setOpenEntries] = createSignal(null); // outbox_id
  const [entries, setEntries] = createSignal([]);
  const [opened, setOpened] = createSignal(null); // OpenedEntry modal
  const [revokeTarget, setRevokeTarget] = createSignal(null);
  const [forgetTarget, setForgetTarget] = createSignal(null);
  let entryDialogRef;

  function recipientName(pubkey) {
    const c = contacts().find((x) => x.identity_signing_pubkey === pubkey);
    return c ? c.display_name : pubkey.slice(0, 12) + "…";
  }

  async function loadAll() {
    try {
      const res = JSON.parse(await daemon("outbox.list", {}));
      setOutboxes(res || []);
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
    try {
      const res = JSON.parse(await daemon("contacts.list", {}));
      setContacts(res.contacts || []);
    } catch {
      setContacts([]);
    }
    try {
      const res = JSON.parse(await daemon("outbox.links", {}));
      setLinks(res || []);
    } catch {
      setLinks([]);
    }
  }

  onSettled(() => void loadAll());

  async function publish() {
    if (pubCiphers().length === 0 || pubContacts().length === 0 || !pubPath().trim()) return;
    setBusy(true);
    try {
      const recipients = pubContacts()
        .map((identity) => contacts().find((contact) => contact.identity_signing_pubkey === identity))
        .filter(Boolean);
      for (const recipient of recipients) {
        for (const cipherId of pubCiphers()) {
          await daemon("outbox.publish", {
            outbox_path: recipients.length === 1 ? pubPath().trim() : recipientOutboxPath(pubPath(), recipient),
            cipher_id: cipherId,
            contact: recipient.identity_signing_pubkey,
          });
        }
      }
      setPubCiphers([]);
      setPubContacts([]);
      setPubPath("");
      toastSuccess(t("outbox.publishedToast"));
      await loadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
      await loadAll();
    } finally {
      setBusy(false);
    }
  }

  async function resync() {
    setBusy(true);
    try {
      const res = JSON.parse(await daemon("outbox.resync", {}));
      const n = (res || []).filter((r) => r.committed).length;
      toastSuccess(t("outbox.resyncedToast", { n }));
      await loadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    const target = revokeTarget();
    if (!target) return;
    setBusy(true);
    try {
      await daemon("outbox.revoke", { outbox_path: target.path });
      toastSuccess(t("outbox.revokedToast"));
      await loadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
      setRevokeTarget(null);
    }
  }

  async function linkFolder() {
    const p = linkPath().trim();
    if (!p) return;
    setBusy(true);
    try {
      await daemon("outbox.link", { outbox_path: p });
      setLinkPath("");
      toastSuccess(t("outbox.linkedToast"));
      await loadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function forget() {
    const target = forgetTarget();
    if (!target) return;
    setBusy(true);
    try {
      await daemon("outbox.forget", { outbox_id: target.outbox_id });
      toastSuccess(t("outbox.forgotToast"));
      if (openEntries() === target.outbox_id) {
        setOpenEntries(null);
        setEntries([]);
      }
      await loadAll();
    } catch (e) {
      toastError(sanitizeError(e, t));
    } finally {
      setBusy(false);
      setForgetTarget(null);
    }
  }

  async function toggleEntries(link) {
    if (openEntries() === link.outbox_id) {
      setOpenEntries(null);
      setEntries([]);
      return;
    }
    try {
      const res = JSON.parse(
        await daemon("outbox.entries", { outbox_id: link.outbox_id }),
      );
      setOpenEntries(link.outbox_id);
      setEntries(res || []);
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  async function openEntry(outboxId, row) {
    try {
      const res = JSON.parse(
        await daemon("outbox.read", {
          outbox_id: outboxId,
          cipher_id: row.cipher_id,
        }),
      );
      setOpened(res);
    } catch (e) {
      toastError(sanitizeError(e, t));
    }
  }

  function loginData(item) {
    if (item?.kind?.type !== "login") return null;
    return item.kind.data || {};
  }

  function entryName(item) {
    return item?.name || item?.kind?.data?.name || "—";
  }

  return (
    <div class="p-6 space-y-6 overflow-y-auto">
      {/* Owner: live mirrors */}
      <section class="space-y-3">
        <div class="flex items-center justify-between">
          <div>
            <h3 class="text-sm font-bold text-[var(--color-text)]">{t("outbox.sharedTitle")}</h3>
            <p class="text-xs text-[var(--color-muted)]">{t("outbox.sharedHint")}</p>
          </div>
          <Show when={outboxes().length > 0}>
            <Button onClick={resync} disabled={busy()}>{t("outbox.resyncAction")}</Button>
          </Show>
        </div>

        <Show
          when={outboxes().length > 0}
          fallback={<p class="text-xs text-[var(--color-muted)]">{t("outbox.empty")}</p>}
        >
          <div class="space-y-2">
            <For each={outboxes()}>
              {(o) => (
                <div class="flex items-center gap-3 p-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)]">
                  <div class="flex-1 min-w-0">
                    <p class="text-xs font-semibold text-[var(--color-text)] truncate">
                      {recipientName(o.recipient_signing_pub)}
                    </p>
                    <p class="text-[11px] text-[var(--color-muted)] truncate">{o.path}</p>
                  </div>
                  <span class="text-[11px] text-[var(--color-muted)] whitespace-nowrap">
                    <Show when={(o.published || []).length === 1} fallback={`${(o.published || []).length} ${t("outbox.itemsSuffix")}`}>
                      {t("outbox.oneItem")}
                    </Show>
                  </span>
                  <Button
                    variant="danger"
                    onClick={() => setRevokeTarget(o)}
                  >
                    {t("outbox.revoke")}
                  </Button>
                </div>
              )}
            </For>
          </div>
        </Show>

        {/* Publish form */}
        <div class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)] space-y-3">
          <h4 class="text-xs font-bold text-[var(--color-text)] uppercase">{t("outbox.publishTitle")}</h4>
          <div>
            <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="ob-item">
              {t("outbox.itemLabel")}
            </label>
            <SearchableTagSelect
              id="ob-item"
              options={vault.ciphers().map((cipher) => ({ value: cipher.id, label: cipher.name }))}
              values={pubCiphers()}
              onChange={setPubCiphers}
              placeholder={t("outbox.itemSearchPlaceholder")}
              noResultsLabel={t("outbox.noResults")}
              removeLabel={t("outbox.removeSelected")}
              resultsLabel={t("outbox.itemLabel")}
              disabled={busy()}
            />
          </div>
          <div>
            <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="ob-contact">
              {t("outbox.contactLabel")}
            </label>
            <SearchableTagSelect
              id="ob-contact"
              options={contacts().filter((contact) => contact.has_wrap_key).map((contact) => ({ value: contact.identity_signing_pubkey, label: contact.display_name }))}
              values={pubContacts()}
              onChange={setPubContacts}
              placeholder={t("outbox.contactSearchPlaceholder")}
              noResultsLabel={t("outbox.noResults")}
              removeLabel={t("outbox.removeSelected")}
              resultsLabel={t("outbox.contactLabel")}
              disabled={busy()}
            />
          </div>
          <div>
            <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="ob-path">
              {t("outbox.pathLabel")}
            </label>
            <Input
              id="ob-path"
              value={pubPath()}
              onInput={(e) => setPubPath(e.currentTarget.value)}
              placeholder={t("outbox.pathPlaceholder")}
              disabled={busy()}
            />
            <p class="mt-1 text-[11px] leading-relaxed text-[var(--color-muted)]">{t("outbox.pathHint")}</p>
          </div>
          <Button onClick={publish} disabled={busy() || pubCiphers().length === 0 || pubContacts().length === 0 || !pubPath().trim()}>
            {busy() ? t("common.sending") : t("outbox.publishAction")}
          </Button>
        </div>
      </section>

      {/* Recipient: linked folders */}
      <section class="space-y-3">
        <h3 class="text-sm font-bold text-[var(--color-text)]">{t("outbox.receivedTitle")}</h3>

        <Show
          when={links().length > 0}
          fallback={<p class="text-xs text-[var(--color-muted)]">{t("outbox.linksEmpty")}</p>}
        >
          <div class="space-y-2">
            <For each={links()}>
              {(l) => (
                <div class="p-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] space-y-2">
                  <div class="flex items-center gap-3">
                    <div class="flex-1 min-w-0">
                      <p class="text-xs font-semibold text-[var(--color-text)] truncate">{l.owner_name}</p>
                      <p class="text-[11px] text-[var(--color-muted)] truncate">{l.path}</p>
                    </div>
                    <Button onClick={() => toggleEntries(l)}>
                      {openEntries() === l.outbox_id ? t("outbox.hideItems") : t("outbox.viewItems")}
                    </Button>
                    <Button variant="danger" onClick={() => setForgetTarget(l)}>
                      {t("outbox.forget")}
                    </Button>
                  </div>
                  <Show when={openEntries() === l.outbox_id}>
                    <div class="pl-3 border-l-2 border-[var(--color-border)] space-y-1">
                      <Show
                        when={entries().length > 0}
                        fallback={<p class="text-[11px] text-[var(--color-muted)]">{t("outbox.entriesEmpty")}</p>}
                      >
                        <For each={entries()}>
                          {(row) => (
                            <button
                              type="button"
                              onClick={() => openEntry(l.outbox_id, row)}
                              class="block w-full text-left text-xs text-[var(--color-text)] hover:text-[var(--color-primary)] cursor-pointer py-0.5"
                            >
                              {entryName(row.item)}
                            </button>
                          )}
                        </For>
                      </Show>
                    </div>
                  </Show>
                </div>
              )}
            </For>
          </div>
        </Show>

        <div class="p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-sidebar)] space-y-3">
          <h4 class="text-xs font-bold text-[var(--color-text)] uppercase">{t("outbox.linkTitle")}</h4>
          <div>
            <label class="block text-xs font-semibold text-[var(--color-muted)] mb-1" for="ob-link-path">
              {t("outbox.pathLabel")}
            </label>
            <Input
              id="ob-link-path"
              value={linkPath()}
              onInput={(e) => setLinkPath(e.currentTarget.value)}
              placeholder={t("outbox.pathPlaceholder")}
            />
          </div>
          <Button onClick={linkFolder} disabled={busy() || !linkPath().trim()}>
            {t("outbox.linkAction")}
          </Button>
        </div>
      </section>

      {/* Opened entry (view-only) */}
      <Show when={opened()}>
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setOpened(null)}>
          <FocusTrap containerRef={() => entryDialogRef} onEscape={() => setOpened(null)} />
          <div
            ref={entryDialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="ob-entry-title"
            class="w-[min(28rem,90vw)] max-h-[80vh] overflow-y-auto p-5 rounded-2xl bg-[var(--color-card)] border border-[var(--color-border)] space-y-3"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 id="ob-entry-title" class="text-sm font-bold text-[var(--color-text)]">{entryName(opened().item)}</h3>
            <p class="text-[11px] text-[var(--color-muted)]">
              {t("outbox.senderLabel")}: {opened().sender_name}
            </p>
            <Show when={loginData(opened().item)?.username}>
              <div>
                <p class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-0.5">{t("outbox.usernameLabel")}</p>
                <p class="text-xs text-[var(--color-text)] break-all">{loginData(opened().item).username}</p>
              </div>
            </Show>
            <Show when={loginData(opened().item)?.password}>
              <div>
                <p class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-0.5">{t("outbox.passwordLabel")}</p>
                <div class="flex items-center gap-2">
                  <code class="text-xs font-mono text-[var(--color-text)] break-all flex-1">
                    {"•".repeat(Math.min(loginData(opened().item).password.length, 12))}
                  </code>
                  <Button
                    onClick={async () => {
                      await copyToClipboard(loginData(opened().item).password);
                      toastSuccess(t("outbox.copiedToast"));
                    }}
                  >
                    {t("outbox.copySecret")}
                  </Button>
                </div>
              </div>
            </Show>
            <Show when={opened().item?.notes}>
              <div>
                <p class="text-[10px] font-bold text-[var(--color-muted)] uppercase mb-0.5">{t("outbox.notesLabel")}</p>
                <p class="text-xs text-[var(--color-text)] whitespace-pre-wrap break-words">{opened().item.notes}</p>
              </div>
            </Show>
            <div class="flex justify-end">
              <Button onClick={() => setOpened(null)}>{t("common.close")}</Button>
            </div>
          </div>
        </div>
      </Show>

      {/* Revoke mirror */}
      <Show when={revokeTarget()}>
        <ConfirmModal
          show
          idPrefix="ob-revoke"
          title={t("outbox.revokeTitle")}
          body={t("outbox.revokeBody")}
          confirmLabel={t("outbox.revoke")}
          confirmVariant="danger"
          onConfirm={revoke}
          onClose={() => setRevokeTarget(null)}
        />
      </Show>

      {/* Forget link */}
      <Show when={forgetTarget()}>
        <ConfirmModal
          show
          idPrefix="ob-forget"
          title={t("outbox.forgetTitle")}
          body={t("outbox.forgetBody")}
          confirmLabel={t("outbox.forget")}
          confirmVariant="danger"
          onConfirm={forget}
          onClose={() => setForgetTarget(null)}
        />
      </Show>
    </div>
  );
}
