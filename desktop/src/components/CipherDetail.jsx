import { createSignal, createEffect, onCleanup, Show, For } from "solid-js";
import { openUrl } from "@tauri-apps/plugin-opener";
import { cipherToFlat } from "../lib/cipherSchema.js";
import { useVault } from "../context/VaultContext.jsx";
import { error } from "../context/errorSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { uriStr, formatCardNumber } from "../lib/utils.js";
import { SECTION_LABEL, typeLabel } from "../lib/helpers.js";
import { buildAttachDownloadPayload } from "../lib/payload.js";
import { IconX, IconCopy, IconCheck, IconLinkSimple, IconDownload, IconPencil, IconArchive, IconTrash, IconRefresh } from "./Icon.jsx";
import CopyableField from "./CopyableField.jsx";
import CardBrandDisplay from "./CardBrandDisplay.jsx";
import CipherAvatar from "./CipherAvatar.jsx";

/** Small copy button for the notes header. Copies entire notes content. */
function CopyNotesButton(props) {
  const [copied, setCopied] = createSignal(false);
  function handleCopy() {
    navigator.clipboard.writeText(props.value || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }
  return (
    <button
      onClick={handleCopy}
      class="p-1.5 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer"
      title="Copy notes"
    >
      <Show when={copied()} fallback={<IconCopy class="w-3.5 h-3.5" />}>
        <span class="copy-feedback"><IconCheck class="w-3.5 h-3.5 text-[var(--color-success)]" /></span>
      </Show>
    </button>
  );
}

export default function CipherDetail(props) {
  const vault = useVault();
  const { t } = useI18n();

  const [revealPass, setRevealPass] = createSignal(false);
  const [totpCode, setTotpCode] = createSignal(null);
  const [attachLoading, setAttachLoading] = createSignal(false);
  const [totpCopied, setTotpCopied] = createSignal(false);

  const cipher = () => props.cipher;

  // TOTP code auto-refresh timer (boundary-aligned)
  createEffect(() => {
    const c = cipher();
    if (!c) return;
    const totpUri = c.totp_uri;
    if (!totpUri || !c.id) {
      setTotpCode(null);
      return;
    }
    let active = true;
    let timer = null;
    const fetchCode = async () => {
      if (!active) return;
      try {
        const data = JSON.parse(await daemon("cipher.totp_code", c.id));
        if (active) {
          setTotpCode(data);
          if (data.expires_at) {
            const msLeft = data.expires_at * 1000 - Date.now();
            const delay = Math.max(200, msLeft + 200);
            timer = setTimeout(fetchCode, delay);
          } else {
            timer = setTimeout(fetchCode, 5000);
          }
        }
      } catch (e) {
        setTotpCode(null);
      }
    };
    fetchCode();
    onCleanup(() => { active = false; if (timer) clearTimeout(timer); });
  });

  function startEdit() {
    const c = cipher();
    if (!c) return;
    props.onEdit(cipherToFlat(c));
  }

  return (
    <div class="h-full flex flex-col justify-between">
      <div class="flex-1 overflow-y-auto p-8 space-y-6">
        {/* Title Header */}
        <div class="flex items-start gap-5 pb-6 border-b border-[var(--color-border)]">
          <CipherAvatar name={cipher()?.name} size="lg" uri={cipher()?.uris?.length ? uriStr(cipher()?.uris?.[0]) : null} />
          <div class="min-w-0 flex-1">
            <h3 class="text-2xl font-bold text-[var(--color-text)] truncate leading-tight select-all">{cipher()?.name || "Untitled"}</h3>
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] mt-2">
              <span class="w-1.5 h-1.5 bg-[var(--color-primary)] rounded-full"></span>
              {typeLabel(cipher()?.type)} Item
            </span>
          </div>
          <button
            onClick={props.onClose}
            class="p-2 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-xl transition-colors cursor-pointer"
            title="Close details"
          >
            <IconX class="w-6 h-6" />
          </button>
        </div>

        {/* Login credentials */}
        <Show when={cipher()?.type === "login" || (!cipher()?.type && cipher()?.username)}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>Login credentials</h4>
            <CopyableField label={t("entry.user")} value={cipher()?.username} />
            <CopyableField
              label={t("entry.pass")}
              value={cipher()?.password}
              isPassword={true}
              showPassword={revealPass()}
              onToggleShow={() => setRevealPass(!revealPass())}
            />

            {/* TOTP code widget */}
            <Show when={totpCode()}>
              <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
                <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block mb-2">Verification Code</label>
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <span class="text-2xl font-mono font-bold tracking-[0.3em] text-[var(--color-text)] select-all">{totpCode()?.code?.match(/.{1,3}/g)?.join(" ") || totpCode()?.code}</span>
                    <button
                      onClick={() => { navigator.clipboard.writeText(totpCode()?.code || ""); setTotpCopied(true); setTimeout(() => setTotpCopied(false), 1800); }}
                      class="p-1.5 rounded-lg text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
                      title="Copy code"
                    >
                      <Show when={!totpCopied()} fallback={<span class="copy-feedback"><IconCheck class="w-4 h-4 text-[var(--color-success)]" /></span>}>
                        <IconCopy class="w-4 h-4" />
                      </Show>
                    </button>
                  </div>
                  <span class="text-[10px] text-[var(--color-muted)]">{totpCode()?.period_seconds}s</span>
                </div>
              </div>
            </Show>
          </div>
        </Show>

        {/* Card fields */}
        <Show when={cipher()?.type === "card"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>Card details</h4>
            <Show when={cipher()?.brand}>
              <CardBrandDisplay number={cipher()?.number || ""} />
            </Show>
            <CopyableField label="Cardholder" value={cipher()?.cardholder_name} />
            <CopyableField label="Number" value={formatCardNumber(cipher()?.number)} copyValue={cipher()?.number} />
            <CopyableField label="Expiration" value={cipher()?.exp_month && cipher()?.exp_year ? `${cipher()?.exp_month}/${cipher()?.exp_year}` : null} />
            <CopyableField label="CVV" value={cipher()?.code} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Identity fields */}
        <Show when={cipher()?.type === "identity"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>Identity details</h4>
            <CopyableField label="Full Name" value={[cipher()?.title, cipher()?.first_name, cipher()?.middle_name, cipher()?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label="Username" value={cipher()?.username} />
            <CopyableField label="Company" value={cipher()?.company} />
            <CopyableField label="Email" value={cipher()?.email} />
            <CopyableField label="Phone" value={cipher()?.phone} />
            <CopyableField label="Address" value={[cipher()?.address1, cipher()?.address2, cipher()?.address3].filter(Boolean).join(", ") || null} />
            <CopyableField label="City/State/Postal" value={[cipher()?.city, cipher()?.state, cipher()?.postal_code].filter(Boolean).join(", ") || null} />
            <CopyableField label="Country" value={cipher()?.country} />
            <CopyableField label="SSN" value={cipher()?.ssn} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="Passport #" value={cipher()?.passport_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="License #" value={cipher()?.license_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* SSH Key fields */}
        <Show when={cipher()?.type === "sshKey"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>SSH Key details</h4>
            <CopyableField label="Public Key" value={cipher()?.public_key} />
            <CopyableField label="Fingerprint" value={cipher()?.fingerprint} />
            <CopyableField label="Private Key" value={cipher()?.private_key} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Bank Account fields */}
        <Show when={cipher()?.type === "bankAccount"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>Bank account details</h4>
            <CopyableField label="Bank Name" value={cipher()?.bank_name} />
            <CopyableField label="Name on Account" value={cipher()?.name_on_account} />
            <CopyableField label="Account Type" value={cipher()?.account_type} />
            <CopyableField label="Account Number" value={cipher()?.account_number} />
            <CopyableField label="Routing Number" value={cipher()?.routing_number} />
            <CopyableField label="Branch Number" value={cipher()?.branch_number} />
            <CopyableField label="SWIFT Code" value={cipher()?.swift_code} />
            <CopyableField label="IBAN" value={cipher()?.iban} />
            <CopyableField label="Bank Phone" value={cipher()?.bank_contact_phone} />
            <CopyableField label="PIN" value={cipher()?.pin} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Driver License fields */}
        <Show when={cipher()?.type === "driversLicense"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>Driver license details</h4>
            <CopyableField label="Full Name" value={[cipher()?.first_name, cipher()?.middle_name, cipher()?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label="Date of Birth" value={cipher()?.date_of_birth} />
            <CopyableField label="License Number" value={cipher()?.license_number} />
            <CopyableField label="Issuing Country" value={cipher()?.issuing_country} />
            <CopyableField label="Issuing State" value={cipher()?.issuing_state} />
            <CopyableField label="Issue Date" value={cipher()?.issue_date} />
            <CopyableField label="Expiration Date" value={cipher()?.expiration_date} />
            <CopyableField label="Issuing Authority" value={cipher()?.issuing_authority} />
            <CopyableField label="License Class" value={cipher()?.license_class} />
          </div>
        </Show>

        {/* Passport fields */}
        <Show when={cipher()?.type === "passport"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>Passport & ID details</h4>
            <CopyableField label="Full Name" value={[cipher()?.given_name, cipher()?.surname].filter(Boolean).join(" ") || null} />
            <CopyableField label="Date of Birth" value={cipher()?.date_of_birth} />
            <CopyableField label="Sex" value={cipher()?.sex} />
            <CopyableField label="Birth Place" value={cipher()?.birth_place} />
            <CopyableField label="Nationality" value={cipher()?.nationality} />
            <CopyableField label="Issuing Country" value={cipher()?.issuing_country} />
            <CopyableField label="Passport Number" value={cipher()?.passport_number} />
            <CopyableField label="Passport Type" value={cipher()?.passport_type} />
            <CopyableField label="National ID Number" value={cipher()?.national_identification_number} />
            <CopyableField label="Issuing Authority" value={cipher()?.issuing_authority} />
            <CopyableField label="Issue Date" value={cipher()?.issue_date} />
            <CopyableField label="Expiration Date" value={cipher()?.expiration_date} />
          </div>
        </Show>

        {/* Website URI group */}
        <Show when={cipher()?.uris?.length}>
          {(() => {
            const uri = () => uriStr(cipher()?.uris?.[0]);
            const launchHref = () => { const u = uri(); return u.startsWith("http") ? u : `https://${u}`; };
            const launch = (e) => { e.preventDefault(); openUrl(launchHref()); };
            return (
              <div class="space-y-4 pt-2">
                <h4 class={SECTION_LABEL}>Website</h4>
                <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-between group hover:border-[var(--color-primary)] transition-all">
                  <div class="min-w-0 flex-1">
                    <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block">Website URL</label>
                    <a
                      href={launchHref()}
                      onClick={launch}
                      target="_blank"
                      rel="noopener noreferrer"
                      class="text-sm text-[var(--color-accent)] hover:underline font-semibold mt-0.5 inline-block"
                    >
                      {uri()}
                    </a>
                  </div>
                  <a
                    href={launchHref()}
                    onClick={launch}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors"
                    title="Launch website"
                  >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
                  </a>
                </div>
              </div>
            );
          })()}
        </Show>

        {/* Custom Fields */}
        <Show when={cipher()?.custom_fields?.length > 0}>
          <div class="space-y-3 pt-2">
            <h4 class={SECTION_LABEL}>Custom Fields</h4>
            <For each={cipher()?.custom_fields || []}>
              {(field) => {
                const isHidden = () => field.field_type === "Hidden";
                const isBoolean = () => field.field_type === "Boolean";
                const [revealCustom, setRevealCustom] = createSignal(false);
                return (
                  <Show when={!isBoolean()} fallback={
                    <div class="flex items-center justify-between py-2">
                      <span class="text-sm text-[var(--color-text)]">{field.name}</span>
                      <span class={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full ${field.value === "true" ? "bg-emerald-500/15 text-emerald-400" : "bg-[var(--color-card)] text-[var(--color-muted)]"}`}>
                        <span class={`w-2 h-2 rounded-full ${field.value === "true" ? "bg-emerald-400" : "bg-[var(--color-muted)]"}`} />
                        {field.value === "true" ? "Yes" : "No"}
                      </span>
                    </div>
                  }>
                    <CopyableField
                      label={field.name}
                      value={field.value}
                      isPassword={isHidden()}
                      showPassword={revealCustom()}
                      onToggleShow={() => setRevealCustom(!revealCustom())}
                    />
                  </Show>
                );
              }}
            </For>
          </div>
        </Show>

        {/* Notes */}
        <Show when={cipher()?.notes}>
          <div class="space-y-4 pt-2">
            <h4 class={`${SECTION_LABEL} flex items-center justify-between`}>
              <span>{t("entry.notes")}</span>
              <CopyNotesButton value={cipher()?.notes || ""} />
            </h4>
            <div class="p-4 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] leading-relaxed font-semibold whitespace-pre-wrap select-text">
              {cipher()?.notes}
            </div>
          </div>
        </Show>

        {/* Attachments */}
        <Show when={cipher()?.attachments?.length > 0}>
          <div class="space-y-3 pt-2">
            <h4 class={SECTION_LABEL}>Attachments</h4>
            <For each={cipher()?.attachments || []}>
              {(attach) => {
                const sizeStr = () => {
                  const s = attach.size;
                  if (s > 1024*1024) return (s/(1024*1024)).toFixed(1) + " MB";
                  if (s > 1024) return (s/1024).toFixed(1) + " KB";
                  return s + " bytes";
                };
                async function handleDownload() {
                  try {
                    const result = await daemon("vault.attach_download", JSON.stringify(
                      buildAttachDownloadPayload(cipher().id, attach.id)
                    ));
                    const b64 = result.data_base64;
                    const binary = atob(b64);
                    const bytes = new Uint8Array(binary.length);
                    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                    const blob = new Blob([bytes]);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url; a.download = attach.filename; a.click();
                    URL.revokeObjectURL(url);
                  } catch(e) { alert("Download failed: " + e.message); }
                }
                return (
                  <div class="flex items-center justify-between p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
                    <div class="flex items-center gap-2 min-w-0">
                      <IconLinkSimple class="w-4 h-4 text-[var(--color-muted)] shrink-0" />
                      <div class="min-w-0">
                        <div class="text-sm font-semibold text-[var(--color-text)] truncate">{attach.filename}</div>
                        <div class="text-[10px] text-[var(--color-muted)]">{sizeStr()}</div>
                      </div>
                    </div>
                    <div class="flex items-center gap-1 shrink-0 ml-2">
                      <button onClick={handleDownload} class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer" title="Download">
                        <IconDownload class="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </div>

      {/* Footer Details Action bar */}
      <div class="p-6 bg-[var(--color-sidebar)] border-t border-[var(--color-border)] flex items-center justify-between gap-4">
        <Show when={props.selectedCategory === "Trash"} fallback={
          <Show when={props.selectedCategory === "Archive"} fallback={
            <>
              <button
                onClick={startEdit}
                class="flex-1 py-3 px-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <IconPencil class="w-4 h-4" />
                Edit
              </button>
              <button
                onClick={() => vault.archiveCipher(cipher().id, t)}
                class="py-3 px-4 rounded-xl bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] hover:bg-[var(--color-card)] font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <IconArchive class="w-4 h-4" />
                {t("entry.archive")}
              </button>
              <button
                onClick={() => props.onDelete?.(cipher().id)}
                class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <IconTrash class="w-4 h-4" />
                {t("entry.delete")}
              </button>
            </>
          }>
            <button
              onClick={() => vault.unarchiveCipher(cipher().id, t).then(() => { props.setViewCipher(null); props.setActivePane("welcome"); })}
              class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <IconRefresh class="w-4 h-4" />
              {t("entry.unarchive")}
            </button>
            <button
              onClick={() => props.onDelete?.(cipher().id)}
              class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <IconTrash class="w-4 h-4" />
              {t("entry.delete")}
            </button>
          </Show>
        }>
          <button
            onClick={() => vault.restoreCipher(cipher().id, t).then(() => { props.setViewCipher(null); props.setActivePane("welcome"); })}
            class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <IconRefresh class="w-4 h-4" />
            {t("entry.restore")}
          </button>
          <button
            onClick={() => props.onDelete?.(cipher().id)}
            class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <IconTrash class="w-4 h-4" />
            {t("entry.deletePermanently")}
          </button>
        </Show>
      </div>
    </div>
  );
}
