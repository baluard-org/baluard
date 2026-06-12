import { createSignal, createEffect, onCleanup, Show, For } from "solid-js";
import { openUrl } from "@tauri-apps/plugin-opener";
import { cipherToFlat } from "../lib/cipherSchema.js";
import { useVault } from "../context/VaultContext.jsx";
import { useI18n } from "../i18n/index.jsx";
import { copyToClipboard } from "../lib/clipboard.js";
import { daemon } from "../lib/daemon.js";
import { toastError } from "../context/toastSignal.js";
import { uriStr, formatCardNumber } from "../lib/utils.js";
import { SECTION_LABEL } from "../lib/helpers.js";
import { buildAttachDownloadPayload } from "../lib/payload.js";
import { IconX, IconCopy, IconCheck, IconLinkSimple, IconDownload, IconPencil, IconArchive, IconTrash, IconRefresh, IconFingerprint } from "./Icon.jsx";
import CopyableField from "./CopyableField.jsx";
import CardBrandDisplay from "./CardBrandDisplay.jsx";
import CipherAvatar from "./CipherAvatar.jsx";

/** Small copy button for the notes header. Copies entire notes content. */
function CopyNotesButton(props) {
  const { t } = useI18n();
  const [copied, setCopied] = createSignal(false);
  async function handleCopy() {
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
    await copyToClipboard(props.value || "");
  }
  return (
    <button
      onClick={handleCopy}
      class="p-1.5 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer"
      title={t("entry.copyNotes")}
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
  const [showPasskeyDelete, setShowPasskeyDelete] = createSignal(null); // { cipher_id, credential_id, name, isOnlyAuth }

  async function deletePasskey() {
    const pk = showPasskeyDelete();
    if (!pk) return;
    try {
      await daemon("passkey.delete", JSON.stringify({ id: pk.cipher_id, credential_id: pk.credential_id }));
      setShowPasskeyDelete(null);
      await vault.refreshCiphers(t);
    } catch (e) {
      toastError(t("passkey.deleteError"));
    }
  }

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
            <h3 class="text-2xl font-bold text-[var(--color-text)] truncate leading-tight select-all">{cipher()?.name || t("entry.untitled")}</h3>
            <div class="flex flex-wrap items-center gap-2 mt-2">
              <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)]">
                <span class="w-1.5 h-1.5 bg-[var(--color-primary)] rounded-full"></span>
                {t("entry.itemType", { type: t("types." + (cipher()?.type || "login")) })}
              </span>
              <Show when={(vault.folders() || []).find(f => f.id === cipher()?.folder_id)}>
                <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)]">
                  <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" /></svg>
                  {(vault.folders() || []).find(f => f.id === cipher()?.folder_id)?.name}
                </span>
              </Show>
              <For each={cipher()?.tags || []}>
                {tag => (
                  <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-primary)]/10 text-[var(--color-primary)] border border-[var(--color-primary)]/20">
                    {tag}
                  </span>
                )}
              </For>
            </div>
          </div>
          <button
            onClick={props.onClose}
            class="p-2 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-xl transition-colors cursor-pointer"
            title={t("entry.close")}
          >
            <IconX class="w-6 h-6" />
          </button>
        </div>

        {/* Login credentials */}
        <Show when={cipher()?.type === "login" || (!cipher()?.type && cipher()?.username)}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>{t("types.login")}</h4>
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
                      onClick={async () => { await copyToClipboard(totpCode()?.code || ""); setTotpCopied(true); setTimeout(() => setTotpCopied(false), 1800); }}
                      class="p-1.5 rounded-lg text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
                      title={t("entry.copyCode")}
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

        {/* Passkeys section */}
        <Show when={(cipher()?.type === "login" || !cipher()?.type) && (cipher()?.fido2_credentials?.length > 0)}>
          <div class="space-y-3">
            <h4 class={SECTION_LABEL}>{t("passkey.sectionTitle")}</h4>
            <For each={cipher()?.fido2_credentials || []}>
              {(pk, i) => {
                const created = pk.creation_date ? new Date(pk.creation_date * 1000).toLocaleDateString() : "-";
                const isMissing = pk.private_key_missing;
                return (
                  <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] space-y-2">
                    <div class="flex items-center justify-between">
                      <div class="flex items-center gap-2 min-w-0">
                        <IconFingerprint class="w-4 h-4 text-[var(--color-primary)] shrink-0" />
                        <span class="text-sm font-semibold text-[var(--color-text)] truncate">{pk.name || pk.rp_name || pk.rp_id}</span>
                      </div>
                      <Show when={isMissing}>
                        <span class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-600 border border-amber-500/20">{t("passkey.imported")}</span>
                      </Show>
                    </div>
                    <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                      <div>
                        <span class="text-[var(--color-muted)]">{t("passkey.rp")}</span>
                        <p class="text-[var(--color-text)] font-mono truncate">{pk.rp_id}</p>
                      </div>
                      <Show when={pk.user_name}>
                        <div>
                          <span class="text-[var(--color-muted)]">{t("passkey.user")}</span>
                          <p class="text-[var(--color-text)] truncate">{pk.user_name}</p>
                        </div>
                      </Show>
                      <div>
                        <span class="text-[var(--color-muted)]">{t("passkey.counter")}</span>
                        <p class="text-[var(--color-text)]">{pk.counter}</p>
                      </div>
                      <div>
                        <span class="text-[var(--color-muted)]">{t("passkey.created")}</span>
                        <p class="text-[var(--color-text)]">{created}</p>
                      </div>
                    </div>
                    <Show when={isMissing}>
                      <p class="text-[10px] text-amber-600">{t("passkey.missingKeyWarning")}</p>
                    </Show>
                    <div class="flex justify-end pt-1">
                      <button
                        onClick={() => {
                          const c = cipher();
                          const fido2 = c?.fido2_credentials || [];
                          const hasPassword = !!c?.password;
                          const hasOtherPasskeys = fido2.length > 1;
                          setShowPasskeyDelete({
                            cipher_id: c.id || c._meta?.id,
                            credential_id: pk.credential_id,
                            name: pk.name || pk.rp_name || pk.rp_id,
                            isOnlyAuth: !hasPassword && !hasOtherPasskeys,
                          });
                        }}
                        class="text-xs text-red-500 hover:text-red-400 transition-colors cursor-pointer"
                      >{t("passkey.deleteBtn")}</button>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>

        {/* Passkey delete confirmation modal */}
        <Show when={showPasskeyDelete()}>
          {(() => {
            const pk = showPasskeyDelete();
            return (
              <div
                role="dialog"
                aria-modal="true"
                aria-labelledby="passkey-delete-title"
                class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
              >
                <div class="bg-[var(--color-sidebar)] border border-[var(--color-border)] rounded-2xl p-6 max-w-sm w-full shadow-2xl">
                  <h3 id="passkey-delete-title" class="text-lg font-bold text-[var(--color-text)] mb-2">{t("passkey.deleteTitle")}</h3>
                  <div class="text-sm text-[var(--color-muted)] mb-4 space-y-2">
                    <p>{t("passkey.deleteConfirm", { name: pk.name })}</p>
                    <Show when={pk.isOnlyAuth}>
                      <div class="p-3 rounded-xl bg-red-500/10 border border-red-500/20">
                        <p class="text-red-400 font-semibold text-xs mb-1">{t("passkey.deleteWarningTitle")}</p>
                        <p class="text-red-400/80 text-xs">{t("passkey.deleteOnlyAuth")}</p>
                      </div>
                    </Show>
                  </div>
                  <div class="flex gap-3">
                    <button
                      onClick={() => setShowPasskeyDelete(null)}
                      class="flex-1 py-2.5 rounded-xl border border-[var(--color-border)] text-sm font-semibold text-[var(--color-text)] hover:bg-[var(--color-card)] transition-colors cursor-pointer"
                    >{t("entry.cancel")}</button>
                    <button
                      onClick={deletePasskey}
                      class="flex-1 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-sm font-semibold transition-colors cursor-pointer"
                    >{t("passkey.deleteBtn")}</button>
                  </div>
                </div>
              </div>
            );
          })()}
        </Show>

        {/* Card fields */}
        <Show when={cipher()?.type === "card"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>{t("types.card")}</h4>
            <Show when={cipher()?.brand}>
              <CardBrandDisplay number={cipher()?.number || ""} />
            </Show>
            <CopyableField label={t("fields.cardholder")} value={cipher()?.cardholder_name} />
            <CopyableField label={t("fields.cardNumber")} value={formatCardNumber(cipher()?.number)} copyValue={cipher()?.number} />
            <CopyableField label={t("fields.expMonth") + " / " + t("fields.expYear")} value={cipher()?.exp_month && cipher()?.exp_year ? `${cipher()?.exp_month}/${cipher()?.exp_year}` : null} />
            <CopyableField label={t("fields.cvv")} value={cipher()?.code} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Identity fields */}
        <Show when={cipher()?.type === "identity"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>{t("types.identity")}</h4>
            <CopyableField label={t("fields.fullName")} value={[cipher()?.title, cipher()?.first_name, cipher()?.middle_name, cipher()?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label={t("fields.username")} value={cipher()?.username} />
            <CopyableField label={t("fields.company")} value={cipher()?.company} />
            <CopyableField label={t("fields.email")} value={cipher()?.email} />
            <CopyableField label={t("fields.phone")} value={cipher()?.phone} />
            <CopyableField label={t("fields.address")} value={[cipher()?.address1, cipher()?.address2, cipher()?.address3].filter(Boolean).join(", ") || null} />
            <CopyableField label={t("fields.cityStatePostal")} value={[cipher()?.city, cipher()?.state, cipher()?.postal_code].filter(Boolean).join(", ") || null} />
            <CopyableField label={t("fields.country")} value={cipher()?.country} />
            <CopyableField label={t("fields.ssn")} value={cipher()?.ssn} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label={t("fields.passportNumber")} value={cipher()?.passport_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label={t("fields.licenseNumber")} value={cipher()?.license_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* SSH Key fields */}
        <Show when={cipher()?.type === "sshKey"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>{t("types.sshKey")}</h4>
            <CopyableField label={t("fields.publicKey")} value={cipher()?.public_key} />
            <CopyableField label={t("fields.fingerprint")} value={cipher()?.fingerprint} />
            <CopyableField label={t("fields.privateKey")} value={cipher()?.private_key} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Bank Account fields */}
        <Show when={cipher()?.type === "bankAccount"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>{t("types.bankAccount")}</h4>
            <CopyableField label={t("fields.bankName")} value={cipher()?.bank_name} />
            <CopyableField label={t("fields.nameOnAccount")} value={cipher()?.name_on_account} />
            <CopyableField label={t("fields.accountType")} value={cipher()?.account_type} />
            <CopyableField label={t("fields.accountNumber")} value={cipher()?.account_number} />
            <CopyableField label={t("fields.routingNumber")} value={cipher()?.routing_number} />
            <CopyableField label={t("fields.branchNumber")} value={cipher()?.branch_number} />
            <CopyableField label={t("fields.swiftCode")} value={cipher()?.swift_code} />
            <CopyableField label={t("fields.iban")} value={cipher()?.iban} />
            <CopyableField label={t("fields.bankPhone")} value={cipher()?.bank_contact_phone} />
            <CopyableField label={t("fields.pin")} value={cipher()?.pin} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Driver License fields */}
        <Show when={cipher()?.type === "driversLicense"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>{t("types.driversLicense")}</h4>
            <CopyableField label={t("fields.fullName")} value={[cipher()?.first_name, cipher()?.middle_name, cipher()?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label={t("fields.dateOfBirth")} value={cipher()?.date_of_birth} />
            <CopyableField label={t("fields.licenseNumber")} value={cipher()?.license_number} />
            <CopyableField label={t("fields.issuingCountry")} value={cipher()?.issuing_country} />
            <CopyableField label={t("fields.issuingState")} value={cipher()?.issuing_state} />
            <CopyableField label={t("fields.issueDate")} value={cipher()?.issue_date} />
            <CopyableField label={t("fields.expirationDate")} value={cipher()?.expiration_date} />
            <CopyableField label={t("fields.issuingAuthority")} value={cipher()?.issuing_authority} />
            <CopyableField label={t("fields.licenseClass")} value={cipher()?.license_class} />
          </div>
        </Show>

        {/* Passport fields */}
        <Show when={cipher()?.type === "passport"}>
          <div class="space-y-4">
            <h4 class={SECTION_LABEL}>{t("types.passport")}</h4>
            <CopyableField label={t("fields.fullName")} value={[cipher()?.given_name, cipher()?.surname].filter(Boolean).join(" ") || null} />
            <CopyableField label={t("fields.dateOfBirth")} value={cipher()?.date_of_birth} />
            <CopyableField label={t("fields.sex")} value={cipher()?.sex} />
            <CopyableField label={t("fields.birthPlace")} value={cipher()?.birth_place} />
            <CopyableField label={t("fields.nationality")} value={cipher()?.nationality} />
            <CopyableField label={t("fields.issuingCountry")} value={cipher()?.issuing_country} />
            <CopyableField label={t("fields.passportNumber")} value={cipher()?.passport_number} />
            <CopyableField label={t("fields.passportType")} value={cipher()?.passport_type} />
            <CopyableField label={t("fields.nationalIdNumber")} value={cipher()?.national_identification_number} />
            <CopyableField label={t("fields.issuingAuthority")} value={cipher()?.issuing_authority} />
            <CopyableField label={t("fields.issueDate")} value={cipher()?.issue_date} />
            <CopyableField label={t("fields.expirationDate")} value={cipher()?.expiration_date} />
          </div>
        </Show>

        {/* Website URI group */}
        <Show when={cipher()?.uris?.length}>
          {(() => {
            const uri = () => uriStr(cipher()?.uris?.[0]);
            // L4 fix: only treat http(s) as already-prefixed URIs. mailto
            // has no // so it needs special handling. The previous regex
            // `/^(https?|mailto):\/\//` broke `mailto:user@example.com` by
            // prepending https://. The new check:
            //   - mailto:user@host   -> keep as-is (no https:// prefix)
            //   - http(s)://...      -> keep as-is
            //   - anything else       -> prepend https://
            const launchHref = () => {
              const u = uri();
              if (!u) return "";
              if (u.startsWith("mailto:")) return u;
              if (/^https?:\/\//i.test(u)) return u;
              return `https://${u}`;
            };
            const launch = (e) => { e.preventDefault(); openUrl(launchHref()); };
            return (
              <div class="space-y-4 pt-2">
                <h4 class={SECTION_LABEL}>{t("entry.uri")}</h4>
                <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-between group hover:border-[var(--color-primary)] transition-all">
                  <div class="min-w-0 flex-1">
                    <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block">{t("entry.uri")}</label>
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
                    title={t("entry.launchWebsite")}
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
            <h4 class={SECTION_LABEL}>{t("entry.customFields")}</h4>
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
                        {field.value === "true" ? t("entry.booleanYes") : t("entry.booleanNo")}
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
                  } catch(e) { alert(t("entry.downloadFailed") + ": " + e.message); }
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
                onClick={() => props.onArchive?.()}
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
