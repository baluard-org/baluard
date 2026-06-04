import { createSignal, createEffect, onCleanup, Show, For } from "solid-js";
import { useVault } from "../context/VaultContext.jsx";
import { error } from "../context/errorSignal.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { getCuratedColor, getDomainInitials, uriStr } from "../lib/utils.js";
import { buildAttachDownloadPayload } from "../lib/payload.js";
import CopyableField from "./CopyableField.jsx";
import CardBrandDisplay from "./CardBrandDisplay.jsx";

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
    const totpUri = c.kind?.login?.totp_uri || c.totp_uri;
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
    const kind = c.kind || {};
    const loginData = kind.login || kind.Login || {};
    const cardData = kind.card || kind.Card || {};
    const idData = kind.identity || kind.Identity || {};
    const cipherType = c.type || "login";
    props.onEdit({
      name: c.name || "",
      cipherType,
      username: loginData.username || idData.username || "",
      password: loginData.password || "",
      uris: (loginData.uris || c.uris || []).map(u => typeof u === "string" ? { uri: u, match_strategy: null } : u),
      notes: c.notes || "",
      favorite: c.favorite || false,
      folder_id: c.folder_id || null,
      custom_fields: c.custom_fields || [],
      totp_uri: loginData.totp_uri || "",
      cardholder_name: cardData.cardholder_name || "",
      cardNumber: cardData.number || "",
      cardBrand: cardData.brand || "",
      expMonth: cardData.exp_month || "",
      expYear: cardData.exp_year || "",
      cvv: cardData.code || "",
      idTitle: idData.title || "",
      firstName: idData.first_name || "",
      middleName: idData.middle_name || "",
      lastName: idData.last_name || "",
      company: idData.company || "",
      email: idData.email || "",
      phone: idData.phone || "",
      address1: idData.address1 || "",
      address2: idData.address2 || "",
      address3: idData.address3 || "",
      city: idData.city || "",
      state: idData.state || "",
      postalCode: idData.postal_code || "",
      country: idData.country || "",
      ssn: idData.ssn || "",
      passportNumber: idData.passport_number || "",
      licenseNumber: idData.license_number || "",
      publicKey: (kind.sshKey || kind.SshKey || {}).public_key || "",
      privateKey: (kind.sshKey || kind.SshKey || {}).private_key || "",
      fingerprint: (kind.sshKey || kind.SshKey || {}).key_fingerprint || "",
      bankName: c.bank_name || "",
      nameOnAccount: c.name_on_account || "",
      accountType: c.account_type || "",
      accountNumber: c.account_number || "",
      routingNumber: c.routing_number || "",
      branchNumber: c.branch_number || "",
      bankPin: c.pin || "",
      swiftCode: c.swift_code || "",
      iban: c.iban || "",
      bankPhone: c.bank_contact_phone || "",
      dlFirstName: c.first_name || "",
      dlMiddleName: c.middle_name || "",
      dlLastName: c.last_name || "",
      dlDob: c.date_of_birth || "",
      dlNumber: c.license_number || "",
      dlCountry: c.issuing_country || "",
      dlState: c.issuing_state || "",
      dlIssueDate: c.issue_date || "",
      dlExpDate: c.expiration_date || "",
      dlAuthority: c.issuing_authority || "",
      dlClass: c.license_class || "",
      ppSurname: c.surname || "",
      ppGivenName: c.given_name || "",
      ppDob: c.date_of_birth || "",
      ppSex: c.sex || "",
      ppBirthPlace: c.birth_place || "",
      ppNationality: c.nationality || "",
      ppCountry: c.issuing_country || "",
      ppNumber: c.passport_number || "",
      ppType: c.passport_type || "",
      ppNationalId: c.national_identification_number || "",
      ppAuthority: c.issuing_authority || "",
      ppIssueDate: c.issue_date || "",
      ppExpDate: c.expiration_date || "",
      reprompt: c.reprompt || false,
    });
  }

  return (
    <div class="h-full flex flex-col justify-between">
      <div class="flex-1 overflow-y-auto p-8 space-y-6">
        {/* Title Header */}
        <div class="flex items-start gap-5 pb-6 border-b border-[var(--color-border)]">
          <div class={`w-16 h-16 rounded-2xl flex items-center justify-center text-white text-3xl font-extrabold shadow-lg ${getCuratedColor(cipher()?.name)}`}>
            {getDomainInitials(cipher()?.name)}
          </div>
          <div class="min-w-0 flex-1">
            <h3 class="text-2xl font-bold text-[var(--color-text)] truncate leading-tight select-all">{cipher()?.name || "Untitled"}</h3>
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] mt-2">
              <span class="w-1.5 h-1.5 bg-[var(--color-primary)] rounded-full"></span>
              {cipher()?.type === "card" ? "Card" : cipher()?.type === "identity" ? "Identity" : cipher()?.type === "secureNote" ? "Secure Note" : cipher()?.type === "sshKey" ? "SSH Key" : cipher()?.type === "bankAccount" ? "Bank Account" : cipher()?.type === "driversLicense" ? "Driver License" : cipher()?.type === "passport" ? "Passport & ID" : "Login"} Item
            </span>
          </div>
          <button
            onClick={props.onClose}
            class="p-2 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-xl transition-colors cursor-pointer"
            title="Close details"
          >
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>

        {/* Login credentials */}
        <Show when={cipher()?.type === "login" || (!cipher()?.type && cipher()?.username)}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Login credentials</h4>
            <CopyableField label={t("entry.user")} value={cipher()?.username || cipher()?.kind?.login?.username} />
            <CopyableField
              label={t("entry.pass")}
              value={cipher()?.password || cipher()?.kind?.login?.password}
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
                      onClick={() => { navigator.clipboard.writeText(totpCode()?.code || ""); setTotpCopied(true); setTimeout(() => setTotpCopied(false), 1500); }}
                      class="p-1.5 rounded-lg text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
                      title="Copy code"
                    >
                      <Show when={!totpCopied()} fallback={<span class="text-xs text-green-500">Copied</span>}>
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
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
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Card details</h4>
            <Show when={cipher()?.kind?.card?.brand}>
              <CardBrandDisplay number={cipher()?.kind?.card?.number || ""} />
            </Show>
            <CopyableField label="Cardholder" value={cipher()?.kind?.card?.cardholder_name} />
            <CopyableField label="Number" value={cipher()?.kind?.card?.number} />
            <CopyableField label="Expiration" value={cipher()?.kind?.card?.exp_month && cipher()?.kind?.card?.exp_year ? `${cipher()?.kind?.card?.exp_month}/${cipher()?.kind?.card?.exp_year}` : null} />
            <CopyableField label="CVV" value={cipher()?.kind?.card?.code} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Identity fields */}
        <Show when={cipher()?.type === "identity"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Identity details</h4>
            <CopyableField label="Full Name" value={[cipher()?.kind?.identity?.title, cipher()?.kind?.identity?.first_name, cipher()?.kind?.identity?.middle_name, cipher()?.kind?.identity?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label="Username" value={cipher()?.kind?.identity?.username} />
            <CopyableField label="Company" value={cipher()?.kind?.identity?.company} />
            <CopyableField label="Email" value={cipher()?.kind?.identity?.email} />
            <CopyableField label="Phone" value={cipher()?.kind?.identity?.phone} />
            <CopyableField label="Address" value={[cipher()?.kind?.identity?.address1, cipher()?.kind?.identity?.address2, cipher()?.kind?.identity?.address3].filter(Boolean).join(", ") || null} />
            <CopyableField label="City/State/Postal" value={[cipher()?.kind?.identity?.city, cipher()?.kind?.identity?.state, cipher()?.kind?.identity?.postal_code].filter(Boolean).join(", ") || null} />
            <CopyableField label="Country" value={cipher()?.kind?.identity?.country} />
            <CopyableField label="SSN" value={cipher()?.kind?.identity?.ssn} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="Passport #" value={cipher()?.kind?.identity?.passport_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="License #" value={cipher()?.kind?.identity?.license_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* SSH Key fields */}
        <Show when={cipher()?.type === "sshKey"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">SSH Key details</h4>
            <CopyableField label="Public Key" value={cipher()?.kind?.sshKey?.public_key} />
            <CopyableField label="Fingerprint" value={cipher()?.kind?.sshKey?.key_fingerprint} />
            <CopyableField label="Private Key" value={cipher()?.kind?.sshKey?.private_key} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Bank Account fields */}
        <Show when={cipher()?.type === "bankAccount"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Bank account details</h4>
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
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Driver license details</h4>
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
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Passport & ID details</h4>
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
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Website</h4>
            <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-between group hover:border-[var(--color-primary)] transition-all">
              <div class="min-w-0 flex-1">
                <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block">Website URL</label>
                <a
                  href={(() => { const u = uriStr(cipher()?.uris?.[0]); return u.startsWith("http") ? u : `https://${u}`; })()}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-sm text-[var(--color-accent)] hover:underline font-semibold mt-0.5 inline-block"
                >
                  {uriStr(cipher()?.uris?.[0])}
                </a>
              </div>
              <a
                href={(() => { const u = uriStr(cipher()?.uris?.[0]); return u.startsWith("http") ? u : `https://${u}`; })()}
                target="_blank"
                rel="noopener noreferrer"
                class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors"
                title="Launch website"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
              </a>
            </div>
          </div>
        </Show>

        {/* Custom Fields */}
        <Show when={cipher()?.custom_fields?.length > 0}>
          <div class="space-y-3 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Custom Fields</h4>
            <For each={cipher()?.custom_fields || []}>
              {(field) => {
                const isHidden = () => field.field_type === "Hidden";
                return (
                  <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
                    <label class="text-[10px] text-[var(--color-muted)] block uppercase tracking-wider font-extrabold">{field.name}</label>
                    <Show when={isHidden()} fallback={
                      <div class="text-sm text-[var(--color-text)] font-semibold mt-0.5 select-all">{field.value || "\u2014"}</div>
                    }>
                      <div class="text-sm font-mono text-[var(--color-text)] tracking-widest mt-0.5 select-all">{"\u2022".repeat(8)}</div>
                    </Show>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>

        {/* Notes group */}
        <Show when={cipher()?.notes}>
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">{t("entry.notes")}</h4>
            <div class="p-4 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] leading-relaxed font-semibold whitespace-pre-wrap select-text">
              {cipher()?.notes}
            </div>
          </div>
        </Show>

        {/* Attachments */}
        <Show when={cipher()?.attachments?.length > 0}>
          <div class="space-y-3 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Attachments</h4>
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
                      <svg class="w-4 h-4 text-[var(--color-muted)] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/></svg>
                      <div class="min-w-0">
                        <div class="text-sm font-semibold text-[var(--color-text)] truncate">{attach.filename}</div>
                        <div class="text-[10px] text-[var(--color-muted)]">{sizeStr()}</div>
                      </div>
                    </div>
                    <div class="flex items-center gap-1 shrink-0 ml-2">
                      <button onClick={handleDownload} class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer" title="Download">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
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
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                Edit
              </button>
              <button
                onClick={() => vault.archiveCipher(cipher().id, t)}
                class="py-3 px-4 rounded-xl bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] hover:bg-[var(--color-card)] font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"/></svg>
                {t("entry.archive")}
              </button>
              <button
                onClick={() => props.onDelete?.(cipher().id)}
                class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                {t("entry.delete")}
              </button>
            </>
          }>
            <button
              onClick={() => vault.unarchiveCipher(cipher().id, t).then(() => { props.setViewCipher(null); props.setActivePane("welcome"); })}
              class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.706 9H17"/></svg>
              {t("entry.unarchive")}
            </button>
            <button
              onClick={() => props.onDelete?.(cipher().id)}
              class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              {t("entry.delete")}
            </button>
          </Show>
        }>
          <button
            onClick={() => vault.restoreCipher(cipher().id, t).then(() => { props.setViewCipher(null); props.setActivePane("welcome"); })}
            class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.706 9H17"/></svg>
            {t("entry.restore")}
          </button>
          <button
            onClick={() => props.onDelete?.(cipher().id)}
            class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            {t("entry.deletePermanently")}
          </button>
        </Show>
      </div>
    </div>
  );
}
