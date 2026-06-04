import { createSignal, createEffect, onCleanup, Show, For } from "solid-js";
import { useApp } from "../context/AppContext.jsx";
import { useActions } from "../hooks/useActions.js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { getCuratedColor, getDomainInitials, uriStr } from "../lib/utils.js";
import { buildAttachDownloadPayload } from "../lib/payload.js";
import CopyableField from "./CopyableField.jsx";
import CardBrandDisplay from "./CardBrandDisplay.jsx";

export default function CipherDetail() {
  const { viewCipher, setViewCipher, setActivePane, setNewCipher, setShowDeleteConfirm, setShowReprompt, setRepromptCallback, selectedCategory } = useApp();
  const { restoreCipher, archiveCipher, unarchiveCipher } = useActions();
  const { t } = useI18n();

  const [revealPass, setRevealPass] = createSignal(false);
  const [totpCode, setTotpCode] = createSignal(null); // { code, period_seconds, expires_at }
  const [attachLoading, setAttachLoading] = createSignal(false);
  const [totpCopied, setTotpCopied] = createSignal(false);

  // TOTP code auto-refresh timer (boundary-aligned)
  createEffect(() => {
    const cipher = viewCipher();
    if (!cipher) return;
    const totpUri = cipher.kind?.login?.totp_uri || cipher.totp_uri;
    if (!totpUri || !cipher.id) {
      setTotpCode(null);
      return;
    }
    let active = true;
    let timer = null;
    const fetchCode = async () => {
      if (!active) return;
      try {
        const data = JSON.parse(await daemon("cipher.totp_code", cipher.id));
        if (active) {
          setTotpCode(data);
          // Schedule next fetch just after window boundary
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
    const c = viewCipher();
    if (!c) return;
    const kind = c.kind || {};
    const isTagged = typeof kind.type === "string" && kind.data !== undefined;
    const loginData = isTagged && kind.type === "login" ? kind.data : (kind.login || kind.Login || {});
    const cardData = isTagged && kind.type === "card" ? kind.data : (kind.card || kind.Card || {});
    const idData = isTagged && kind.type === "identity" ? kind.data : (kind.identity || kind.Identity || {});
    const sshData = isTagged && kind.type === "sshKey" ? kind.data : (kind.sshKey || kind.SshKey || {});
    const cipherType = c.type || "login";
    setNewCipher({
      name: c.name || "",
      cipherType,
      username: c.username || loginData.username || idData.username || "",
      password: c.password || loginData.password || "",
      uris: (c.uris || loginData.uris || []).map(u => typeof u === "string" ? { uri: u, match_strategy: null } : u),
      notes: c.notes || "",
      favorite: c.favorite || false,
      folder_id: c.folder_id || null,
      custom_fields: c.custom_fields || [],
      totp_uri: c.totp_uri || loginData.totp_uri || "",
      // Card fields
      cardholder: c.cardholder_name || cardData.cardholder_name || "",
      cardNumber: c.number || cardData.number || "",
      cardBrand: c.brand || cardData.brand || "",
      expMonth: c.exp_month || cardData.exp_month || "",
      expYear: c.exp_year || cardData.exp_year || "",
      cvv: c.code || cardData.code || "",
      // Identity fields
      idTitle: idData.title || c.title || "",
      firstName: idData.first_name || c.first_name || "",
      middleName: idData.middle_name || c.middle_name || "",
      lastName: idData.last_name || c.last_name || "",
      company: idData.company || c.company || "",
      email: idData.email || c.email || "",
      phone: idData.phone || c.phone || "",
      address1: idData.address1 || c.address1 || "",
      address2: idData.address2 || c.address2 || "",
      address3: idData.address3 || c.address3 || "",
      city: idData.city || c.city || "",
      state: idData.state || c.state || "",
      postalCode: idData.postal_code || c.postalCode || c.postal_code || "",
      country: idData.country || c.country || "",
      ssn: idData.ssn || c.ssn || "",
      passportNumber: idData.passport_number || c.passport_number || "",
      licenseNumber: idData.license_number || c.license_number || "",
      // SSH Key fields
      publicKey: sshData.public_key || c.public_key || "",
      privateKey: sshData.private_key || c.private_key || "",
      fingerprint: sshData.key_fingerprint || c.fingerprint || "",
      // Bank Account fields
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
      // Driver License fields
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
      // Passport fields
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
    });
    setActivePane("edit");
  }

  return (
    <div class="h-full flex flex-col justify-between">
      <div class="flex-1 overflow-y-auto p-8 space-y-6">
        {/* Title Header */}
        <div class="flex items-start gap-5 pb-6 border-b border-[var(--color-border)]">
          <div class={`w-16 h-16 rounded-2xl flex items-center justify-center text-white text-3xl font-extrabold shadow-lg ${getCuratedColor(viewCipher()?.name)}`}>
            {getDomainInitials(viewCipher()?.name)}
          </div>
          <div class="min-w-0 flex-1">
            <h3 class="text-2xl font-bold text-[var(--color-text)] truncate leading-tight select-all">{viewCipher()?.name || "Untitled"}</h3>
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] mt-2">
              <span class="w-1.5 h-1.5 bg-[var(--color-primary)] rounded-full"></span>
              {viewCipher()?.type === "card" ? "Card" : viewCipher()?.type === "identity" ? "Identity" : viewCipher()?.type === "secureNote" ? "Secure Note" : viewCipher()?.type === "sshKey" ? "SSH Key" : viewCipher()?.type === "bankAccount" ? "Bank Account" : viewCipher()?.type === "driversLicense" ? "Driver License" : viewCipher()?.type === "passport" ? "Passport & ID" : "Login"} Item
            </span>
          </div>
          <button
            onClick={() => setActivePane("welcome")}
            class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-lg border border-transparent hover:border-[var(--color-border)] transition-all cursor-pointer flex items-center justify-center"
            title="Close details"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>

        {/* Login credentials */}
        <Show when={viewCipher()?.type === "login" || (!viewCipher()?.type && viewCipher()?.username)}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Login credentials</h4>
            <CopyableField label={t("entry.user")} value={viewCipher()?.username || viewCipher()?.kind?.login?.username} />
            <CopyableField
              label={t("entry.pass")}
              value={viewCipher()?.password || viewCipher()?.kind?.login?.password}
              isPassword={true}
              showPassword={revealPass()}
              onToggleShow={() => {
                if (!revealPass() && (viewCipher()?.reprompt || viewCipher()?._meta?.reprompt)) {
                  setRepromptCallback(() => () => setRevealPass(true));
                  setShowReprompt(true);
                } else {
                  setRevealPass(!revealPass());
                }
              }}
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
        <Show when={viewCipher()?.type === "card"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Card details</h4>
            <Show when={viewCipher()?.kind?.card?.brand}>
              <CardBrandDisplay number={viewCipher()?.kind?.card?.number || ""} />
            </Show>
            <CopyableField label="Cardholder" value={viewCipher()?.kind?.card?.cardholder_name} />
            <CopyableField label="Number" value={viewCipher()?.kind?.card?.number} />
            <CopyableField label="Expiration" value={viewCipher()?.kind?.card?.exp_month && viewCipher()?.kind?.card?.exp_year ? `${viewCipher()?.kind?.card?.exp_month}/${viewCipher()?.kind?.card?.exp_year}` : null} />
            <CopyableField label="CVV" value={viewCipher()?.kind?.card?.code} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Identity fields */}
        <Show when={viewCipher()?.type === "identity"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Identity details</h4>
            <CopyableField label="Full Name" value={[viewCipher()?.kind?.identity?.title, viewCipher()?.kind?.identity?.first_name, viewCipher()?.kind?.identity?.middle_name, viewCipher()?.kind?.identity?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label="Username" value={viewCipher()?.kind?.identity?.username} />
            <CopyableField label="Company" value={viewCipher()?.kind?.identity?.company} />
            <CopyableField label="Email" value={viewCipher()?.kind?.identity?.email} />
            <CopyableField label="Phone" value={viewCipher()?.kind?.identity?.phone} />
            <CopyableField label="Address" value={[viewCipher()?.kind?.identity?.address1, viewCipher()?.kind?.identity?.address2, viewCipher()?.kind?.identity?.address3].filter(Boolean).join(", ") || null} />
            <CopyableField label="City/State/Postal" value={[viewCipher()?.kind?.identity?.city, viewCipher()?.kind?.identity?.state, viewCipher()?.kind?.identity?.postal_code].filter(Boolean).join(", ") || null} />
            <CopyableField label="Country" value={viewCipher()?.kind?.identity?.country} />
            <CopyableField label="SSN" value={viewCipher()?.kind?.identity?.ssn} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="Passport #" value={viewCipher()?.kind?.identity?.passport_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="License #" value={viewCipher()?.kind?.identity?.license_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* SSH Key fields */}
        <Show when={viewCipher()?.type === "sshKey"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">SSH Key details</h4>
            <CopyableField label="Public Key" value={viewCipher()?.kind?.sshKey?.public_key} />
            <CopyableField label="Fingerprint" value={viewCipher()?.kind?.sshKey?.key_fingerprint} />
            <CopyableField label="Private Key" value={viewCipher()?.kind?.sshKey?.private_key} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Bank Account fields */}
        <Show when={viewCipher()?.type === "bankAccount"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Bank account details</h4>
            <CopyableField label="Bank Name" value={viewCipher()?.bank_name} />
            <CopyableField label="Name on Account" value={viewCipher()?.name_on_account} />
            <CopyableField label="Account Type" value={viewCipher()?.account_type} />
            <CopyableField label="Account Number" value={viewCipher()?.account_number} />
            <CopyableField label="Routing Number" value={viewCipher()?.routing_number} />
            <CopyableField label="Branch Number" value={viewCipher()?.branch_number} />
            <CopyableField label="SWIFT Code" value={viewCipher()?.swift_code} />
            <CopyableField label="IBAN" value={viewCipher()?.iban} />
            <CopyableField label="Bank Phone" value={viewCipher()?.bank_contact_phone} />
            <CopyableField label="PIN" value={viewCipher()?.pin} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Driver License fields */}
        <Show when={viewCipher()?.type === "driversLicense"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Driver license details</h4>
            <CopyableField label="Full Name" value={[viewCipher()?.first_name, viewCipher()?.middle_name, viewCipher()?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label="Date of Birth" value={viewCipher()?.date_of_birth} />
            <CopyableField label="License Number" value={viewCipher()?.license_number} />
            <CopyableField label="Issuing Country" value={viewCipher()?.issuing_country} />
            <CopyableField label="Issuing State" value={viewCipher()?.issuing_state} />
            <CopyableField label="Issue Date" value={viewCipher()?.issue_date} />
            <CopyableField label="Expiration Date" value={viewCipher()?.expiration_date} />
            <CopyableField label="Issuing Authority" value={viewCipher()?.issuing_authority} />
            <CopyableField label="License Class" value={viewCipher()?.license_class} />
          </div>
        </Show>

        {/* Passport fields */}
        <Show when={viewCipher()?.type === "passport"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Passport & ID details</h4>
            <CopyableField label="Full Name" value={[viewCipher()?.given_name, viewCipher()?.surname].filter(Boolean).join(" ") || null} />
            <CopyableField label="Date of Birth" value={viewCipher()?.date_of_birth} />
            <CopyableField label="Sex" value={viewCipher()?.sex} />
            <CopyableField label="Birth Place" value={viewCipher()?.birth_place} />
            <CopyableField label="Nationality" value={viewCipher()?.nationality} />
            <CopyableField label="Issuing Country" value={viewCipher()?.issuing_country} />
            <CopyableField label="Passport Number" value={viewCipher()?.passport_number} />
            <CopyableField label="Passport Type" value={viewCipher()?.passport_type} />
            <CopyableField label="National ID Number" value={viewCipher()?.national_identification_number} />
            <CopyableField label="Issuing Authority" value={viewCipher()?.issuing_authority} />
            <CopyableField label="Issue Date" value={viewCipher()?.issue_date} />
            <CopyableField label="Expiration Date" value={viewCipher()?.expiration_date} />
          </div>
        </Show>

        {/* Website URI group */}
        <Show when={viewCipher()?.uris?.length}>
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Website</h4>
            <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-between group hover:border-[var(--color-primary)] transition-all">
              <div class="min-w-0 flex-1">
                <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block">Website URL</label>
                <a
                  href={(() => { const u = uriStr(viewCipher()?.uris?.[0]); return u.startsWith("http") ? u : `https://${u}`; })()}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-sm text-[var(--color-accent)] hover:underline font-semibold mt-0.5 inline-block"
                >
                  {uriStr(viewCipher()?.uris?.[0])}
                </a>
              </div>
              <a
                href={(() => { const u = uriStr(viewCipher()?.uris?.[0]); return u.startsWith("http") ? u : `https://${u}`; })()}
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
        <Show when={viewCipher()?.custom_fields?.length > 0}>
          <div class="space-y-3 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Custom Fields</h4>
            <For each={viewCipher()?.custom_fields || []}>
              {(field) => {
                const isLinked = () => typeof field.field_type === "object" && field.field_type?.Linked;
                const isHidden = () => field.field_type === "Hidden";
                const linkedType = () => isLinked() ? field.field_type.Linked : "";
                const resolved = () => {
                  if (isLinked()) {
                    const lt = linkedType();
                    const c = viewCipher();
                    if (!c) return field.value || "";
                    const map = {
                      LoginUsername: c.username, LoginPassword: c.password,
                      CardCardholderName: c.cardholder_name, CardNumber: c.number, CardExpMonth: c.exp_month, CardExpYear: c.exp_year, CardCvv: c.code,
                      IdentityTitle: c.title, IdentityFirstName: c.first_name, IdentityMiddleName: c.middle_name, IdentityLastName: c.last_name, IdentityUsername: c.username, IdentityCompany: c.company, IdentityEmail: c.email, IdentityPhone: c.phone, IdentityAddress1: c.address1, IdentityAddress2: c.address2, IdentityAddress3: c.address3, IdentityCity: c.city, IdentityState: c.state, IdentityPostalCode: c.postal_code, IdentityCountry: c.country,
                      BankAccountBankName: c.bank_name, BankAccountNameOnAccount: c.name_on_account, BankAccountAccountType: c.account_type, BankAccountAccountNumber: c.account_number, BankAccountRoutingNumber: c.routing_number, BankAccountBranchNumber: c.branch_number, BankAccountPin: c.pin, BankAccountSwiftCode: c.swift_code, BankAccountIban: c.iban, BankAccountBankContactPhone: c.bank_contact_phone,
                      DriversLicenseFirstName: c.first_name, DriversLicenseMiddleName: c.middle_name, DriversLicenseLastName: c.last_name, DriversLicenseDateOfBirth: c.date_of_birth, DriversLicenseLicenseNumber: c.license_number, DriversLicenseIssuingCountry: c.issuing_country, DriversLicenseIssuingState: c.issuing_state, DriversLicenseIssueDate: c.issue_date, DriversLicenseExpirationDate: c.expiration_date, DriversLicenseIssuingAuthority: c.issuing_authority, DriversLicenseLicenseClass: c.license_class,
                      PassportSurname: c.surname, PassportGivenName: c.given_name, PassportDateOfBirth: c.date_of_birth, PassportSex: c.sex, PassportBirthPlace: c.birth_place, PassportNationality: c.nationality, PassportIssuingCountry: c.issuing_country, PassportPassportNumber: c.passport_number, PassportPassportType: c.passport_type, PassportNationalIdNumber: c.national_identification_number, PassportIssuingAuthority: c.issuing_authority, PassportIssueDate: c.issue_date, PassportExpirationDate: c.expiration_date,
                    };
                    return map[lt] || "(linked field)";
                  }
                  return field.value || "";
                };
                return (
                  <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
                    <label class="text-[10px] text-[var(--color-muted)] block uppercase tracking-wider font-extrabold">{field.name}{isLinked() ? " (linked)" : ""}</label>
                    <Show when={isHidden()} fallback={
                      <div class="text-sm text-[var(--color-text)] font-semibold mt-0.5 select-all">{resolved() || "\u2014"}</div>
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
        <Show when={viewCipher()?.notes}>
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">{t("entry.notes")}</h4>
            <div class="p-4 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] leading-relaxed font-semibold whitespace-pre-wrap select-text">
              {viewCipher()?.notes}
            </div>
          </div>
        </Show>

        {/* Attachments */}
        <Show when={viewCipher()?.attachments?.length > 0}>
          <div class="space-y-3 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Attachments</h4>
            <For each={viewCipher()?.attachments || []}>
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
                      buildAttachDownloadPayload(viewCipher().id, attach.id)
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
        <Show when={selectedCategory() === "Trash"} fallback={
          <Show when={selectedCategory() === "Archive"} fallback={
            <>
              <button
                onClick={startEdit}
                class="flex-1 py-3 px-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                Edit
              </button>
              <button
                onClick={() => archiveCipher(viewCipher().id)}
                class="py-3 px-4 rounded-xl bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] hover:bg-[var(--color-card)] font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"/></svg>
                {t("entry.archive")}
              </button>
              <button
                onClick={() => setShowDeleteConfirm(true)}
                class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                {t("entry.delete")}
              </button>
            </>
          }>
            {/* Archive category: Unarchive + Delete (moves to trash) */}
            <button
              onClick={() => unarchiveCipher(viewCipher().id)}
              class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.706 9H17"/></svg>
              {t("entry.unarchive")}
            </button>
            <button
              onClick={() => setShowDeleteConfirm(true)}
              class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              {t("entry.delete")}
            </button>
          </Show>
        }>
          <button
            onClick={() => restoreCipher(viewCipher().id, t)}
            class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.706 9H17"/></svg>
            {t("entry.restore")}
          </button>
          <button
            onClick={() => setShowDeleteConfirm(true)}
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
