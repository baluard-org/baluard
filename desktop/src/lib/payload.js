// ── Payload builders for daemon IPC ──
//
// Rule: NEVER send null for fields the Rust backend expects as enum/struct.
// Send undefined (omitted from JSON) instead. Rust serde(default) handles missing keys.
// null ≠ missing and causes "expected value" errors.

/**
 * Build URIs array for login kind. Omit match_strategy when absent
 * so Rust serde(default) kicks in (UriMatchStrategy::Domain).
 */
export function buildUris(uris) {
  if (!uris || uris.length === 0) return [];
  return uris.map(u => {
    const obj = { uri: u.uri || u };
    if (u.match_strategy) obj.match_strategy = u.match_strategy;
    return obj;
  });
}

/**
 * Build the CipherKind tagged union object from form state.
 * { type: "login", data: { ... } }
 */
export function buildKind(c) {
  const cipherType = c.cipherType || "login";

  if (cipherType === "secureNote") {
    return { type: "secureNote", data: {} };
  }

  if (cipherType === "card") {
    return {
      type: "card",
      data: {
        cardholder_name: c.cardholder_name || null,
        number: c.cardNumber || null,
        brand: c.cardBrand || null,
        exp_month: c.expMonth || null,
        exp_year: c.expYear || null,
        code: c.cvv || null,
      },
    };
  }

  if (cipherType === "identity") {
    return {
      type: "identity",
      data: {
        title: c.idTitle || null,
        first_name: c.firstName || null,
        middle_name: c.middleName || null,
        last_name: c.lastName || null,
        username: c.username || null,
        company: c.company || null,
        email: c.email || null,
        phone: c.phone || null,
        address1: c.address1 || null,
        address2: c.address2 || null,
        address3: c.address3 || null,
        city: c.city || null,
        state: c.state || null,
        postal_code: c.postalCode || null,
        country: c.country || null,
        ssn: c.ssn || null,
        passport_number: c.passportNumber || null,
        license_number: c.licenseNumber || null,
      },
    };
  }

  if (cipherType === "sshKey") {
    return {
      type: "sshKey",
      data: {
        public_key: c.publicKey || null,
        private_key: c.privateKey || null,
        key_fingerprint: c.fingerprint || null,
      },
    };
  }

  if (cipherType === "bankAccount") {
    return {
      type: "bankAccount",
      data: {
        bank_name: c.bankName || null,
        name_on_account: c.nameOnAccount || null,
        account_type: c.accountType || null,
        account_number: c.accountNumber || null,
        routing_number: c.routingNumber || null,
        branch_number: c.branchNumber || null,
        pin: c.bankPin || null,
        swift_code: c.swiftCode || null,
        iban: c.iban || null,
        bank_contact_phone: c.bankPhone || null,
      },
    };
  }

  if (cipherType === "driversLicense") {
    return {
      type: "driversLicense",
      data: {
        first_name: c.dlFirstName || null,
        middle_name: c.dlMiddleName || null,
        last_name: c.dlLastName || null,
        date_of_birth: c.dlDob || null,
        license_number: c.dlNumber || null,
        issuing_country: c.dlCountry || null,
        issuing_state: c.dlState || null,
        issue_date: c.dlIssueDate || null,
        expiration_date: c.dlExpDate || null,
        issuing_authority: c.dlAuthority || null,
        license_class: c.dlClass || null,
      },
    };
  }

  if (cipherType === "passport") {
    return {
      type: "passport",
      data: {
        surname: c.ppSurname || null,
        given_name: c.ppGivenName || null,
        date_of_birth: c.ppDob || null,
        sex: c.ppSex || null,
        birth_place: c.ppBirthPlace || null,
        nationality: c.ppNationality || null,
        issuing_country: c.ppCountry || null,
        passport_number: c.ppNumber || null,
        passport_type: c.ppType || null,
        national_identification_number: c.ppNationalId || null,
        issuing_authority: c.ppAuthority || null,
        issue_date: c.ppIssueDate || null,
        expiration_date: c.ppExpDate || null,
      },
    };
  }

  // Login (default)
  return {
    type: "login",
    data: {
      username: c.username || null,
      password: c.password || null,
      uris: buildUris(c.uris),
      totp_uri: c.totp_uri || null,
    },
  };
}

/**
 * Build the full vault.add payload.
 */
export function buildAddPayload(c) {
  return {
    name: c.name,
    kind: buildKind(c),
    favorite: c.favorite || false,
    notes: c.notes || null,
    folder_id: c.folder_id || null,
    custom_fields: c.custom_fields || [],
  };
}

/**
 * Build the full vault.update payload.
 */
export function buildUpdatePayload(id, c) {
  return {
    id,
    name: c.name,
    kind: buildKind(c),
    favorite: c.favorite || false,
    notes: c.notes || null,
    folder_id: c.folder_id || null,
    custom_fields: c.custom_fields || [],
  };
}

/**
 * Build vault.get payload.
 */
export function buildGetPayload(id) {
  return { id, decrypt: true };
}

/**
 * Build settings.set payload.
 */
export function buildSettingsPayload(key, value) {
  return { [key]: value };
}

/**
 * Build vault.create payload.
 */
export function buildCreatePayload(password, profile = "desktop_std") {
  return { password, profile };
}

/**
 * Build vault.import payload.
 */
export function buildImportPayload(format, data) {
  return { format, data };
}

/**
 * Build vault.export payload.
 */
export function buildExportPayload(format) {
  return { format };
}

/**
 * Build vault.attach_download payload.
 */
export function buildAttachDownloadPayload(cipherId, attachmentId) {
  return { cipher_id: cipherId, attachment_id: attachmentId };
}

/**
 * Build folder.create payload.
 */
export function buildFolderCreatePayload(name, parentId) {
  const p = { name };
  if (parentId) p.parent_id = parentId;
  return p;
}

/**
 * Build vault.biometric_enable payload.
 */
export function buildBiometricEnablePayload(password) {
  return { password };
}
