/**
 * Cipher type schemas — single source of truth for field definitions.
 * Used by: CipherDetail.startEdit (fromKind), payload.buildKind (toKind),
 * AddEditCipherForm (field rendering).
 */

/**
 * Each schema defines:
 * - fields: array of { key, label, placeholder?, type?, mono?, sensitive?, options? }
 * - fromKind(kind): structured daemon response → flat buffer keys
 * - toKind(flat): flat buffer → structured { type, data } for payload
 */
export const CIPHER_SCHEMAS = {
  login: {
    typeKey: "login",
    fields: [
      { key: "username", label: "entry.user", placeholder: "entry.usernamePlaceholder" },
      { key: "password", label: "entry.pass", placeholder: "entry.passwordPlaceholder", type: "password" },
      { key: "totp_uri", label: "fields.totpUri", placeholder: "otpauth://totp/...", mono: true },
    ],
    fromKind(kind) {
      const d = kind.data || kind.login || kind.Login || {};
      return {
        username: d.username || "",
        password: d.password || "",
        uris: (d.uris || []).map(u => typeof u === "string" ? { uri: u, match_strategy: null } : u),
        totp_uri: d.totp_uri || "",
        favicon: d.favicon || null,
        // Fields the edit form does not render: carried through so an edit
        // cannot silently reset them (fido2_credentials and password
        // history survive edits in the core merge; these do not).
        password_revision_date: d.password_revision_date ?? null,
        autofill_on_page_load: d.autofill_on_page_load ?? null,
      };
    },
    toKind(flat) {
      const data = {
        username: flat.username || null,
        password: flat.password || null,
        uris: flat.uris?.length ? flat.uris : [],
        totp_uri: flat.totp_uri || null,
        password_revision_date: flat.password_revision_date ?? null,
        autofill_on_page_load: flat.autofill_on_page_load ?? null,
      };
      // Persist favicon only when present (opt-in fetch at add/edit time).
      if (flat.favicon) data.favicon = flat.favicon;
      return { type: "login", data };
    },
  },

  card: {
    typeKey: "card",
    fields: [
      { key: "cardholder_name", label: "fields.cardholder", placeholder: "Full name on card" },
      { key: "cardNumber", label: "fields.cardNumber", placeholder: "1234 5678 9012 3456", mono: true },
      { key: "expMonth", label: "fields.expMonth", placeholder: "MM", type: "select", options: ["01","02","03","04","05","06","07","08","09","10","11","12"] },
      { key: "expYear", label: "fields.expYear", placeholder: "2028", mono: true },
      { key: "cvv", label: "fields.cvv", placeholder: "123", type: "password", mono: true },
    ],
    fromKind(kind) {
      const d = kind.data || kind.card || kind.Card || {};
      return {
        cardholder_name: d.cardholder_name || "",
        cardNumber: d.number || "",
        cardBrand: d.brand || "",
        expMonth: d.exp_month || "",
        expYear: d.exp_year || "",
        cvv: d.code || "",
      };
    },
    toKind(flat) {
      return {
        type: "card",
        data: {
          cardholder_name: flat.cardholder_name || null,
          number: flat.cardNumber || null,
          brand: flat.cardBrand || null,
          exp_month: flat.expMonth || null,
          exp_year: flat.expYear || null,
          code: flat.cvv || null,
        },
      };
    },
  },

  identity: {
    typeKey: "identity",
    fields: [
      { key: "idTitle", label: "fields.title", type: "select", options: ["Mr","Mrs","Ms","Dr"] },
      { key: "firstName", label: "fields.firstName", placeholder: "John" },
      { key: "middleName", label: "fields.middleName", placeholder: "A" },
      { key: "lastName", label: "fields.lastName", placeholder: "Doe" },
      { key: "username", label: "fields.username", placeholder: "johndoe" },
      { key: "company", label: "fields.company", placeholder: "Acme Inc" },
      { key: "email", label: "fields.email", placeholder: "john@example.com", type: "email" },
      { key: "phone", label: "fields.phone", placeholder: "+1 555 123 4567" },
      { key: "address1", label: "fields.address1", placeholder: "123 Main St" },
      { key: "address2", label: "fields.address2", placeholder: "Apt 4B" },
      { key: "address3", label: "fields.address3", placeholder: "Care of" },
      { key: "city", label: "fields.city", placeholder: "New York" },
      { key: "state", label: "fields.state", placeholder: "NY" },
      { key: "postalCode", label: "fields.postalCode", placeholder: "10001" },
      { key: "country", label: "fields.country", placeholder: "US" },
      { key: "ssn", label: "fields.ssn", placeholder: "123-45-6789", type: "password", mono: true },
      { key: "passportNumber", label: "fields.passportNumber", placeholder: "AB1234567", type: "password", mono: true },
      { key: "licenseNumber", label: "fields.licenseNumber", placeholder: "D123-456-78-901", type: "password", mono: true },
    ],
    layout: [
      ["idTitle", "firstName", "middleName", "lastName"],
      ["username", "company"],
      ["email", "phone"],
      ["address1"],
      ["address2"],
      ["address3"],
      ["city", "state", "postalCode", "country"],
      ["ssn", "passportNumber", "licenseNumber"],
    ],
    fromKind(kind) {
      const d = kind.data || kind.identity || kind.Identity || {};
      return {
        idTitle: d.title || "",
        firstName: d.first_name || "",
        middleName: d.middle_name || "",
        lastName: d.last_name || "",
        username: d.username || "",
        company: d.company || "",
        email: d.email || "",
        phone: d.phone || "",
        address1: d.address1 || "",
        address2: d.address2 || "",
        address3: d.address3 || "",
        city: d.city || "",
        state: d.state || "",
        postalCode: d.postal_code || "",
        country: d.country || "",
        ssn: d.ssn || "",
        passportNumber: d.passport_number || "",
        licenseNumber: d.license_number || "",
      };
    },
    toKind(flat) {
      return {
        type: "identity",
        data: {
          title: flat.idTitle || null,
          first_name: flat.firstName || null,
          middle_name: flat.middleName || null,
          last_name: flat.lastName || null,
          username: flat.username || null,
          company: flat.company || null,
          email: flat.email || null,
          phone: flat.phone || null,
          address1: flat.address1 || null,
          address2: flat.address2 || null,
          address3: flat.address3 || null,
          city: flat.city || null,
          state: flat.state || null,
          postal_code: flat.postalCode || null,
          country: flat.country || null,
          ssn: flat.ssn || null,
          passport_number: flat.passportNumber || null,
          license_number: flat.licenseNumber || null,
        },
      };
    },
  },

  sshKey: {
    typeKey: "sshKey",
    fields: [
      { key: "publicKey", label: "fields.publicKey", placeholder: "ssh-rsa AAAA...", type: "textarea", mono: true },
      { key: "privateKey", label: "fields.privateKey", placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----", type: "textarea", mono: true, rows: 6 },
      { key: "fingerprint", label: "fields.fingerprint", placeholder: "SHA256:abc123...", mono: true },
    ],
    fromKind(kind) {
      const d = kind.data || kind.sshKey || kind.SshKey || {};
      return {
        publicKey: d.public_key || "",
        privateKey: d.private_key || "",
        fingerprint: d.key_fingerprint || "",
      };
    },
    toKind(flat) {
      return {
        type: "sshKey",
        data: {
          public_key: flat.publicKey || null,
          private_key: flat.privateKey || null,
          key_fingerprint: flat.fingerprint || null,
        },
      };
    },
  },

  secureNote: {
    typeKey: "secureNote",
    fields: [],
    fromKind() { return {}; },
    toKind() { return { type: "secureNote" }; },
  },

  bankAccount: {
    typeKey: "bankAccount",
    fields: [
      { key: "bankName", label: "fields.bankName", placeholder: "Chase" },
      { key: "nameOnAccount", label: "fields.nameOnAccount", placeholder: "John Doe" },
      { key: "accountType", label: "fields.accountType", type: "select", options: ["checking","savings","investment","other"] },
      { key: "accountNumber", label: "fields.accountNumber", placeholder: "123456789", mono: true },
      { key: "routingNumber", label: "fields.routingNumber", placeholder: "987654321", mono: true },
      { key: "branchNumber", label: "fields.branchNumber", placeholder: "001", mono: true },
      { key: "swiftCode", label: "fields.swiftCode", placeholder: "CHASUS33", mono: true },
      { key: "iban", label: "fields.iban", placeholder: "US12 3456 7890", mono: true },
      { key: "bankPhone", label: "fields.bankPhone", placeholder: "+1 800 555 1234" },
      { key: "bankPin", label: "fields.pin", placeholder: "****", type: "password", mono: true },
    ],
    layout: [
      ["bankName", "nameOnAccount"],
      ["accountType", "accountNumber"],
      ["routingNumber", "branchNumber"],
      ["swiftCode", "iban"],
      ["bankPhone", "bankPin"],
    ],
    fromKind(kind) {
      const d = kind.data || kind.bankAccount || kind.BankAccount || {};
      return {
        bankName: d.bank_name || "",
        nameOnAccount: d.name_on_account || "",
        accountType: d.account_type || "",
        accountNumber: d.account_number || "",
        routingNumber: d.routing_number || "",
        branchNumber: d.branch_number || "",
        bankPin: d.pin || "",
        swiftCode: d.swift_code || "",
        iban: d.iban || "",
        bankPhone: d.bank_contact_phone || "",
      };
    },
    toKind(flat) {
      return {
        type: "bankAccount",
        data: {
          bank_name: flat.bankName || null,
          name_on_account: flat.nameOnAccount || null,
          account_type: flat.accountType || null,
          account_number: flat.accountNumber || null,
          routing_number: flat.routingNumber || null,
          branch_number: flat.branchNumber || null,
          pin: flat.bankPin || null,
          swift_code: flat.swiftCode || null,
          iban: flat.iban || null,
          bank_contact_phone: flat.bankPhone || null,
        },
      };
    },
  },

  driversLicense: {
    typeKey: "driversLicense",
    fields: [
      { key: "dlFirstName", label: "fields.firstName", placeholder: "Jane" },
      { key: "dlMiddleName", label: "fields.middleName", placeholder: "A" },
      { key: "dlLastName", label: "fields.lastName", placeholder: "Doe" },
      { key: "dlDob", label: "fields.dateOfBirth", placeholder: "1990-01-15" },
      { key: "dlNumber", label: "fields.licenseNumber", placeholder: "D55555", mono: true },
      { key: "dlCountry", label: "fields.issuingCountry", placeholder: "US" },
      { key: "dlState", label: "fields.issuingState", placeholder: "CA" },
      { key: "dlIssueDate", label: "fields.issueDate", placeholder: "2020-06-01" },
      { key: "dlExpDate", label: "fields.expirationDate", placeholder: "2028-06-01" },
      { key: "dlAuthority", label: "fields.issuingAuthority", placeholder: "DMV" },
      { key: "dlClass", label: "fields.licenseClass", placeholder: "C" },
    ],
    layout: [
      ["dlFirstName", "dlMiddleName", "dlLastName"],
      ["dlDob", "dlNumber"],
      ["dlCountry", "dlState"],
      ["dlIssueDate", "dlExpDate", "dlClass"],
    ],
    fromKind(kind) {
      const d = kind.data || kind.driversLicense || kind.DriversLicense || {};
      return {
        dlFirstName: d.first_name || "",
        dlMiddleName: d.middle_name || "",
        dlLastName: d.last_name || "",
        dlDob: d.date_of_birth || "",
        dlNumber: d.license_number || "",
        dlCountry: d.issuing_country || "",
        dlState: d.issuing_state || "",
        dlIssueDate: d.issue_date || "",
        dlExpDate: d.expiration_date || "",
        dlAuthority: d.issuing_authority || "",
        dlClass: d.license_class || "",
      };
    },
    toKind(flat) {
      return {
        type: "driversLicense",
        data: {
          first_name: flat.dlFirstName || null,
          middle_name: flat.dlMiddleName || null,
          last_name: flat.dlLastName || null,
          date_of_birth: flat.dlDob || null,
          license_number: flat.dlNumber || null,
          issuing_country: flat.dlCountry || null,
          issuing_state: flat.dlState || null,
          issue_date: flat.dlIssueDate || null,
          expiration_date: flat.dlExpDate || null,
          issuing_authority: flat.dlAuthority || null,
          license_class: flat.dlClass || null,
        },
      };
    },
  },

  passport: {
    typeKey: "passport",
    fields: [
      { key: "ppGivenName", label: "fields.givenName", placeholder: "John" },
      { key: "ppSurname", label: "fields.surname", placeholder: "Doe" },
      { key: "ppDob", label: "fields.dateOfBirth", placeholder: "1990-01-15" },
      { key: "ppSex", label: "fields.sex", type: "select", options: ["M","F","X"] },
      { key: "ppBirthPlace", label: "fields.birthPlace", placeholder: "City" },
      { key: "ppNationality", label: "fields.nationality", placeholder: "US" },
      { key: "ppCountry", label: "fields.issuingCountry", placeholder: "US" },
      { key: "ppNumber", label: "fields.passportNumber", placeholder: "P1234567", mono: true },
      { key: "ppType", label: "fields.passportType", placeholder: "P" },
      { key: "ppNationalId", label: "fields.nationalIdNumber", placeholder: "123-45-6789", mono: true },
      { key: "ppAuthority", label: "fields.issuingAuthority", placeholder: "State Department" },
      { key: "ppIssueDate", label: "fields.issueDate", placeholder: "2020-01-01" },
      { key: "ppExpDate", label: "fields.expirationDate", placeholder: "2030-01-01" },
    ],
    layout: [
      ["ppGivenName", "ppSurname"],
      ["ppDob", "ppSex", "ppBirthPlace"],
      ["ppNationality", "ppCountry"],
      ["ppNumber", "ppType"],
      ["ppNationalId", "ppAuthority"],
      ["ppIssueDate", "ppExpDate"],
    ],
    fromKind(kind) {
      const d = kind.data || kind.passport || kind.Passport || {};
      return {
        ppSurname: d.surname || "",
        ppGivenName: d.given_name || "",
        ppDob: d.date_of_birth || "",
        ppSex: d.sex || "",
        ppBirthPlace: d.birth_place || "",
        ppNationality: d.nationality || "",
        ppCountry: d.issuing_country || "",
        ppNumber: d.passport_number || "",
        ppType: d.passport_type || "",
        ppNationalId: d.national_identification_number || "",
        ppAuthority: d.issuing_authority || "",
        ppIssueDate: d.issue_date || "",
        ppExpDate: d.expiration_date || "",
      };
    },
    toKind(flat) {
      return {
        type: "passport",
        data: {
          surname: flat.ppSurname || null,
          given_name: flat.ppGivenName || null,
          date_of_birth: flat.ppDob || null,
          sex: flat.ppSex || null,
          birth_place: flat.ppBirthPlace || null,
          nationality: flat.ppNationality || null,
          issuing_country: flat.ppCountry || null,
          passport_number: flat.ppNumber || null,
          passport_type: flat.ppType || null,
          national_identification_number: flat.ppNationalId || null,
          issuing_authority: flat.ppAuthority || null,
          issue_date: flat.ppIssueDate || null,
          expiration_date: flat.ppExpDate || null,
        },
      };
    },
  },
};

/**
 * Get the schema for a cipher type. Falls back to login.
 */
export function getSchema(cipherType) {
  return CIPHER_SCHEMAS[cipherType] || CIPHER_SCHEMAS.login;
}

/**
 * Extract flat buffer from a structured cipher response.
 * Replaces CipherDetail.startEdit() 80-line mapping.
 */
export function cipherToFlat(cipher) {
  if (!cipher) return {};
  const kind = cipher.kind || {};
  const cipherType = cipher.type || "login";
  const schema = getSchema(cipherType);

  // Common fields
  const flat = {
    name: cipher.name || "",
    cipherType,
    notes: cipher.notes || "",
    favorite: cipher.favorite || false,
    folder_id: cipher.folder_id || null,
    custom_fields: cipher.custom_fields || [],
    attachments: cipher.attachments || [],
    reprompt: cipher.reprompt || false,
    tags: cipher.tags || [],
  };

  // Type-specific fields from schema
  Object.assign(flat, schema.fromKind(kind));

  return flat;
}
