import { describe, it, expect } from "vitest";
import { CIPHER_SCHEMAS, getSchema, cipherToFlat } from "../lib/cipherSchema.js";

const TYPES = ["login", "card", "identity", "sshKey", "secureNote", "bankAccount", "driversLicense", "passport"];

describe("getSchema", () => {
  it("returns login for unknown type", () => {
    expect(getSchema("unknown").typeKey).toBe("login");
  });

  it("returns correct schema for each type", () => {
    TYPES.forEach(t => {
      expect(getSchema(t).typeKey).toBe(t);
    });
  });
});

describe("fromKind → toKind roundtrip", () => {
  const testCases = {
    login: { login: { username: "user", password: "pass", uris: [{ uri: "https://example.com", match_strategy: "domain" }], totp_uri: "otpauth://totp/Test" } },
    card: { card: { cardholder_name: "John", number: "4111111111111111", brand: "visa", exp_month: "12", exp_year: "2030", code: "123" } },
    identity: { identity: { title: "Mr", first_name: "John", middle_name: "A", last_name: "Doe", username: "johndoe", company: "Acme", email: "john@acme.com", phone: "+1234", address1: "123 Main", address2: "Apt 4B", address3: "", city: "NYC", state: "NY", postal_code: "10001", country: "US", ssn: "123-45-6789", passport_number: "AB123", license_number: "D555" } },
    sshKey: { sshKey: { public_key: "ssh-rsa AAAA", private_key: "-----BEGIN KEY-----", key_fingerprint: "SHA256:abc" } },
    secureNote: { secureNote: {} },
    bankAccount: { bankAccount: { bank_name: "Chase", name_on_account: "John", account_type: "checking", account_number: "123456", routing_number: "987654", branch_number: "001", pin: "9999", swift_code: "CHASUS33", iban: "US12 3456", bank_contact_phone: "+1 800 555" } },
    driversLicense: { driversLicense: { first_name: "Jane", middle_name: "B", last_name: "Doe", date_of_birth: "1990-01-15", license_number: "D55555", issuing_country: "US", issuing_state: "CA", issue_date: "2020-06-01", expiration_date: "2028-06-01", issuing_authority: "DMV", license_class: "C" } },
    passport: { passport: { surname: "Doe", given_name: "John", date_of_birth: "1990-01-15", sex: "M", birth_place: "NYC", nationality: "US", issuing_country: "US", passport_number: "P1234567", passport_type: "P", national_identification_number: "123-45-6789", issuing_authority: "State Dept", issue_date: "2020-01-01", expiration_date: "2030-01-01" } },
  };

  TYPES.forEach(type => {
    it(`roundtrips ${type}`, () => {
      const schema = getSchema(type);
      const kind = testCases[type];

      // fromKind: structured → flat
      const flat = schema.fromKind(kind);

      // toKind: flat → structured
      const result = schema.toKind(flat);

      // Verify type
      expect(result.type).toBe(type);

      // Verify roundtrip: toKind(fromKind(kind)) should equal toKind(flatWithSameValues)
      // by checking each key in the original kind data
      const originalData = kind[type];
      if (originalData) {
        for (const [key, val] of Object.entries(originalData)) {
          // null → "" in fromKind → null in toKind. So compare truthy values match.
          if (val != null && val !== "") {
            if (Array.isArray(val)) {
              expect(result.data[key]).toEqual(val);
            } else {
              expect(result.data[key]).toBe(val);
            }
          }
        }
      }
    });
  });
});

describe("cipherToFlat", () => {
  it("extracts common fields", () => {
    const cipher = { name: "Test", type: "login", notes: "hello", favorite: true, folder_id: "f1", custom_fields: [], reprompt: true, kind: { login: { username: "u" } } };
    const flat = cipherToFlat(cipher);
    expect(flat.name).toBe("Test");
    expect(flat.cipherType).toBe("login");
    expect(flat.notes).toBe("hello");
    expect(flat.favorite).toBe(true);
    expect(flat.folder_id).toBe("f1");
    expect(flat.reprompt).toBe(true);
  });

  it("returns empty object for null", () => {
    expect(cipherToFlat(null)).toEqual({});
  });

  it("defaults to login type", () => {
    const flat = cipherToFlat({ name: "X" });
    expect(flat.cipherType).toBe("login");
  });

  it("extracts card fields via schema", () => {
    const cipher = { type: "card", kind: { card: { cardholder_name: "John", number: "4111", brand: "visa", exp_month: "12", exp_year: "2030", code: "123" } } };
    const flat = cipherToFlat(cipher);
    expect(flat.cardholder_name).toBe("John");
    expect(flat.cardNumber).toBe("4111");
    expect(flat.cvv).toBe("123");
  });
});
