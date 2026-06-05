import { describe, test, expect } from "vitest";
import {
  buildUris,
  buildKind,
  buildAddPayload,
  buildUpdatePayload,
  buildGetPayload,
  buildFolderCreatePayload,
  buildCreatePayload,
  buildImportPayload,
  buildExportPayload,
  buildAttachDownloadPayload,
  buildBiometricEnablePayload,
} from "../lib/payload.js";

// ── buildUris ──

describe("buildUris", () => {
  test("empty array returns empty", () => {
    expect(buildUris([])).toEqual([]);
  });

  test("null returns empty", () => {
    expect(buildUris(null)).toEqual([]);
  });

  test("undefined returns empty", () => {
    expect(buildUris(undefined)).toEqual([]);
  });

  test("string URIs are wrapped", () => {
    expect(buildUris(["https://example.com"])).toEqual([{ uri: "https://example.com" }]);
  });

  test("object URIs with match_strategy include it", () => {
    const result = buildUris([{ uri: "https://x.com", match_strategy: "exact" }]);
    expect(result).toEqual([{ uri: "https://x.com", match_strategy: "exact" }]);
  });

  test("object URIs without match_strategy omit it", () => {
    const result = buildUris([{ uri: "https://x.com", match_strategy: null }]);
    expect(result).toEqual([{ uri: "https://x.com" }]);
    expect("match_strategy" in result[0]).toBe(false);
  });

  test("object URIs with empty match_strategy omit it", () => {
    const result = buildUris([{ uri: "https://x.com", match_strategy: "" }]);
    expect(result).toEqual([{ uri: "https://x.com" }]);
    expect("match_strategy" in result[0]).toBe(false);
  });
});

// ── buildKind ──

describe("buildKind", () => {
  test("login (default)", () => {
    const kind = buildKind({ cipherType: "login", username: "a@b.com", password: "secret" });
    expect(kind.type).toBe("login");
    expect(kind.data.username).toBe("a@b.com");
    expect(kind.data.password).toBe("secret");
    expect(kind.data.uris).toEqual([]);
  });

  test("login with URIs omits null match_strategy", () => {
    const kind = buildKind({
      cipherType: "login",
      uris: [{ uri: "https://x.com", match_strategy: null }],
    });
    expect(kind.data.uris[0]).toEqual({ uri: "https://x.com" });
    expect("match_strategy" in kind.data.uris[0]).toBe(false);
  });

  test("login with URIs preserves match_strategy when set", () => {
    const kind = buildKind({
      cipherType: "login",
      uris: [{ uri: "https://x.com", match_strategy: "exact" }],
    });
    expect(kind.data.uris[0]).toEqual({ uri: "https://x.com", match_strategy: "exact" });
  });

  test("secureNote has no data key", () => {
    const kind = buildKind({ cipherType: "secureNote" });
    expect(kind.type).toBe("secureNote");
    expect(kind.data).toBeUndefined();
  });

  test("card maps fields correctly", () => {
    const kind = buildKind({
      cipherType: "card",
      cardholder_name: "John",
      cardNumber: "4111111111111111",
      expMonth: "12",
      expYear: "2030",
      cvv: "123",
    });
    expect(kind.type).toBe("card");
    expect(kind.data.cardholder_name).toBe("John");
    expect(kind.data.number).toBe("4111111111111111");
    expect(kind.data.exp_month).toBe("12");
    expect(kind.data.code).toBe("123");
  });

  test("identity maps all fields", () => {
    const kind = buildKind({
      cipherType: "identity",
      firstName: "John",
      lastName: "Doe",
      email: "john@example.com",
    });
    expect(kind.type).toBe("identity");
    expect(kind.data.first_name).toBe("John");
    expect(kind.data.last_name).toBe("Doe");
    expect(kind.data.email).toBe("john@example.com");
  });

  test("sshKey maps fields", () => {
    const kind = buildKind({
      cipherType: "sshKey",
      publicKey: "ssh-rsa AAAA",
      privateKey: "-----BEGIN...",
      fingerprint: "SHA256:abc",
    });
    expect(kind.type).toBe("sshKey");
    expect(kind.data.public_key).toBe("ssh-rsa AAAA");
    expect(kind.data.private_key).toBe("-----BEGIN...");
    expect(kind.data.key_fingerprint).toBe("SHA256:abc");
  });

  test("bankAccount maps fields", () => {
    const kind = buildKind({
      cipherType: "bankAccount",
      bankName: "Chase",
      routingNumber: "123456789",
    });
    expect(kind.type).toBe("bankAccount");
    expect(kind.data.bank_name).toBe("Chase");
    expect(kind.data.routing_number).toBe("123456789");
  });

  test("driversLicense maps fields", () => {
    const kind = buildKind({
      cipherType: "driversLicense",
      dlFirstName: "John",
      dlNumber: "D123456",
    });
    expect(kind.type).toBe("driversLicense");
    expect(kind.data.first_name).toBe("John");
    expect(kind.data.license_number).toBe("D123456");
  });

  test("passport maps fields", () => {
    const kind = buildKind({
      cipherType: "passport",
      ppSurname: "Doe",
      ppNumber: "AB1234567",
    });
    expect(kind.type).toBe("passport");
    expect(kind.data.surname).toBe("Doe");
    expect(kind.data.passport_number).toBe("AB1234567");
  });

  test("defaults to login when cipherType missing", () => {
    const kind = buildKind({ username: "test" });
    expect(kind.type).toBe("login");
  });

  test("null fields remain null (Rust expects Option<T>)", () => {
    const kind = buildKind({ cipherType: "login" });
    expect(kind.data.username).toBe(null);
    expect(kind.data.password).toBe(null);
    expect(kind.data.totp_uri).toBe(null);
  });
});

// ── buildAddPayload ──

describe("buildAddPayload", () => {
  test("full payload structure", () => {
    const p = buildAddPayload({
      name: "Gmail",
      cipherType: "login",
      username: "user@gmail.com",
      password: "secret",
      notes: "my notes",
      favorite: true,
      folder_id: "uuid-123",
      custom_fields: [{ name: "pin", value: "1234", field_type: "Text" }],
    });
    expect(p.name).toBe("Gmail");
    expect(p.kind.type).toBe("login");
    expect(p.favorite).toBe(true);
    expect(p.notes).toBe("my notes");
    expect(p.folder_id).toBe("uuid-123");
    expect(p.custom_fields).toHaveLength(1);
  });

  test("minimal payload defaults", () => {
    const p = buildAddPayload({ name: "Test", cipherType: "secureNote" });
    expect(p.name).toBe("Test");
    expect(p.favorite).toBe(false);
    expect(p.notes).toBe(null);
    expect(p.folder_id).toBe(null);
    expect(p.custom_fields).toEqual([]);
  });
});

// ── buildUpdatePayload ──

describe("buildUpdatePayload", () => {
  test("includes id at top level", () => {
    const p = buildUpdatePayload("uuid-abc", { name: "Updated", cipherType: "login" });
    expect(p.id).toBe("uuid-abc");
    expect(p.name).toBe("Updated");
    expect(p.kind.type).toBe("login");
  });
});

// ── buildGetPayload ──

describe("buildGetPayload", () => {
  test("structure", () => {
    expect(buildGetPayload("uuid-1")).toEqual({ id: "uuid-1", decrypt: true });
  });
});

// ── buildFolderCreatePayload ──

describe("buildFolderCreatePayload", () => {
  test("name only", () => {
    expect(buildFolderCreatePayload("Personal")).toEqual({ name: "Personal" });
  });

  test("with parent_id", () => {
    expect(buildFolderCreatePayload("Sub", "uuid-parent")).toEqual({
      name: "Sub",
      parent_id: "uuid-parent",
    });
  });

  test("omits parent_id when null", () => {
    const p = buildFolderCreatePayload("Root", null);
    expect("parent_id" in p).toBe(false);
  });
});

// ── buildCreatePayload ──

describe("buildCreatePayload", () => {
  test("structure", () => {
    expect(buildCreatePayload("mypass123")).toEqual({
      password: "mypass123",
      profile: "desktop_std",
    });
  });

  test("custom profile", () => {
    expect(buildCreatePayload("pw", "custom")).toEqual({
      password: "pw",
      profile: "custom",
    });
  });
});

// ── buildImportPayload ──

describe("buildImportPayload", () => {
  test("structure", () => {
    expect(buildImportPayload("bitwarden-json", "{...}")).toEqual({
      format: "bitwarden-json",
      data: "{...}",
    });
  });
});

// ── buildExportPayload ──

describe("buildExportPayload", () => {
  test("structure", () => {
    expect(buildExportPayload("bw-json")).toEqual({ format: "bw-json" });
  });
});

// ── buildAttachDownloadPayload ──

describe("buildAttachDownloadPayload", () => {
  test("structure", () => {
    expect(buildAttachDownloadPayload("cipher-1", "attach-2")).toEqual({
      cipher_id: "cipher-1",
      attachment_id: "attach-2",
    });
  });
});

// ── buildBiometricEnablePayload ──

describe("buildBiometricEnablePayload", () => {
  test("structure", () => {
    expect(buildBiometricEnablePayload("masterpw")).toEqual({ password: "masterpw" });
  });
});
