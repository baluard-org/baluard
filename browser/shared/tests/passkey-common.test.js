// Unit tests for passkey-common.js (pure ceremony helpers).
import { describe, it, expect } from "vitest";
import {
  bufferSourceToB64url,
  b64urlToUint8Array,
  isValidWebAuthnOrigin,
  rpIdMatches,
  effectiveRpId,
  clampTimeout,
  filterPubKeyCredParams,
  normalizeCreationOptions,
  normalizeRequestOptions,
  assertionNeedsFallback,
  serializeError,
  buildPublicKeyCredential,
  ErrName,
} from "../src/passkey-common.js";

const enc = (s) => new TextEncoder().encode(s);

describe("base64url conversion", () => {
  it("round-trips bytes", () => {
    const bytes = enc("challenge-bytes-1234");
    const b64 = bufferSourceToB64url(bytes);
    expect(b64).not.toContain("+");
    expect(b64).not.toContain("/");
    expect(b64).not.toContain("=");
    expect(Array.from(b64urlToUint8Array(b64))).toEqual(Array.from(bytes));
  });

  it("handles ArrayBuffer, DataView and padded input", () => {
    const buf = enc("ab").buffer;
    expect(bufferSourceToB64url(buf)).toBe("YWI");
    const view = new DataView(enc("ab").buffer);
    expect(bufferSourceToB64url(view)).toBe("YWI");
    expect(Array.from(b64urlToUint8Array("YWI="))).toEqual(Array.from(enc("ab")));
  });

  it("rejects junk and non-BufferSources", () => {
    expect(bufferSourceToB64url("nope")).toBeNull();
    expect(bufferSourceToB64url(undefined)).toBeNull();
    expect(b64urlToUint8Array("not!valid!")).toBeNull();
    expect(b64urlToUint8Array(42)).toBeNull();
  });
});

describe("origin rules", () => {
  it("accepts https and localhost http only", () => {
    expect(isValidWebAuthnOrigin("https://example.com")).toBe(true);
    expect(isValidWebAuthnOrigin("http://localhost:3000")).toBe(true);
    expect(isValidWebAuthnOrigin("http://127.0.0.1:8080")).toBe(true);
    expect(isValidWebAuthnOrigin("http://example.com")).toBe(false);
    expect(isValidWebAuthnOrigin("null")).toBe(false);
    expect(isValidWebAuthnOrigin("")).toBe(false);
    expect(isValidWebAuthnOrigin(undefined)).toBe(false);
    expect(isValidWebAuthnOrigin("ftp://x")).toBe(false);
  });

  it("matches rp.id on dot boundaries only", () => {
    expect(rpIdMatches("example.com", "example.com")).toBe(true);
    expect(rpIdMatches("example.com", "login.example.com")).toBe(true);
    expect(rpIdMatches("example.com", "evilexample.com")).toBe(false);
    expect(rpIdMatches("example.com", "example.com.evil.test")).toBe(false);
    expect(rpIdMatches("Example.COM", "LOGIN.example.com")).toBe(true);
    expect(rpIdMatches("", "example.com")).toBe(false);
  });

  it("defaults rp.id to the host and rejects bad suffixes", () => {
    expect(effectiveRpId("login.example.com", undefined)).toBe("login.example.com");
    expect(effectiveRpId("login.example.com", "example.com")).toBe("example.com");
    expect(effectiveRpId("evilexample.com", "example.com")).toBeNull();
  });

  it("rejects IP-literal hosts as effective rp.id (spec: rp.id must be a domain)", () => {
    expect(effectiveRpId("127.0.0.1", undefined)).toBeNull();
    expect(effectiveRpId("[::1]", undefined)).toBeNull();
    expect(effectiveRpId("93.184.216.34", undefined)).toBeNull();
    expect(effectiveRpId("93.184.216.34", "93.184.216.34")).toBeNull();
    expect(effectiveRpId("rp.example", "rp.example")).toBe("rp.example");
  });
});

describe("timeout clamp", () => {
  it("clamps per UV band with defaults", () => {
    expect(clampTimeout(undefined, true)).toBe(300_000);
    expect(clampTimeout(undefined, false)).toBe(120_000);
    expect(clampTimeout(1, true)).toBe(30_000);
    expect(clampTimeout(999_999, true)).toBe(600_000);
    expect(clampTimeout(999_999, false)).toBe(180_000);
    expect(clampTimeout(60_000, true)).toBe(60_000);
    expect(clampTimeout("60000", false)).toBe(60_000);
  });
});

describe("pubKeyCredParams filter", () => {
  it("keeps ES256 only", () => {
    expect(filterPubKeyCredParams([{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }]))
      .toEqual([{ type: "public-key", alg: -7 }]);
    expect(filterPubKeyCredParams([{ type: "public-key", alg: "-7" }]))
      .toEqual([{ type: "public-key", alg: -7 }]);
    expect(filterPubKeyCredParams([{ type: "public-key", alg: -8 }])).toEqual([]);
    expect(filterPubKeyCredParams(undefined)).toEqual([]);
    expect(filterPubKeyCredParams([{ type: "public-key" }])).toEqual([]);
  });
});

describe("creation option normalization", () => {
  const base = () => ({
    rp: { id: "example.com", name: "Example" },
    user: { id: enc("user-id-bytes"), name: "u@example.com", displayName: "U" },
    challenge: enc("the-challenge"),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    excludeCredentials: [
      { type: "public-key", id: enc("excluded"), transports: ["usb"] },
      { type: "public-key", id: undefined },
    ],
    authenticatorSelection: { userVerification: "required", residentKey: "required" },
    timeout: 999_999,
    attestation: "none",
  });

  it("serializes buffers, filters algorithms and clamps timeout", () => {
    const r = normalizeCreationOptions(base());
    expect(r.ok).toBe(true);
    expect(r.requiresUv).toBe(true);
    expect(r.options.challenge).toBe(bufferSourceToB64url(enc("the-challenge")));
    expect(r.options.user.id).toBe(bufferSourceToB64url(enc("user-id-bytes")));
    expect(r.options.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }]);
    expect(r.options.excludeCredentials).toHaveLength(1);
    expect(r.options.timeout).toBe(600_000);
    expect(r.options.attestation).toBe("none");
  });

  it("defaults pubKeyCredParams when the RP omits them", () => {
    const pk = base();
    delete pk.pubKeyCredParams;
    const r = normalizeCreationOptions(pk);
    expect(r.ok).toBe(true);
    expect(r.options.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }]);
  });

  it("rejects non-ES256-only requests with NotSupportedError", () => {
    const pk = base();
    pk.pubKeyCredParams = [{ type: "public-key", alg: -257 }];
    expect(normalizeCreationOptions(pk)).toEqual({ ok: false, errorName: ErrName.NOT_SUPPORTED });
  });

  it("rejects a missing or unusable challenge", () => {
    const pk = base();
    delete pk.challenge;
    expect(normalizeCreationOptions(pk).ok).toBe(false);
  });

  it("keeps the L1 residentKey quirk", () => {
    const pk = base();
    pk.authenticatorSelection = { requireResidentKey: true };
    const r = normalizeCreationOptions(pk);
    expect(r.options.authenticatorSelection.residentKey).toBe("required");
    expect(normalizeCreationOptions({ challenge: enc("c") }).options.authenticatorSelection)
      .toBeUndefined();
  });
});

describe("request option normalization", () => {
  it("serializes challenge + allowCredentials", () => {
    const r = normalizeRequestOptions({
      challenge: enc("get-challenge"),
      rpId: "example.com",
      allowCredentials: [{ type: "public-key", id: enc("cred-1") }],
      userVerification: "required",
      timeout: 10,
    });
    expect(r.ok).toBe(true);
    expect(r.options.rpId).toBe("example.com");
    expect(r.options.allowCredentials[0].id).toBe(bufferSourceToB64url(enc("cred-1")));
    expect(r.options.timeout).toBe(30_000);
    expect(r.requiresUv).toBe(true);
  });
});

describe("fallback rule", () => {
  it("hands non-internal-only allowCredentials to the browser", () => {
    expect(assertionNeedsFallback({ allowCredentials: [{ transports: ["usb", "nfc"] }] })).toBe(true);
    expect(assertionNeedsFallback({ allowCredentials: [{ transports: ["internal"] }] })).toBe(false);
    expect(assertionNeedsFallback({ allowCredentials: [{}] })).toBe(false);
    expect(assertionNeedsFallback({ allowCredentials: [] })).toBe(false);
    expect(assertionNeedsFallback({})).toBe(false);
  });
});

describe("serializeError", () => {
  it("keeps name/message/code", () => {
    const e = new Error("nope");
    e.code = "locked";
    expect(serializeError(e)).toEqual({ name: "Error", message: "nope", code: "locked" });
    expect(serializeError(undefined)).toEqual({ name: "Error", message: "" });
  });
});

describe("buildPublicKeyCredential", () => {
  const credJson = (isCreate) => ({
    rawId: bufferSourceToB64url(enc("credential-id")),
    response: isCreate
      ? {
          clientDataJSON: bufferSourceToB64url(enc('{"type":"webauthn.create"}')),
          attestationObject: bufferSourceToB64url(enc("attestation")),
          publicKey: bufferSourceToB64url(enc("spki-bytes")),
          publicKeyAlgorithm: -7,
          transports: ["internal"],
        }
      : {
          clientDataJSON: bufferSourceToB64url(enc('{"type":"webauthn.get"}')),
          authenticatorData: bufferSourceToB64url(enc("authdata")),
          signature: bufferSourceToB64url(enc("sig")),
          userHandle: bufferSourceToB64url(enc("uh")),
        },
    clientExtensionResults: { credProtect: 2 },
  });

  it("rebuilds an attestation credential with spec-placed methods", () => {
    const cred = buildPublicKeyCredential(credJson(true), true);
    expect(cred).not.toBeNull();
    expect(cred.id).toBe(credJson(true).rawId);
    expect(cred.type).toBe("public-key");
    // Spec shape: rawId and every response field are ArrayBuffers.
    expect(cred.rawId instanceof ArrayBuffer).toBe(true);
    expect(Array.from(new Uint8Array(cred.response.clientDataJSON))).toEqual(Array.from(enc('{"type":"webauthn.create"}')));
    expect(cred.response.attestationObject instanceof ArrayBuffer).toBe(true);
    // Spec shape: getTransports/getPublicKey/getPublicKeyAlgorithm belong to
    // AuthenticatorAttestationResponse, not the credential.
    expect(cred.response.getTransports()).toEqual(["internal"]);
    expect(Array.from(new Uint8Array(cred.response.getPublicKey()))).toEqual(Array.from(enc("spki-bytes")));
    expect(cred.response.getPublicKeyAlgorithm()).toBe(-7);
    expect(cred.response.getAuthenticatorData()).toBeNull();
    expect(cred.authenticatorAttachment).toBe("platform");
    expect(cred.getClientExtensionResults()).toEqual({ credProtect: 2 });
    expect(cred.toJSON().rawId).toBe(credJson(true).rawId);
    expect(cred.getTransports).toBeUndefined();
    expect(cred.getPublicKey).toBeUndefined();
    // instanceof checks pass wherever the native interfaces exist.
    if (typeof PublicKeyCredential !== "undefined") {
      expect(cred instanceof PublicKeyCredential).toBe(true);
      expect(cred.response instanceof AuthenticatorAttestationResponse.prototype.constructor).toBe(true);
    }
  });

  it("rebuilds an assertion credential with userHandle and null attachment", () => {
    const cred = buildPublicKeyCredential(credJson(false), false);
    expect(cred.response.signature instanceof ArrayBuffer).toBe(true);
    expect(Array.from(new Uint8Array(cred.response.userHandle))).toEqual(Array.from(enc("uh")));
    expect(cred.authenticatorAttachment).toBeNull();
    expect(Array.from(new Uint8Array(cred.response.getAuthenticatorData()))).toEqual(Array.from(enc("authdata")));
    expect(cred.response.getTransports).toBeUndefined();
    if (typeof AuthenticatorAssertionResponse !== "undefined") {
      expect(cred.response instanceof AuthenticatorAssertionResponse.prototype.constructor).toBe(true);
    }
  });

  it("keeps attachment overrides and survives deleted native interfaces", () => {
    const withAttachment = credJson(true);
    withAttachment.authenticatorAttachment = "cross-platform";
    const cred = buildPublicKeyCredential(withAttachment, true);
    expect(cred.authenticatorAttachment).toBe("cross-platform");
    const userHandleJson = credJson(false);
    delete userHandleJson.response.userHandle;
    const noHandle = buildPublicKeyCredential(userHandleJson, false);
    expect(noHandle.response.userHandle).toBeNull();
  });

  it("returns null for garbage or an unusable rawId", () => {
    expect(buildPublicKeyCredential(null, true)).toBeNull();
    expect(buildPublicKeyCredential({ rawId: "!!!" }, true)).toBeNull();
  });
});
