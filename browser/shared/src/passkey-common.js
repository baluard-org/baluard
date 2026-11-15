// Passkey ceremony shared helpers (page script, bridge, service worker).
//
// Pure functions only: the page script runs in the page's MAIN world where
// no extension APIs exist, and the unit suite imports this source directly
// (the esbuild IIFE bundle strips exports from the built scripts).

// Protocol constants for the window.postMessage channel between the MAIN
// world script and the isolated-world bridge. A fixed sender tag plus a
// random per-context id: both sides drop messages whose tag or id do not
// match, so page noise and other extensions' traffic cannot inject into
// the ceremony.
export const SENDER_TAG = "baluard-webauthn";

export const MsgType = {
  CREATE: "createRequest",
  GET: "getRequest",
  ABORT: "abortRequest",
  RESPONSE: "response",
  DESTROY: "destroy",
  // Announced by the page script right after install, so the bridge knows
  // the page's context id (and can stamp DESTROY) before any ceremony runs.
  HELLO: "hello",
};

// The page world learns nothing about WHY a ceremony was declined beyond
// these names; everything else degrades to a generic NotAllowedError so
// error text can never smuggle vault or extension detail into a page.
export const ErrName = {
  NOT_ALLOWED: "NotAllowedError",
  NOT_SUPPORTED: "NotSupportedError",
  SECURITY: "SecurityError",
  INVALID: "TypeError",
  FALLBACK: "FallbackRequested",
};

// ── base64url ↔ bytes ──

export function bufferSourceToB64url(v) {
  let bytes;
  // Tag-string check, not instanceof: tests and workers can hand over
  // BufferSources from another realm, where instanceof lies.
  const tag = Object.prototype.toString.call(v);
  if (tag === "[object ArrayBuffer]") {
    bytes = new Uint8Array(v);
  } else if (ArrayBuffer.isView(v)) {
    // TypedArray or DataView; isView checks the internal slot, realm-safe.
    bytes = new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  } else {
    return null;
  }
  if (!bytes) return null;
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlToUint8Array(s) {
  if (typeof s !== "string") return null;
  const bare = s.replace(/=+$/, "");
  if (/[^A-Za-z0-9\-_]/.test(bare)) return null;
  let b64 = bare.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

// ── origin / rp.id rules (coarse pre-checks; the daemon's RpIdVerifier
// stays authoritative and re-validates every request) ──

// WebAuthn requires a secure context: https, or localhost's insecure
// exception. Opaque origins ("null" in sandboxed iframes) fail.
export function isValidWebAuthnOrigin(origin) {
  if (typeof origin !== "string" || origin === "null" || origin === "") return false;
  if (origin.startsWith("https://")) return true;
  if (origin.startsWith("http://")) {
    try {
      const host = new URL(origin).hostname;
      return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
    } catch {
      return false;
    }
  }
  return false;
}

// The spec's registrable-domain-suffix rule reduced to the dot-boundary
// check; the Public-Suffix edge cases (rp.id of a bare TLD, private PSL
// entries) are caught Rust-side by passkey-rs' verifier.
export function rpIdMatches(rpId, originHost) {
  if (typeof rpId !== "string" || typeof originHost !== "string") return false;
  const rp = rpId.toLowerCase();
  const host = originHost.toLowerCase();
  if (rp === host) return true;
  return host.endsWith("." + rp);
}

// Effective rp.id per the client algorithm: the option, else the origin's
// host. Returns null when the option is not a valid suffix of the host, or
// when the result is an IP literal — the spec restricts rp.id to domains,
// so a WebAuthn ceremony on a bare IP origin can never be claimed.
export function effectiveRpId(originHost, rpIdOption) {
  const candidate = rpIdOption
    ? rpIdMatches(rpIdOption, originHost)
      ? rpIdOption.toLowerCase()
      : null
    : originHost || null;
  if (candidate && isIpLiteral(candidate)) return null;
  return candidate;
}

function isIpLiteral(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
}

// ── client algorithm pieces ──

// Bitwarden parity: UV ceremonies get 30s-600s (default 300s), plain
// ceremonies 30s-180s (default 120s). Values outside the band clamp in.
export function clampTimeout(ms, requiresUv) {
  const min = 30_000;
  const max = requiresUv ? 600_000 : 180_000;
  const def = requiresUv ? 300_000 : 120_000;
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return def;
  return Math.min(max, Math.max(min, n));
}

// ES256 only (ADR 0095). Accepts the alg-string form too ("ES256"-style
// numbers arrive as numbers; a missing alg is not spec-valid and drops).
// Returns [] when nothing usable remains -> NotSupportedError (spec step 5:
// never answer with an algorithm the RP did not request).
export function filterPubKeyCredParams(params) {
  if (!Array.isArray(params)) return [];
  return params
    .filter(
      (p) =>
        p &&
        typeof p === "object" &&
        p.type === "public-key" &&
        (p.alg === -7 || p.alg === "-7")
    )
    .map((p) => ({ type: "public-key", alg: -7 }));
}

// Normalize the page's structured creation options into the daemon's inner
// options shape (no publicKey wrapper, BufferSources as base64url). Returns
// { ok: true, options } or { ok: false, errorName } — one uniform shape so
// callers cannot confuse sentinels.
export function normalizeCreationOptions(publicKey) {
  if (!publicKey || typeof publicKey !== "object") return { ok: false, errorName: ErrName.INVALID };
  const challenge = bufferSourceToB64url(publicKey.challenge);
  if (!challenge) return { ok: false, errorName: ErrName.INVALID };
  const uv =
    publicKey.authenticatorSelection?.userVerification === "required" ? true : false;
  const out = { challenge };
  if (publicKey.rp) {
    out.rp = {};
    if (typeof publicKey.rp.id === "string") out.rp.id = publicKey.rp.id;
    if (typeof publicKey.rp.name === "string") out.rp.name = publicKey.rp.name;
  }
  if (publicKey.user && typeof publicKey.user === "object") {
    out.user = {};
    const id = bufferSourceToB64url(publicKey.user.id);
    if (id) out.user.id = id;
    if (typeof publicKey.user.name === "string") out.user.name = publicKey.user.name;
    if (typeof publicKey.user.displayName === "string")
      out.user.displayName = publicKey.user.displayName;
  }
  const params = filterPubKeyCredParams(publicKey.pubKeyCredParams);
  // No ES256 offered -> the ceremony cannot proceed (client algorithm step
  // 5: never answer with an algorithm the RP did not request). An ABSENT
  // list means the RP left the choice to the authenticator; default ES256.
  if (publicKey.pubKeyCredParams !== undefined && params.length === 0) {
    return { ok: false, errorName: ErrName.NOT_SUPPORTED };
  }
  out.pubKeyCredParams = params.length > 0 ? params : [{ type: "public-key", alg: -7 }];
  if (Array.isArray(publicKey.excludeCredentials)) {
    out.excludeCredentials = publicKey.excludeCredentials
      .map((d) => {
        const id = d && bufferSourceToB64url(d.id);
        return id ? { type: "public-key", id, transports: d.transports || undefined } : null;
      })
      .filter(Boolean);
  }
  if (publicKey.authenticatorSelection && typeof publicKey.authenticatorSelection === "object") {
    const sel = { ...publicKey.authenticatorSelection };
    // L1-compat quirk kept per spec: the string residentKey maps to the
    // boolean requireResidentKey when residentKey is absent.
    if (!("residentKey" in sel) && typeof sel.requireResidentKey === "boolean") {
      sel.residentKey = sel.requireResidentKey ? "required" : "preferred";
    }
    out.authenticatorSelection = sel;
  }
  if (publicKey.timeout !== undefined) out.timeout = clampTimeout(publicKey.timeout, uv);
  else out.timeout = clampTimeout(undefined, uv);
  if (publicKey.attestation !== undefined) out.attestation = publicKey.attestation;
  if (publicKey.attestationFormats !== undefined)
    out.attestationFormats = publicKey.attestationFormats;
  if (publicKey.extensions && typeof publicKey.extensions === "object")
    out.extensions = publicKey.extensions;
  return { ok: true, options: out, requiresUv: uv };
}

export function normalizeRequestOptions(publicKey) {
  if (!publicKey || typeof publicKey !== "object") return { ok: false, errorName: ErrName.INVALID };
  const challenge = bufferSourceToB64url(publicKey.challenge);
  if (!challenge) return { ok: false, errorName: ErrName.INVALID };
  const uv = publicKey.userVerification === "required";
  const out = { challenge, userVerification: publicKey.userVerification || "preferred" };
  if (typeof publicKey.rpId === "string") out.rpId = publicKey.rpId;
  if (Array.isArray(publicKey.allowCredentials)) {
    out.allowCredentials = publicKey.allowCredentials
      .map((d) => {
        const id = d && bufferSourceToB64url(d.id);
        return id ? { type: "public-key", id, transports: d.transports || undefined } : null;
      })
      .filter(Boolean);
  }
  out.timeout = clampTimeout(publicKey.timeout, uv);
  if (publicKey.extensions && typeof publicKey.extensions === "object")
    out.extensions = publicKey.extensions;
  return { ok: true, options: out, requiresUv: uv };
}

// Assertions listing credentials that can only live on non-internal
// transports are handed to the browser untouched (spec step 20): a USB
// security key must stay reachable even with Baluard installed.
export function assertionNeedsFallback(requestOptions) {
  const allow = requestOptions && requestOptions.allowCredentials;
  if (!Array.isArray(allow) || allow.length === 0) return false;
  return allow.every((d) => {
    const t = d && d.transports;
    return Array.isArray(t) && t.length > 0 && !t.includes("internal") && !t.includes("hybrid");
  });
}

// ── error plumbing ──

// Serialize an Error across postMessage: own properties only, so a DOMException
// survives as {name, message} and rebuilds as a real DOMException.
export function serializeError(e) {
  const out = { name: e && e.name ? e.name : "Error", message: e && e.message ? e.message : "" };
  if (e && e.code !== undefined) out.code = e.code;
  return out;
}

// ── PublicKeyCredential reconstruction ──

// Rebuild a spec-shaped PublicKeyCredential from the daemon's toJSON JSON.
// Plain object literals + prototype fixes so site instanceof checks pass
// (the payload crosses postMessage, which strips prototypes). Every field
// the spec types as BufferSource is rebuilt as an ArrayBuffer, and the
// response methods live on the response object where the spec puts them.
export function buildPublicKeyCredential(json, isCreate) {
  if (!json || typeof json !== "object") return null;
  const rawId = b64urlToUint8Array(json.rawId);
  if (!rawId) return null;
  const respJson = json.response || {};
  const bytesOf = (b64) => {
    const u8 = b64urlToUint8Array(b64);
    return u8 ? u8.buffer : null;
  };
  const response = {
    clientDataJSON: bytesOf(respJson.clientDataJSON),
  };
  if (isCreate) {
    response.attestationObject = bytesOf(respJson.attestationObject);
    if (respJson.publicKey) response.publicKey = bytesOf(respJson.publicKey);
    if (typeof respJson.publicKeyAlgorithm === "number")
      response.publicKeyAlgorithm = respJson.publicKeyAlgorithm;
    if (Array.isArray(respJson.transports)) response.transports = respJson.transports;
    response.getTransports = function () {
      return Array.isArray(this.transports) ? this.transports : [];
    };
    response.getPublicKey = function () {
      return this.publicKey || null;
    };
    response.getPublicKeyAlgorithm = function () {
      return typeof this.publicKeyAlgorithm === "number" ? this.publicKeyAlgorithm : -7;
    };
    response.getAuthenticatorData = function () {
      return this.authenticatorData || null;
    };
  } else {
    response.authenticatorData = bytesOf(respJson.authenticatorData);
    response.signature = bytesOf(respJson.signature);
    response.userHandle = respJson.userHandle ? bytesOf(respJson.userHandle) : null;
    response.getAuthenticatorData = function () {
      return this.authenticatorData || null;
    };
  }
  for (const k of Object.keys(response)) {
    if (response[k] === undefined) delete response[k];
  }
  const cred = {
    rawId: rawId.buffer,
    id: json.rawId,
    type: "public-key",
    // The spec types authenticatorAttachment as string|null; the browser
    // fills it from the authenticator actually used, which a software
    // authenticator reconstructs as platform for create and unknown (null)
    // for assertions unless the daemon recorded one.
    authenticatorAttachment: json.authenticatorAttachment || (isCreate ? "platform" : null),
    response,
  };
  if (typeof PublicKeyCredential !== "undefined") {
    try {
      Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
      Object.setPrototypeOf(
        cred.response,
        isCreate
          ? AuthenticatorAttestationResponse.prototype
          : AuthenticatorAssertionResponse.prototype
      );
    } catch {
      // A page that deleted the interfaces keeps a plain object; the own
      // methods below still behave.
    }
  }
  cred.getClientExtensionResults = function () {
    return json.clientExtensionResults || {};
  };
  cred.toJSON = function () {
    return json;
  };
  return cred;
}
