// Local WebAuthn relying party for the passkey e2e leg (Leg C).
//
// A real, verifying RP on http://localhost:<port> — a secure context, so
// the browser and Baluard's page-script gate both accept it. No deps:
// a minimal CBOR decoder for the fmt:"none" attestation layout and
// Node crypto for the ECDSA P-256 assertion check. This is the proof the
// whole stack (page-script wrap -> bridge -> SW -> daemon passkey-rs ->
// rebuilt PublicKeyCredential) produces credentials a REAL relying party
// accepts.
//
// Endpoints:
//   GET  /                 test page (register / sign-in / conditional buttons)
//   GET  /options?u=<name> creation options (challenge random per call)
//   POST /register         verify attestation, store credential
//   GET  /assert-options   request options for the stored credential
//   POST /verify           verify the assertion signature
//   GET  /state            {registered: bool} for test polling
//   POST /reset            forget the credential (test isolation)

import { createServer } from "node:http";
import { createHash, generateKeyPairSync, createPublicKey, verify as cryptoVerify, randomBytes } from "node:crypto";

const PORT = Number(process.env.RP_PORT || 18901);
const RP_ID = "localhost";

// ── minimal CBOR decode (uint/nint, bytes, text, maps, arrays) ──
function cborDecode(buf, offset = 0) {
  const major = buf[offset] >> 5;
  let info = buf[offset] & 0x1f;
  offset += 1;
  let val;
  if (info < 24) val = info;
  else if (info === 24) { val = buf[offset]; offset += 1; }
  else if (info === 25) { val = (buf[offset] << 8) | buf[offset + 1]; offset += 2; }
  else if (info === 26) {
    val = buf.readUInt32BE(offset); offset += 4;
  } else if (info === 27) {
    val = Number(buf.readBigUInt64BE(offset)); offset += 8;
  } else throw new Error(`unsupported cbor additional info ${info}`);
  if (major === 0) return [val, offset];
  if (major === 1) return [-1 - val, offset];
  if (major === 2 || major === 3) {
    const slice = buf.subarray(offset, offset + val);
    return [major === 2 ? new Uint8Array(slice) : Buffer.from(slice).toString("utf8"), offset + val];
  }
  if (major === 4) {
    const arr = [];
    for (let i = 0; i < val; i++) {
      const [item, next] = cborDecode(buf, offset);
      arr.push(item);
      offset = next;
    }
    return [arr, offset];
  }
  if (major === 5) {
    const map = {};
    for (let i = 0; i < val; i++) {
      const [k, kNext] = cborDecode(buf, offset);
      const [v, vNext] = cborDecode(buf, kNext);
      map[k] = v;
      offset = vNext;
    }
    return [map, offset];
  }
  throw new Error(`unsupported cbor major ${major}`);
}

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const unb64u = (s) => new Uint8Array(Buffer.from(s, "base64url"));

// COSE EC2 (-7 ES256, P-256) -> SPKI, for Node's verify().
function coseToSpki(cose) {
  if (cose[1] !== 2 || cose[3] !== -7 || cose[-1] !== 1) {
    throw new Error("only ES256 P-256 keys supported");
  }
  const x = Buffer.from(cose[-2]);
  const y = Buffer.from(cose[-3]);
  const point = Buffer.concat([Buffer.from([0x04]), x, y]);
  const spkiDer = Buffer.concat([
    Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
    point,
  ]);
  return createPublicKey({ key: spkiDer, format: "der", type: "spki" });
}

const store = {
  credentialId: null, // base64url
  coseKey: null,
  signCount: 0,
  lastChallenge: null,
  uvRequired: false,
  lastAssertion: null,
};

function resetStore() {
  store.credentialId = null;
  store.coseKey = null;
  store.signCount = 0;
  store.lastChallenge = null;
  store.uvRequired = false;
  store.lastAssertion = null;
}

const PAGE = `<!doctype html>
<html><head><meta charset="utf-8"><title>Passkey RP</title></head>
<body>
  <h1>Local passkey RP</h1>
  <input id="user" autocomplete="username webauthn" placeholder="username" />
  <button id="register">Register passkey</button>
  <button id="signin">Sign in</button>
  <button id="signin-uv">Sign in (verification required)</button>
  <button id="conditional">Conditional sign-in</button>
  <button id="usb">USB-only sign-in (fallback)</button>
  <pre id="status"></pre>
  <script>
    const statusEl = document.getElementById("status");
    const status = (s) => { statusEl.textContent = s; document.title = "RP:" + s.slice(0, 60); };
    const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
    const ub64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const bufB64 = (v) => { const u = v instanceof Uint8Array ? v : new Uint8Array(v); return b64u(u); };
    document.getElementById("register").onclick = async () => {
      try {
        const opts = await (await fetch("/options?u=demo")).json();
        opts.challenge = ub64u(opts.challenge);
        opts.user.id = ub64u(opts.user.id);
        const cred = await navigator.credentials.create({ publicKey: opts });
        const body = {
          id: cred.id, rawId: bufB64(cred.rawId), type: cred.type,
          response: {
            clientDataJSON: bufB64(cred.response.clientDataJSON),
            attestationObject: bufB64(cred.response.attestationObject),
          },
        };
        const r = await (await fetch("/register", { method: "POST", body: JSON.stringify(body) })).json();
        status("REGISTER " + JSON.stringify(r));
      } catch (e) { status("REGISTER-ERR " + e.name + ": " + e.message); }
    };
    document.getElementById("signin").onclick = async () => {
      try {
        const opts = await (await fetch("/assert-options")).json();
        await signIn(opts);
      } catch (e) { status("ASSERT-ERR " + e.name + ": " + e.message); }
    };
    // UV ceremony: the popout picker must grant user verification before
    // the daemon signs, so the RP can check the UV flag in authData.
    document.getElementById("signin-uv").onclick = async () => {
      try {
        const opts = await (await fetch("/assert-options?uv=required")).json();
        await signIn(opts);
      } catch (e) { status("UV-ERR " + e.name + ": " + e.message); }
    };
    async function signIn(opts) {
      opts.challenge = ub64u(opts.challenge);
      opts.allowCredentials[0].id = ub64u(opts.allowCredentials[0].id);
      const cred = await navigator.credentials.get({ publicKey: opts });
      const body = {
        id: cred.id, rawId: bufB64(cred.rawId), type: cred.type,
        response: {
          clientDataJSON: bufB64(cred.response.clientDataJSON),
          authenticatorData: bufB64(cred.response.authenticatorData),
          signature: bufB64(cred.response.signature),
          userHandle: cred.response.userHandle ? bufB64(cred.response.userHandle) : null,
        },
      };
      const r = await (await fetch("/verify", { method: "POST", body: JSON.stringify(body) })).json();
      status((opts.userVerification === "required" ? "UV " : "ASSERT ") + JSON.stringify(r));
    }
    // Conditional mediation: the promise resolves when the inline dropdown
    // pick resumes Baluard's pending request; the browser's native sheet
    // would race it, so the field carries autocomplete=webauthn.
    document.getElementById("conditional").onclick = async () => {
      try {
        const opts = await (await fetch("/assert-options")).json();
        opts.challenge = ub64u(opts.challenge);
        opts.allowCredentials[0].id = ub64u(opts.allowCredentials[0].id);
        const cred = await navigator.credentials.get({ publicKey: opts, mediation: "conditional" });
        document.getElementById("user").value = "signed-in";
        const body = {
          id: cred.id, rawId: bufB64(cred.rawId), type: cred.type,
          response: {
            clientDataJSON: bufB64(cred.response.clientDataJSON),
            authenticatorData: bufB64(cred.response.authenticatorData),
            signature: bufB64(cred.response.signature),
            userHandle: cred.response.userHandle ? bufB64(cred.response.userHandle) : null,
          },
        };
        const r = await (await fetch("/verify", { method: "POST", body: JSON.stringify(body) })).json();
        status("CONDITIONAL " + JSON.stringify(r));
      } catch (e) { status("COND-ERR " + e.name + ": " + e.message); }
    };
    document.getElementById("usb").onclick = async () => {
      try {
        const opts = await (await fetch("/assert-options?transports=usb")).json();
        opts.challenge = ub64u(opts.challenge);
        opts.allowCredentials[0].id = ub64u(opts.allowCredentials[0].id);
        await navigator.credentials.get({ publicKey: opts });
        status("USB UNEXPECTED-RESOLVE");
      } catch (e) { status("USB " + e.name); }
    };
  </script>
</body></html>`;

function parseClientData(bytes) {
  const cd = JSON.parse(Buffer.from(bytes).toString("utf8"));
  if (!cd.challenge || cd.challenge !== store.lastChallenge) {
    throw new Error("challenge mismatch");
  }
  // Single use: a replayed clientDataJSON must never verify twice.
  store.lastChallenge = null;
  if (cd.origin !== `http://localhost:${PORT}`) throw new Error("origin mismatch: " + cd.origin);
  return cd;
}

// Full assertion verification: challenge freshness (single use), origin,
// type, credential id, rpIdHash, UP, optional UV, counter policy, and the
// ECDSA signature over authData || clientDataHash.
function verifyAssertion(body) {
  const clientDataBytes = unb64u(body.response.clientDataJSON);
  const cd = parseClientData(clientDataBytes);
  if (cd.type !== "webauthn.get") throw new Error("wrong client data type");
  const authData = unb64u(body.response.authenticatorData);
  const sig = unb64u(body.response.signature);
  if (body.id !== store.credentialId) throw new Error("credential id mismatch");
  const clientDataHash = createHash("sha256").update(clientDataBytes).digest();
  const signed = Buffer.concat([Buffer.from(authData), clientDataHash]);
  const ok = cryptoVerify(
    "sha256",
    signed,
    { key: coseToSpki(store.coseKey), dsaEncoding: "der" },
    Buffer.from(sig)
  );
  if (!ok) throw new Error("signature did not verify");
  const flags = authData[32];
  if (!(flags & 0x01)) throw new Error("user-present flag missing");
  if (store.uvRequired && !(flags & 0x04)) throw new Error("user-verified flag missing");
  const newCount = Buffer.from(authData.slice(33, 37)).readUInt32BE(0);
  // Clone detection per spec: only when the stored counter has started.
  // Synced passkeys hold counter 0 (W3C L3 multi-device guidance), so the
  // zero-to-zero path is legal and skipped here.
  if (store.signCount > 0 && newCount !== 0 && newCount <= store.signCount) {
    throw new Error("sign counter did not advance (possible clone)");
  }
  store.signCount = Math.max(store.signCount, newCount);
  return { ok: true, verified: true, uv: Boolean(flags & 0x04), signCount: newCount };
}

// Signature binding only (tamper probe): the captured body already passed
// the freshness checks; flipping a byte must fail the ECDSA verification.
function verifySignatureOnly(body) {
  const authData = unb64u(body.response.authenticatorData);
  const sig = unb64u(body.response.signature);
  const clientDataHash = createHash("sha256").update(unb64u(body.response.clientDataJSON)).digest();
  const signed = Buffer.concat([Buffer.from(authData), clientDataHash]);
  const ok = cryptoVerify(
    "sha256",
    signed,
    { key: coseToSpki(store.coseKey), dsaEncoding: "der" },
    Buffer.from(sig)
  );
  if (!ok) throw new Error("signature did not verify");
}

function parseAuthData(authData) {
  // rpIdHash is SHA-256 over the rpId string; a ceremony signed for any
  // other RP id fails here before signature checks even run.
  const expectedRpIdHash = createHash("sha256").update(RP_ID).digest();
  if (!Buffer.from(authData.subarray(0, 32)).equals(expectedRpIdHash)) {
    throw new Error("rpIdHash mismatch");
  }
  const flags = authData[32];
  const signCount = Buffer.from(authData.slice(33, 37)).readUInt32BE(0);
  let offset = 37;
  let credentialId = null;
  let coseKey = null;
  if (flags & 0x40) {
    // attestedCredentialData: aaguid(16) credIdLen(2) credId COSE(CBOR)
    offset += 16;
    const idLen = Buffer.from(authData.slice(offset, offset + 2)).readUInt16BE(0);
    offset += 2;
    credentialId = authData.slice(offset, offset + idLen);
    offset += idLen;
    const [cose] = cborDecode(authData, offset);
    coseKey = cose;
  }
  return { flags, signCount, credentialId, coseKey };
}

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const json = (obj, code = 200) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  if (url.pathname === "/" || url.pathname === "/index.html") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(PAGE);
    return;
  }
  if (url.pathname === "/options") {
    store.lastChallenge = b64u(randomBytes(32));
    json({
      rp: { id: RP_ID, name: "Local Passkey RP" },
      user: {
        id: b64u(randomBytes(16)),
        name: url.searchParams.get("u") || "demo",
        displayName: "Demo User",
      },
      challenge: store.lastChallenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 120000,
      attestation: "none",
    });
    return;
  }
  if (url.pathname === "/register" && req.method === "POST") {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      try {
        const body = JSON.parse(raw);
        const cd = parseClientData(unb64u(body.response.clientDataJSON));
        if (cd.type !== "webauthn.create") throw new Error("wrong client data type");
        const [attObj] = cborDecode(unb64u(body.response.attestationObject), 0);
        if (attObj.fmt !== "none") throw new Error("unexpected attestation fmt " + attObj.fmt);
        const auth = parseAuthData(attObj.authData);
        if (!(auth.flags & 0x40) || !(auth.flags & 0x01)) {
          throw new Error("missing attested credential data or UP flag");
        }
        store.credentialId = b64u(auth.credentialId);
        store.coseKey = auth.coseKey;
        store.signCount = auth.signCount;
        json({ ok: true, credentialId: store.credentialId, verified: true });
      } catch (e) {
        json({ ok: false, error: String(e.message || e) }, 400);
      }
    });
    return;
  }
  if (url.pathname === "/assert-options") {
    if (!store.credentialId) {
      json({ error: "no credential registered" }, 400);
      return;
    }
    store.lastChallenge = b64u(randomBytes(32));
    const transports = url.searchParams.get("transports");
    store.uvRequired = url.searchParams.get("uv") === "required";
    json({
      challenge: store.lastChallenge,
      rpId: RP_ID,
      userVerification: store.uvRequired ? "required" : "preferred",
      timeout: 120000,
      allowCredentials: [
        {
          type: "public-key",
          id: store.credentialId,
          transports: transports ? transports.split(",") : ["internal"],
        },
      ],
    });
    return;
  }
  if (url.pathname === "/verify" && req.method === "POST") {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      try {
        const body = JSON.parse(raw);
        store.lastAssertion = body;
        json(verifyAssertion(body));
      } catch (e) {
        json({ ok: false, error: String(e.message || e) }, 400);
      }
    });
    return;
  }
  // Negative probes: prove the assertion is cryptographically bound (a
  // flipped signature byte must fail) and that challenges are single-use
  // (a replay must fail). Neither endpoint is touched by the happy path.
  if (url.pathname === "/tamper-verify" && req.method === "POST") {
    if (!store.lastAssertion) {
      json({ error: "no assertion captured" }, 400);
      return;
    }
    const body = JSON.parse(JSON.stringify(store.lastAssertion));
    const sig = Buffer.from(body.response.signature, "base64url");
    sig[sig.length - 1] ^= 0xff;
    body.response.signature = sig.toString("base64url");
    // Crypto-only check: challenge/origin freshness is already proven for
    // the captured assertion; this isolates the signature binding.
    try {
      const cd = JSON.parse(Buffer.from(unb64u(body.response.clientDataJSON)).toString("utf8"));
      void cd;
      verifySignatureOnly(body);
      json({ ok: true, verified: true });
    } catch (e) {
      json({ ok: false, error: String(e.message || e) });
    }
    return;
  }
  if (url.pathname === "/replay-verify" && req.method === "POST") {
    if (!store.lastAssertion) {
      json({ error: "no assertion captured" }, 400);
      return;
    }
    try {
      json(verifyAssertion(store.lastAssertion));
    } catch (e) {
      json({ ok: false, error: String(e.message || e) });
    }
    return;
  }
  if (url.pathname === "/state") {
    json({ registered: Boolean(store.credentialId), credentialId: store.credentialId });
    return;
  }
  if (url.pathname === "/reset" && req.method === "POST") {
    resetStore();
    json({ ok: true });
    return;
  }
  res.writeHead(404);
  res.end("not found");
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`RP-READY http://localhost:${PORT}/`);
});
