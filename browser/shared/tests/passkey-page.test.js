// Unit tests for passkey-page.js — the MAIN-world interception factory.
// The IIFE bundle strips exports, so tests import the factory and drive it
// with fake window/navigator objects and a real MessageChannel.
import { describe, it, expect, vi } from "vitest";
import { SENDER_TAG, MsgType, ErrName } from "../src/passkey-common.js";
import { createPageInterception } from "../src/passkey-page.js";

const enc = (s) => new TextEncoder().encode(s);

function makeEnv(overrides = {}) {
  const messageHandlers = [];
  const posted = [];
  const nativeGet = vi.fn(() => new Promise(() => {}));
  const nativeCreate = vi.fn(() => new Promise(() => {}));
  // The natives live on the PROTOTYPE (as in a real browser), so install()
  // can shadow them with the wrap and restoreNatives can put them back.
  const wrapProto = { create: nativeCreate, get: nativeGet };
  const credentials = Object.create(wrapProto);
  const win = {
    __baluardPasskey: undefined,
    self: null,
    top: null,
    addEventListener: (type, fn) => {
      if (type === "message") messageHandlers.push(fn);
    },
    postMessage: (msg, origin, transfer) => posted.push({ msg, origin, transfer }),
  };
  win.self = win;
  win.top = win;
  const env = {
    window: win,
    navigator: { credentials },
    document: { contentType: "text/html" },
    location: { protocol: "https:", hostname: "rp.example", origin: "https://rp.example" },
    crypto: globalThis.crypto,
    DOMException: globalThis.DOMException,
    AbortController: globalThis.AbortController,
    MessageChannel: globalThis.MessageChannel,
    ...overrides,
    // Never let an override clobber these captures.
    __posted: posted,
    __handlers: messageHandlers,
    __nativeGet: nativeGet,
    __nativeCreate: nativeCreate,
    __wrapProto: wrapProto,
    __credentials: credentials,
  };
  return env;
}

const start = (overrides = {}) => {
  const env = makeEnv(overrides);
  const api = createPageInterception(env);
  api.install();
  api.announce();
  return { env, api, posted: env.__posted, nativeGet: env.__nativeGet, nativeCreate: env.__nativeCreate };
};

const getOpts = (overrides = {}) => ({
  publicKey: { challenge: enc("challenge"), rpId: "rp.example", ...overrides },
});

// Simulate the bridge delivering a response over the transferred port.
function deliver(postedEntry, api, data, type = MsgType.RESPONSE) {
  const port2 = postedEntry.transfer[0];
  port2.postMessage({
    sender: SENDER_TAG,
    contextId: api.contextId,
    type,
    sessionId: postedEntry.msg.sessionId,
    data,
  });
}

describe("eligibility", () => {
  it("returns null for non-html documents", () => {
    const env = makeEnv({ document: { contentType: "application/xhtml+xml" } });
    expect(createPageInterception(env)).toBeNull();
    expect(env.window.__baluardPasskey).toBe(false);
  });

  it("returns null for insecure origins", () => {
    const env = makeEnv({
      location: { protocol: "http:", hostname: "rp.example", origin: "http://rp.example" },
    });
    expect(createPageInterception(env)).toBeNull();
  });

  it("returns null for opaque origins", () => {
    const env = makeEnv({
      location: { protocol: "https:", hostname: "rp.example", origin: "null" },
    });
    expect(createPageInterception(env)).toBeNull();
  });

  it("allows localhost over http", () => {
    const env = makeEnv({
      location: { protocol: "http:", hostname: "localhost", origin: "http://localhost:3000" },
    });
    expect(createPageInterception(env)).not.toBeNull();
  });

  it("refuses a second copy", () => {
    const env = makeEnv();
    const api = createPageInterception(env);
    api.install();
    expect(createPageInterception(env)).toBeNull();
  });
});

describe("install and hello", () => {
  it("wraps navigator.credentials and announces the context id", () => {
    const { env, api, posted } = start();
    expect(env.__credentials.get).not.toBe(env.__nativeGet);
    expect(posted[0].msg.type).toBe(MsgType.HELLO);
    expect(posted[0].msg.sender).toBe(SENDER_TAG);
    expect(posted[0].msg.contextId).toBe(api.contextId);
    expect(posted[0].origin).toBe("https://rp.example");
  });
});

describe("non-publicKey passthrough", () => {
  it("passes non-WebAuthn options through untouched", () => {
    const { env, api, nativeGet, posted } = start();
    env.__credentials.get({ mediation: "optional" });
    expect(nativeGet).toHaveBeenCalledWith({ mediation: "optional" });
    expect(posted).toHaveLength(1); // hello only
  });
});

describe("fallback semantics", () => {
  it("hands USB-only assertions to the browser WITHOUT restoring natives", async () => {
    const { env, api, nativeGet, posted } = start();
    nativeGet.mockResolvedValueOnce("native-credential");
    const result = await api.request("get", {
      publicKey: {
        challenge: enc("challenge"),
        rpId: "rp.example",
        allowCredentials: [{ type: "public-key", id: enc("cred"), transports: ["usb"] }],
      },
    });
    expect(result).toBe("native-credential");
    expect(nativeGet).toHaveBeenCalled();
    // One window message (hello): the fallback never touches the bridge.
    expect(posted).toHaveLength(1);
    expect(api.nativesRestored()).toBe(false);
    expect(env.__credentials.get).not.toBe(env.__nativeGet);
  });

  it("does not restore natives on a FallbackRequested push", async () => {
    const { env, api, nativeGet, posted } = start();
    nativeGet.mockResolvedValueOnce("native-credential");
    const p = api.request("get", getOpts());
    deliver(posted[1], api, { type: "error", name: ErrName.FALLBACK });
    await expect(p).resolves.toBe("native-credential");
    expect(api.nativesRestored()).toBe(false);
    expect(env.__credentials.get).not.toBe(env.__nativeGet);
  });

  it("rejects plain errors as DOMExceptions in the page world", async () => {
    const { api, posted } = start();
    const p = api.request("get", getOpts());
    deliver(posted[1], api, { type: "error", name: "NotAllowedError", message: "declined" });
    await expect(p).rejects.toMatchObject({ name: "NotAllowedError" });
  });
});

describe("destroy semantics", () => {
  function dispatchDestroy(api, env, contextId) {
    for (const fn of env.__handlers) {
      fn({ source: env.window, data: { sender: SENDER_TAG, contextId, type: MsgType.DESTROY } });
    }
  }

  it("restores natives and rejects pending ceremonies on a stamped DESTROY", async () => {
    const { env, api, posted } = start();
    const p = api.request("get", getOpts());
    dispatchDestroy(api, env, api.contextId);
    await expect(p).rejects.toMatchObject({ name: "NotAllowedError" });
    expect(api.nativesRestored()).toBe(true);
    expect(env.window.__baluardPasskey).toBe(false);
    // The restored binding wraps the native spy: a passthrough call lands
    // on it directly.
    env.__credentials.get({ mediation: "optional" });
    expect(env.__nativeGet).toHaveBeenCalledWith({ mediation: "optional" });
  });

  it("ignores DESTROY with a foreign context id", () => {
    const { env, api, posted } = start();
    const p = api.request("get", getOpts());
    dispatchDestroy(api, env, "not-my-context");
    expect(api.nativesRestored()).toBe(false);
    expect(api.pendingCount()).toBe(1);
    void p;
  });

  it("ignores an unstamped DESTROY (blocker: natives must never strand)", () => {
    const { env, api, posted } = start();
    const p = api.request("get", getOpts());
    dispatchDestroy(api, env, undefined);
    expect(api.nativesRestored()).toBe(false);
    expect(api.pendingCount()).toBe(1);
    void p;
  });
});

describe("conditional race", () => {
  const conditional = () => ({
    publicKey: { challenge: enc("challenge"), rpId: "rp.example" },
    mediation: "conditional",
  });

  it("starts a native conditional get in parallel", () => {
    const { api, nativeGet, posted } = start();
    api.request("get", conditional());
    expect(nativeGet).toHaveBeenCalledTimes(1);
    expect(nativeGet.mock.calls[0][0].mediation).toBe("conditional");
    expect(nativeGet.mock.calls[0][0].signal).toBeInstanceOf(AbortSignal);
    expect(nativeGet.mock.calls[0][0].signal.aborted).toBe(false);
    expect(posted).toHaveLength(2); // hello + GET
  });

  it("aborts the native leg when Baluard wins", async () => {
    const { api, nativeGet, posted } = start();
    const p = api.request("get", conditional());
    const nativeSignal = nativeGet.mock.calls[0][0].signal;
    deliver(posted[1], api, {
      type: "success",
      credential: { rawId: btoa("cred"), response: { clientDataJSON: btoa("{}") } },
    });
    const cred = await p;
    expect(cred.id).toBeTruthy();
    expect(nativeSignal.aborted).toBe(true);
  });

  it("tells the SW to drop the session when the native leg wins", async () => {
    const { api, nativeGet, posted } = start();
    nativeGet.mockResolvedValueOnce("native-credential");
    const p = api.request("get", conditional());
    const port2 = posted[1].transfer[0];
    const inner = [];
    port2.onmessage = (ev) => inner.push(ev.data);
    await expect(p).resolves.toBe("native-credential");
    // Port delivery rides the microtask queue; give it a macrotask.
    await new Promise((r) => setTimeout(r, 20));
    expect(inner.some((m) => m.type === MsgType.ABORT)).toBe(true);
  });

  it("swallows Baluard errors and lets the native sheet decide", async () => {
    const { api, nativeGet, posted } = start();
    const p = api.request("get", conditional());
    deliver(posted[1], api, { type: "error", name: "NotAllowedError", message: "locked vault" });
    await new Promise((r) => setTimeout(r, 5));
    // Still pending: no rejection raced the native leg.
    let settled = false;
    p.then(() => {}, () => {}).finally(() => (settled = true));
    await new Promise((r) => setTimeout(r, 5));
    expect(settled).toBe(false);
  });

  it("propagates the user's abort to both legs", async () => {
    const { api, posted } = start();
    const userSignal = new AbortController();
    const p = api.request("get", { ...conditional(), signal: userSignal.signal });
    userSignal.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
  });
});

describe("page timeout", () => {
  it("settles a non-conditional ceremony with NotAllowedError", async () => {
    vi.useFakeTimers();
    try {
      const { api, posted } = start();
      const p = api.request("get", { publicKey: { challenge: enc("challenge"), rpId: "rp.example", timeout: 30000 } });
      const port2 = posted[1].transfer[0];
      const inner = [];
      port2.onmessage = (ev) => inner.push(ev.data);
      // Attach the rejection handler BEFORE the timer fires, or Node flags
      // the pending rejection as unhandled.
      const assertion = expect(p).rejects.toMatchObject({
        name: "NotAllowedError",
        message: "The operation timed out",
      });
      await vi.advanceTimersByTimeAsync(31000);
      await assertion;
      expect(inner.some((m) => m.type === MsgType.ABORT)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("leaves conditional ceremonies pending past the timeout", async () => {
    vi.useFakeTimers();
    try {
      const { api } = start();
      const p = api.request("get", {
        publicKey: { challenge: enc("challenge"), rpId: "rp.example", timeout: 30000 },
        mediation: "conditional",
      });
      await vi.advanceTimersByTimeAsync(31000);
      let settled = false;
      p.then(() => {}, () => {}).finally(() => (settled = true));
      await vi.advanceTimersByTimeAsync(10);
      expect(settled).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("rebuild", () => {
  it("resolves spec-shaped credentials from a success push", async () => {
    const { api, posted } = start();
    const p = api.request("create", {
      publicKey: { challenge: enc("challenge"), rp: { id: "rp.example" }, user: { id: enc("u") }, pubKeyCredParams: [{ type: "public-key", alg: -7 }] },
    });
    deliver(posted[1], api, {
      type: "success",
      credential: {
        rawId: btoa("credential-id"),
        response: { clientDataJSON: btoa("{}"), attestationObject: btoa("attobj") },
      },
    });
    const cred = await p;
    expect(cred.rawId instanceof ArrayBuffer).toBe(true);
    expect(cred.response.getTransports()).toEqual([]);
  });
});
