// Unit tests for passkey-client.js — the SW-side WebAuthn client.
// The browser surfaces (popout window, focus) are injected fakes; send is a
// scripted daemon mock so every flow is asserted at the NMH boundary.
import { describe, it, expect, vi } from "vitest";
import { createPasskeyClient } from "../src/passkey-client.js";

function makeClient({ sendScript, openPopout, focusTab, sessionStore } = {}) {
  const pushed = []; // every port.postMessage payload
  const removedWindows = [];
  const port = {
    sender: { tab: { id: 7, url: "https://rp.example/login" }, origin: "https://rp.example", frameId: 0 },
    postMessage: vi.fn((m) => pushed.push(m)),
    onDisconnect: { addListener: vi.fn() },
  };
  const popovers = [];
  const client = createPasskeyClient(sendScript || vi.fn(), {
    sessionStore,
    openPopout:
      openPopout ||
      ((session) => {
        session.windowId = 4242;
        popovers.push(session.uiKind);
      }),
    focusTab: focusTab || vi.fn(),
  });
  client.onBridgePort(port);
  return { client, port, pushed, popovers, popoutSpy: openPopout, removedWindows };
}

const sender = {
  tab: { id: 7, url: "https://rp.example/login" },
  origin: "https://rp.example",
  frameId: 0,
};
const createPayload = (overrides = {}) => ({
  sessionId: "s-1",
  contextId: "ctx-1",
  options: {
    rp: { id: "rp.example", name: "RP Example" },
    user: { id: "dXNlcg", name: "u@rp.example", displayName: "U" },
    challenge: "Y2hhbGxlbmdl",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 300000,
  },
  requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
  ...overrides,
});

const daemonOk = (payload) => ({ ok: true, payload: JSON.stringify(payload) });
// The client passes payload OBJECTS to send (background.js stringifies at
// the NMH layer), so mocks normalize both shapes.
const P = (p) => (typeof p === "string" ? JSON.parse(p) : p);
const b64Json = (b64) => JSON.parse(new TextDecoder().decode(b64urlToBytes(b64)));
function b64urlToBytes(s) {
  let b = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b.length % 4 !== 0) b += "=";
  return Uint8Array.from(atob(b), (c) => c.charCodeAt(0));
}
const pkRow = (id, extra = {}) => ({
  id: "cipher-1",
  login_name: "RP Login",
  has_password: true,
  pk_name: "rp.example",
  favorite: false,
  rp_id: "rp.example",
  rp_name: "RP Example",
  user_name: "u@rp.example",
  credential_id: id,
  counter: 0,
  private_key_missing: false,
  vault_slug: "main",
  ...extra,
});

// The SW mints session ids; tests grab the live session instead of guessing.
const onlySession = (client) => {
  const all = client.activeSessions();
  return all.length === 1 ? all[0] : all;
};

describe("create flow", () => {
  it("validates origin from the SENDER, not the page", async () => {
    const { client, pushed } = makeClient();
    const hostile = { ...sender, origin: "https://evil.example", tab: { ...sender.tab, url: "https://evil.example/x" } };
    const r = await client.handleCreateRequest(hostile, createPayload());
    expect(r.error).toBe("SecurityError");
    expect(pushed).toHaveLength(0);
  });

  it("rejects cross-origin iframes", async () => {
    const { client, pushed } = makeClient();
    const r = await client.handleCreateRequest(
      sender,
      createPayload({ requested: { origin: "https://rp.example", sameOriginWithAncestors: false } })
    );
    expect(r.error).toBe("NotAllowedError");
    expect(pushed).toHaveLength(0);
  });

  it("falls back when the desktop is unreachable", async () => {
    const send = vi.fn().mockRejectedValue(Object.assign(new Error("Cannot reach"), { code: "no-daemon" }));
    const { client, pushed } = makeClient({ sendScript: send });
    const r = await client.handleCreateRequest(sender, createPayload());
    expect(r.accepted).toBe(true);
    expect(pushed[0].data).toEqual({
      type: "error",
      name: "FallbackRequested",
      message: "handed to the browser",
    });
  });

  it("opens the locked prompt when the vault is locked", async () => {
    const send = vi.fn().mockRejectedValue(Object.assign(new Error("locked"), { code: "locked" }));
    const { client, pushed, popovers } = makeClient({ sendScript: send });
    await client.handleCreateRequest(sender, createPayload());
    expect(popovers).toEqual(["locked"]);
    expect(pushed).toHaveLength(0);
    expect(client.uiState(onlySession(client).id).kind).toBe("locked");
  });

  it("confirm-then-sign: registers and stores with the chosen save target", async () => {
    const send = vi.fn(async (action, payload) => {
      const v = P(payload);
      if (action === "passkey.list") return daemonOk([]);
      if (action === "bridge.match")
        return daemonOk({ matches: [{ id: "cipher-9", name: "RP Login", username: "u", vault_slug: "main" }] });
      if (action === "passkey.provider_register") {
        expect(v.origin).toBe("https://rp.example");
        expect(v.user_verified).toBe(false);
        const cdj = b64Json(v.client_data_json_b64);
        expect(cdj.type).toBe("webauthn.create");
        expect(cdj.challenge).toBe("Y2hhbGxlbmdl");
        expect(cdj.origin).toBe("https://rp.example");
        expect(JSON.parse(v.request_json).rp.id).toBe("rp.example");
        return daemonOk({ ceremony_id: "c-reg", attestation_response: { rawId: "abc" } });
      }
      if (action === "passkey.store_registered") {
        expect(v.ceremony_id).toBe("c-reg");
        expect(v.cipher_id).toBe("cipher-9");
        expect(v.new_login).toBeUndefined();
        expect(v.vault_slug).toBe("main");
        return daemonOk({ cipher_id: "cipher-9" });
      }
      throw new Error("unexpected action " + action);
    });
    const { client, pushed } = makeClient({ sendScript: send });
    await client.handleCreateRequest(sender, createPayload());
    const sid = onlySession(client).id;
    expect(client.uiState(sid).siteRows).toHaveLength(1);
    const r = await client.uiDecide(sid, { kind: "confirmRegister", cipher_id: "cipher-9", vault_slug: "main" });
    expect(r.ok).toBe(true);
    expect(pushed[0].data.type).toBe("success");
    expect(pushed[0].data.credential).toEqual({ rawId: "abc" });
    expect(client.uiState(sid).gone).toBe(true);
    // The page keeps its own id across the port push; the SW id is separate.
    expect(pushed[0].sessionId).toBe("s-1");
  });

  it("reports presence only: never claims user_verified, even when the RP required it", async () => {
    const uvs = [];
    const send = vi.fn(async (action, payload) => {
      if (action === "passkey.list") return daemonOk([]);
      if (action === "bridge.match") return daemonOk({ matches: [] });
      if (action === "passkey.provider_register") {
        uvs.push(P(payload).user_verified);
        return daemonOk({ ceremony_id: "c", attestation_response: { rawId: "abc" } });
      }
      if (action === "passkey.store_registered") return daemonOk({});
      throw new Error("unexpected " + action);
    });
    const { client } = makeClient({ sendScript: send });
    const payload = createPayload();
    payload.options.authenticatorSelection = { userVerification: "required" };
    await client.handleCreateRequest(sender, payload);
    await client.uiDecide(onlySession(client).id, { kind: "confirmRegister", new_login: { name: "RP Example" } });
    // A picker pick proves presence; the daemon fail-closes UV-required
    // ceremonies (passkey:uv-required) instead of trusting this flag.
    expect(uvs).toEqual([false]);
  });

  it("maps the duplicate-credential daemon error to the excluded screen", async () => {
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([]);
      if (action === "bridge.match") return daemonOk({ matches: [] });
      if (action === "passkey.provider_register")
        throw Object.assign(new Error("a passkey for this site already exists in the vault; use the existing one"), {
          code: "denied",
        });
      throw new Error("unexpected " + action);
    });
    const { client, pushed, popovers } = makeClient({ sendScript: send });
    await client.handleCreateRequest(sender, createPayload());
    await client.uiDecide(onlySession(client).id, { kind: "confirmRegister", new_login: { name: "RP" } });
    expect(popovers).toEqual(["confirmRegister", "excluded"]);
    expect(pushed).toHaveLength(0);
    // Dismissing the info screen declines the ceremony.
    await client.uiDecide(onlySession(client).id, { kind: "dismiss" });
    expect(pushed[0].data).toEqual({ type: "error", name: "NotAllowedError", message: "declined in Baluard" });
  });
});

describe("assertion flow", () => {
  it("shows the picker even for a single credential without UV (Bitwarden parity)", async () => {
    const calls = [];
    const send = vi.fn(async (action, payload) => {
      calls.push([action, P(payload)]);
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      if (action === "passkey.provider_assert") {
        const v = P(payload);
        return daemonOk({ ceremony_id: "c-a", assertion_response: { rawId: "cred-1" }, new_counter: 0 });
      }
      if (action === "passkey.consume_assertion") return daemonOk({ recorded: 0 });
      throw new Error("unexpected " + action);
    });
    const { client, pushed, popovers } = makeClient({ sendScript: send });
    const r = await client.handleGetRequest(sender, {
      sessionId: "s-2",
      contextId: "ctx-1",
      options: { challenge: "Y2g", rpId: "rp.example", timeout: 120000 },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    });
    expect(r.accepted).toBe(true);
    // Nothing is signed until the user confirms the popout.
    expect(popovers).toEqual(["pickAssertion"]);
    expect(calls.some(([a]) => a === "passkey.provider_assert")).toBe(false);
    await client.uiDecide(onlySession(client).id, { kind: "pickAssertion", credential_id: "cred-1" });
    const assertCall = calls.find(([a]) => a === "passkey.provider_assert");
    expect(assertCall[1].credential_id).toBe("cred-1");
    expect(assertCall[1].user_verified).toBe(false);
    expect(assertCall[1].vault_slug).toBe("main");
    const cdj = b64Json(assertCall[1].client_data_json_b64);
    expect(cdj.type).toBe("webauthn.get");
    expect(calls.some(([a]) => a === "passkey.consume_assertion")).toBe(true);
    expect(pushed[0].data.type).toBe("success");
    expect(pushed[0].data.credential).toEqual({ rawId: "cred-1" });
  });

  it("picks via the popout for multiple candidates", async () => {
    const send = vi.fn(async (action, payload) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1"), pkRow("cred-2", { id: "cipher-2" })]);
      if (action === "passkey.provider_assert") {
        const v = P(payload);
        expect(v.credential_id).toBe("cred-2");
        expect(v.user_verified).toBe(false);
        return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-2" } });
      }
      if (action === "passkey.consume_assertion") return daemonOk({ recorded: 0 });
      throw new Error("unexpected " + action);
    });
    const { client, pushed, popovers } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, {
      sessionId: "s-3",
      contextId: "ctx-1",
      options: { challenge: "Y2g", rpId: "rp.example" },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    });
    expect(popovers).toEqual(["pickAssertion"]);
    await client.uiDecide(onlySession(client).id, { kind: "pickAssertion", credential_id: "cred-2" });
    expect(pushed[0].data.credential).toEqual({ rawId: "cred-2" });
  });

  it("shows the picker when the RP requires user verification", async () => {
    const send = vi.fn(async (action, payload) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      if (action === "passkey.provider_assert")
        return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-1" } });
      if (action === "passkey.consume_assertion") return daemonOk({});
      throw new Error("unexpected " + action);
    });
    const { client, popovers } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, {
      sessionId: "s-4",
      contextId: "ctx-1",
      options: { challenge: "Y2g", rpId: "rp.example", userVerification: "required" },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    });
    expect(popovers).toEqual(["pickAssertion"]);
    await client.uiDecide(onlySession(client).id, { kind: "pickAssertion", credential_id: "cred-1" });
    const assertPayload = P(
      send.mock.calls.find(([a]) => a === "passkey.provider_assert")[1]
    );
    expect(assertPayload.user_verified).toBe(false);
  });

  it("surfaces the uv-required refusal as a plain NotAllowedError", async () => {
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      if (action === "passkey.provider_assert")
        return Promise.reject(Object.assign(new Error("passkey:uv-required"), { code: "proto" }));
      throw new Error("unexpected " + action);
    });
    const { client, pushed } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, {
      sessionId: "s-9",
      contextId: "ctx-1",
      options: { challenge: "Y2g", rpId: "rp.example", userVerification: "required" },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    });
    await client.uiDecide(onlySession(client).id, { kind: "pickAssertion", credential_id: "cred-1" });
    expect(pushed[0].data).toEqual({
      type: "error",
      name: "NotAllowedError",
      message: "This site requires user verification that Baluard cannot provide",
    });
  });

  it("filters candidates by allowCredentials and informs when none match", async () => {
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      throw new Error("unexpected " + action);
    });
    const { client, pushed, popovers } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, {
      sessionId: "s-5",
      contextId: "ctx-1",
      options: {
        challenge: "Y2g",
        rpId: "rp.example",
        allowCredentials: [{ type: "public-key", id: "other-cred" }],
      },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    });
    expect(popovers).toEqual(["notFound"]);
    await client.uiDecide(onlySession(client).id, { kind: "dismiss" });
    expect(pushed[0].data.name).toBe("NotAllowedError");
  });
});

describe("conditional mediation", () => {
  const conditionalPayload = (overrides = {}) => ({
    sessionId: "s-cond",
    contextId: "ctx-1",
    options: { challenge: "Y2g", rpId: "rp.example" },
    requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    mediation: "conditional",
    ...overrides,
  });

  it("holds the request open and exposes candidates to the inline menu", async () => {
    const send = vi.fn(async () => daemonOk([pkRow("cred-1")]));
    const { client } = makeClient({ sendScript: send });
    const r = await client.handleGetRequest(sender, conditionalPayload());
    expect(r.accepted).toBe(true);
    const inline = await client.handleInlinePasskeys(sender);
    expect(inline.rows).toHaveLength(1);
    expect(inline.rows[0].credential_id).toBe("cred-1");
    expect(inline.rows[0].vault_slug).toBe("main");
    // Another tab sees nothing.
    const otherTab = { tab: { id: 8, url: "https://rp.example/" } };
    expect((await client.handleInlinePasskeys(otherTab)).rows).toHaveLength(0);
  });

  it("continues the assertion when the inline menu picks a credential", async () => {
    const send = vi.fn(async (action, payload) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      if (action === "passkey.provider_assert")
        return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-1" } });
      if (action === "passkey.consume_assertion") return daemonOk({});
      throw new Error("unexpected " + action);
    });
    const { client, pushed } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, conditionalPayload());
    // The dropdown awaits the candidate list before rendering, mirroring
    // handleInlinePasskeys.
    await client.handleInlinePasskeys(sender);
    const r = await client.handleInlinePick(sender, "cred-1");
    expect(r.accepted).toBe(true);
    expect(pushed[0].data.type).toBe("success");
    expect((await client.handleInlinePasskeys(sender)).rows).toHaveLength(0);
  });

  it("respects allowCredentials narrowing in the inline list", async () => {
    const send = vi.fn(async () => daemonOk([pkRow("cred-1"), pkRow("cred-2", { id: "cipher-2" })]));
    const { client } = makeClient({ sendScript: send });
    await client.handleGetRequest(
      sender,
      conditionalPayload({
        options: { challenge: "Y2g", rpId: "rp.example", allowCredentials: [{ type: "public-key", id: "cred-2" }] },
      })
    );
    expect((await client.handleInlinePasskeys(sender)).rows.map((r) => r.credential_id)).toEqual(["cred-2"]);
  });

  it("abort removes the pending session", async () => {
    const send = vi.fn(async () => daemonOk([pkRow("cred-1")]));
    const { client } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, conditionalPayload());
    client.handleAbortRequest(sender, "s-cond");
    expect((await client.handleInlinePasskeys(sender)).rows).toHaveLength(0);
  });
});

describe("popout lifecycle", () => {
  it("closing the popout hands the ceremony back to the browser", async () => {
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([]);
      if (action === "bridge.match") return daemonOk({ matches: [] });
      throw new Error("unexpected " + action);
    });
    const { client, pushed } = makeClient({ sendScript: send });
    await client.handleCreateRequest(sender, createPayload());
    client.popoutClosed(4242);
    expect(pushed[0].data.name).toBe("FallbackRequested");
    expect(client.activeSessions()).toHaveLength(0);
  });

  it("tab cleanup drops sessions and closes the popout", async () => {
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([]);
      if (action === "bridge.match") return daemonOk({ matches: [] });
      throw new Error("unexpected " + action);
    });
    let removed = 0;
    const origRemove = globalThis.chrome?.windows?.remove;
    // uiDecide-less cleanup path only touches sessions + ports.
    const { client } = makeClient({ sendScript: send });
    await client.handleCreateRequest(sender, createPayload());
    await client.cleanupTab(7);
    expect(client.activeSessions()).toHaveLength(0);
    void removed;
    void origRemove;
  });

  it("retryUnlock resumes a pending assertion after unlock", async () => {
    let locked = true;
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") {
        if (locked) throw Object.assign(new Error("locked"), { code: "locked" });
        return daemonOk([pkRow("cred-1")]);
      }
      if (action === "passkey.provider_assert")
        return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-1" } });
      if (action === "passkey.consume_assertion") return daemonOk({});
      throw new Error("unexpected " + action);
    });
    const { client, pushed } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, {
      sessionId: "s-lock",
      contextId: "ctx-1",
      options: { challenge: "Y2g", rpId: "rp.example" },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    });
    const sid = onlySession(client).id;
    expect(client.uiState(sid).kind).toBe("locked");
    locked = false;
    const r = await client.uiDecide(sid, { kind: "retryUnlock" });
    expect(r.ok).toBe(true);
    // Unlocking alone never signs; the picker still needs a decision.
    expect(client.uiState(sid).kind).toBe("pickAssertion");
    expect(pushed).toHaveLength(0);
    await client.uiDecide(sid, { kind: "pickAssertion", credential_id: "cred-1" });
    expect(pushed[0].data.type).toBe("success");
  });
});

describe("review fixes", () => {
  it("refuses non-top-frame senders", async () => {
    const { client, pushed } = makeClient();
    const r = await client.handleCreateRequest({ ...sender, frameId: 1 }, createPayload());
    expect(r.error).toBe("SecurityError");
    expect(pushed).toHaveLength(0);
  });

  it("prefers sender.origin over the tab url", async () => {
    // Tab url says plain http (would fail the secure-context check on a
    // non-localhost host); the isolated-world origin is authoritative.
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      if (action === "passkey.provider_assert") return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-1" } });
      if (action === "passkey.consume_assertion") return daemonOk({});
      throw new Error("unexpected " + action);
    });
    const pushed = [];
    const client = createPasskeyClient(send, {
      openPopout: (session) => { session.windowId = 2; },
      focusTab: vi.fn(),
    });
    client.onBridgePort({
      sender: { origin: "https://rp.example", frameId: 0, tab: { id: 7, url: "http://rp.example/login" } },
      postMessage: (m) => pushed.push(m),
      onDisconnect: { addListener: vi.fn() },
    });
    const r = await client.handleGetRequest(
      { origin: "https://rp.example", frameId: 0, tab: { id: 7, url: "http://rp.example/login" } },
      {
        sessionId: "s-orig",
        contextId: "ctx",
        options: { challenge: "Y2g", rpId: "rp.example" },
        requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
      }
    );
    expect(r.accepted).toBe(true);
    await client.uiDecide(onlySession(client).id, { kind: "pickAssertion", credential_id: "cred-1" });
    expect(pushed[0].data.type).toBe("success");
  });

  it("supersedes a previous session on the same tab", async () => {
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([]);
      if (action === "bridge.match") return daemonOk({ matches: [] });
      throw new Error("unexpected " + action);
    });
    const { client, pushed } = makeClient({ sendScript: send });
    await client.handleCreateRequest(sender, createPayload({ sessionId: "first" }));
    await client.handleCreateRequest(sender, createPayload({ sessionId: "second" }));
    expect(client.activeSessions()).toHaveLength(1);
    expect(pushed[0].data.type).toBe("error");
    expect(pushed[0].data.name).toBe("NotAllowedError");
    expect(pushed[0].sessionId).toBe("first");
  });

  it("enforces the clamped timeout with a NotAllowedError", async () => {
    vi.useFakeTimers();
    try {
      const send = vi.fn(async (action) => {
        if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
        if (action === "passkey.provider_assert") return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-1" } });
        if (action === "passkey.consume_assertion") return daemonOk({});
        throw new Error("unexpected " + action);
      });
      // The popout picker keeps the ceremony pending; requiring UV pins the
      // UV-confirm path while the timer is observable.
      const { client, pushed } = makeClient({ sendScript: send });
      await client.handleGetRequest(sender, {
        sessionId: "s-timeout",
        contextId: "ctx",
        options: { challenge: "Y2g", rpId: "rp.example", userVerification: "required", timeout: 60000 },
        requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
      });
      expect(client.activeSessions()).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(60001);
      expect(client.activeSessions()).toHaveLength(0);
      expect(pushed[0].data.name).toBe("NotAllowedError");
    } finally {
      vi.useRealTimers();
    }
  });

  it("abort closes the popout and drops the session", async () => {
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([]);
      if (action === "bridge.match") return daemonOk({ matches: [] });
      throw new Error("unexpected " + action);
    });
    const { client } = makeClient({ sendScript: send });
    await client.handleCreateRequest(sender, createPayload({ sessionId: "page-1" }));
    expect(client.activeSessions()).toHaveLength(1);
    await client.handleAbortRequest(sender, "page-1");
    expect(client.activeSessions()).toHaveLength(0);
  });

  it("finishes the session even when the page push fails", async () => {
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      if (action === "passkey.provider_assert") return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-1" } });
      if (action === "passkey.consume_assertion") return daemonOk({});
      throw new Error("unexpected " + action);
    });
    const client = createPasskeyClient(send, {
      openPopout: (s) => { s.windowId = 9; },
      focusTab: vi.fn(),
    });
    // No bridge port connected: every push fails.
    const r = await client.handleGetRequest(sender, {
      sessionId: "s-nopush",
      contextId: "ctx",
      options: { challenge: "Y2g", rpId: "rp.example" },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    });
    expect(r.accepted).toBe(true);
    await client.uiDecide(onlySession(client).id, { kind: "pickAssertion", credential_id: "cred-1" });
    expect(client.activeSessions()).toHaveLength(0);
  });

  it("re-lists candidates when the cached conditional list is empty", async () => {
    let locked = true;
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") {
        if (locked) throw Object.assign(new Error("locked"), { code: "locked" });
        return daemonOk([pkRow("cred-1")]);
      }
      throw new Error("unexpected " + action);
    });
    const { client } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, {
      sessionId: "s-cond2",
      contextId: "ctx",
      options: { challenge: "Y2g", rpId: "rp.example" },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
      mediation: "conditional",
    });
    expect((await client.handleInlinePasskeys(sender)).rows).toHaveLength(0);
    locked = false;
    expect((await client.handleInlinePasskeys(sender)).rows).toHaveLength(1);
  });

  it("filters private_key_missing rows out of assertions", async () => {
    const send = vi.fn(async (action, payload) => {
      if (action === "passkey.list")
        return daemonOk([pkRow("cred-missing", { private_key_missing: true, id: "cipher-2" }), pkRow("cred-good")]);
      if (action === "passkey.provider_assert") {
        expect(P(payload).credential_id).toBe("cred-good");
        return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-good" } });
      }
      if (action === "passkey.consume_assertion") return daemonOk({});
      throw new Error("unexpected " + action);
    });
    const { client, pushed } = makeClient({ sendScript: send });
    await client.handleGetRequest(sender, {
      sessionId: "s-filter",
      contextId: "ctx",
      options: { challenge: "Y2g", rpId: "rp.example" },
      requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    });
    await client.uiDecide(onlySession(client).id, { kind: "pickAssertion", credential_id: "cred-good" });
    expect(pushed[0].data.type).toBe("success");
  });
});

describe("parked session survival", () => {
  const conditionalPayload = (overrides = {}) => ({
    sessionId: "s-cond",
    contextId: "ctx-1",
    options: { challenge: "Y2g", rpId: "rp.example" },
    requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
    mediation: "conditional",
    ...overrides,
  });

  // A Map-backed storage.session: in-memory, browser-lifetime, the same
  // surface the production code reads.
  const makeStore = () => {
    const map = new Map();
    return {
      map,
      get: async (key) => (map.has(key) ? { [key]: map.get(key) } : {}),
      set: async (obj) => {
        for (const [k, v] of Object.entries(obj)) map.set(k, v);
      },
      remove: async (key) => {
        map.delete(key);
      },
    };
  };

  const assertScript = () =>
    vi.fn(async (action, payload) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      if (action === "passkey.provider_assert")
        return daemonOk({ ceremony_id: "c", assertion_response: { rawId: "cred-1" } });
      if (action === "passkey.consume_assertion") return daemonOk({});
      throw new Error("unexpected " + action);
    });

  it("persists undecided conditional sessions as a clean projection", async () => {
    const store = makeStore();
    const send = vi.fn(async () => daemonOk([pkRow("cred-1")]));
    const { client } = makeClient({ sendScript: send, sessionStore: store });
    await client.handleGetRequest(sender, conditionalPayload());
    const parked = store.map.get("pkParked");
    expect(Array.isArray(parked)).toBe(true);
    expect(parked).toHaveLength(1);
    expect(parked[0].mode).toBe("get");
    expect(parked[0].conditional).toBe(true);
    expect(parked[0].tabId).toBe(7);
    expect(parked[0].origin).toBe("https://rp.example");
    expect(parked[0].rpId).toBe("rp.example");
    expect(parked[0].options.challenge).toBe("Y2g");
    expect(parked[0].expiresAt).toBeGreaterThan(Date.now());
    // Handles and promises must never reach storage.
    expect(parked[0].rowsPromise).toBeUndefined();
    expect(parked[0].timer).toBeUndefined();
    // Round-trips through JSON untouched (storage.session stores
    // structured clones, but the projection must be serializable anyway).
    expect(JSON.parse(JSON.stringify(parked))).toEqual(parked);
  });

  it("resumes a parked ceremony on a restarted worker and completes the pick", async () => {
    const store = makeStore();
    const send = assertScript();
    const first = makeClient({ sendScript: send, sessionStore: store });
    await first.client.handleGetRequest(sender, conditionalPayload());
    // The SW restarts; the fresh instance restores the parked session.
    const second = makeClient({ sendScript: assertScript(), sessionStore: store });
    const restored = await second.client.restoreParked();
    expect(restored).toBe(1);
    expect(second.client.activeSessions()).toHaveLength(1);
    const inline = await second.client.handleInlinePasskeys(sender);
    expect(inline.rows).toHaveLength(1);
    const r = await second.client.handleInlinePick(sender, "cred-1");
    expect(r.accepted).toBe(true);
    expect(second.pushed[0].data.type).toBe("success");
    // The finished ceremony must not linger in storage.
    expect(await second.client.restoreParked()).toBe(0);
  });

  it("keeps the expiry clock across repeated restarts", async () => {
    const store = makeStore();
    const first = makeClient({ sendScript: vi.fn(async () => daemonOk([pkRow("cred-1")])), sessionStore: store });
    await first.client.handleGetRequest(sender, conditionalPayload());
    const before = store.map.get("pkParked")[0].expiresAt;
    const second = makeClient({ sendScript: vi.fn(), sessionStore: store });
    expect(await second.client.restoreParked()).toBe(1);
    // The rewrite must not strip the clock: entry stays resumable.
    const entry = store.map.get("pkParked")[0];
    expect(entry.id).toBe(second.client.activeSessions()[0].id);
    expect(entry.expiresAt).toBe(before);
    const third = makeClient({ sendScript: vi.fn(), sessionStore: store });
    expect(await third.client.restoreParked()).toBe(1);
  });

  it("never surfaces a parked session to a different origin on the same tab", async () => {
    const store = makeStore();
    const first = makeClient({ sendScript: vi.fn(async () => daemonOk([pkRow("cred-1")])), sessionStore: store });
    await first.client.handleGetRequest(sender, conditionalPayload());
    const second = makeClient({ sendScript: vi.fn(async () => daemonOk([pkRow("cred-1")])), sessionStore: store });
    await second.client.restoreParked();
    // The user navigated tab 7 elsewhere; the new document's ask must not
    // see (or let a user pick from) the old origin's session.
    const navigate = { tab: { id: 7, url: "https://evil.example/" }, origin: "https://evil.example", frameId: 0 };
    expect((await second.client.handleInlinePasskeys(navigate)).rows).toHaveLength(0);
    expect(await second.client.handleInlinePick(navigate, "cred-1")).toEqual({ error: "no session" });
    // The honest origin still resumes it.
    expect((await second.client.handleInlinePasskeys(sender)).rows).toHaveLength(1);
  });

  it("does not resurrect a session whose pick is already in flight", async () => {
    const store = makeStore();
    let releaseAssertion;
    const gate = new Promise((r) => (releaseAssertion = r));
    const send = vi.fn(async (action) => {
      if (action === "passkey.list") return daemonOk([pkRow("cred-1")]);
      if (action === "passkey.provider_assert") await gate;
      if (action === "passkey.consume_assertion") return daemonOk({});
      return daemonOk({});
    });
    const first = makeClient({ sendScript: send, sessionStore: store });
    await first.client.handleGetRequest(sender, conditionalPayload());
    await first.client.handleInlinePasskeys(sender);
    const picking = first.client.handleInlinePick(sender, "cred-1");
    await new Promise((r) => setTimeout(r, 10));
    // The SW dies mid-assertion: the parked projection must be empty.
    const restart = makeClient({ sendScript: vi.fn(), sessionStore: store });
    expect(await restart.client.restoreParked()).toBe(0);
    releaseAssertion();
    expect((await picking).accepted).toBe(true);
  });

  it("drops expired and malformed parked entries instead of resuming them", async () => {
    const store = makeStore();
    const valid = {
      id: "park-ok",
      pageId: "s-page",
      contextId: "ctx",
      tabId: 7,
      mode: "get",
      conditional: true,
      origin: "https://rp.example",
      rpId: "rp.example",
      requiresUv: false,
      options: { challenge: "Y2g", rpId: "rp.example" },
      expiresAt: Date.now() + 60000,
    };
    store.map.set("pkParked", [
      { ...valid, id: "park-old", expiresAt: Date.now() - 1000 },
      "garbage",
      { ...valid, id: "park-create", mode: "create" },
      { ...valid, id: "park-insecure", origin: "http://insecure.example" },
      { ...valid, id: "park-noopts", options: null },
      valid,
    ]);
    const { client } = makeClient({ sendScript: vi.fn(), sessionStore: store });
    expect(await client.restoreParked()).toBe(1);
    const live = client.activeSessions();
    expect(live).toHaveLength(1);
    expect(live[0].id).toBe("park-ok");
    expect(live[0].rpId).toBe("rp.example");
    // Storage is rewritten to the cleaned list.
    expect(store.map.get("pkParked")).toHaveLength(1);
    expect(store.map.get("pkParked")[0].id).toBe("park-ok");
  });
  it("clearParked empties the park so the next restore resumes nothing", async () => {
    const store = makeStore();
    const { client } = makeClient({ sessionStore: store });
    await client.handleGetRequest({ tab: { id: 7 }, origin: "https://rp.example", frameId: 0 }, conditionalPayload());
    expect(store.map.get("pkParked").length).toBe(1);
    await client.clearParked();
    expect(store.map.has("pkParked")).toBe(false);
    const second = makeClient({ sessionStore: store }).client;
    expect(await second.restoreParked()).toBe(0);
  });

});
