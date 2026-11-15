// Unit tests for passkey-bridge.js — the isolated-world origin-stamping
// bridge. Tests drive the factory with fake chrome/window objects and a
// real MessageChannel for the page ports.
import { describe, it, expect, vi } from "vitest";
import { SENDER_TAG, MsgType } from "../src/passkey-common.js";
import { createPasskeyBridge } from "../src/passkey-bridge.js";

function makeEnv(overrides = {}) {
  const winHandlers = [];
  const posted = [];
  const runtimeMessages = [];
  const swPort = {
    onMessage: { addListener: vi.fn() },
    onDisconnect: { addListener: vi.fn() },
    postMessage: vi.fn(),
  };
  const sendMessage = vi.fn(async () => ({ ok: true, payload: {} }));
  const chromeApi = {
    runtime: {
      connect: vi.fn(() => swPort),
      sendMessage,
      onMessage: { addListener: (fn) => runtimeMessages.push(fn) },
    },
  };
  const win = {
    __baluardPasskeyBridge: undefined,
    self: null,
    top: null,
    addEventListener: (type, fn) => {
      if (type === "message") winHandlers.push(fn);
    },
    postMessage: (msg, origin) => posted.push({ msg, origin }),
  };
  win.self = win;
  win.top = win;
  const env = {
    window: win,
    chrome: chromeApi,
    document: { contentType: "text/html" },
    location: { protocol: "https:", hostname: "rp.example", origin: "https://rp.example" },
    ...overrides,
    __posted: posted,
    __winHandlers: winHandlers,
    __runtimeMessages: runtimeMessages,
    __sendMessage: sendMessage,
    __swPort: swPort,
  };
  return env;
}

const start = (overrides = {}) => {
  const env = makeEnv(overrides);
  const api = createPasskeyBridge(env);
  const onSwMessage = env.__swPort.onMessage.addListener.mock.calls[0][0];
  const onSwDisconnect = env.__swPort.onDisconnect.addListener.mock.calls[0][0];
  const onRuntimeMessage = env.__runtimeMessages[0];
  return {
    env,
    api,
    posted: env.__posted,
    sendMessage: env.__sendMessage,
    onSwMessage,
    onSwDisconnect,
    onRuntimeMessage,
  };
};

// A page GET as it leaves the page world (transfers the paired port). The
// page's advisory `requested` block deliberately lies so the test proves
// the isolated-world stamp wins.
function pageRequest(overrides = {}) {
  const channel = new MessageChannel();
  return {
    event: {
      source: null,
      data: {
        sender: SENDER_TAG,
        contextId: "ctx-page-1",
        type: MsgType.GET,
        sessionId: "page-session-1",
        data: {
          options: { challenge: "Y2g", rpId: "rp.example" },
          mediation: undefined,
          requested: { origin: "https://evil.example", sameOriginWithAncestors: true },
        },
        ...overrides,
      },
      ports: [channel.port2],
    },
    pagePort: channel.port1,
  };
}

const drain = () => new Promise((r) => setTimeout(r, 5));

describe("eligibility", () => {
  it("returns null for non-html documents", () => {
    const env = makeEnv({ document: { contentType: "text/plain" } });
    expect(createPasskeyBridge(env)).toBeNull();
  });

  it("returns null for insecure origins", () => {
    const env = makeEnv({
      location: { protocol: "http:", hostname: "rp.example", origin: "http://rp.example" },
    });
    expect(createPasskeyBridge(env)).toBeNull();
  });

  it("refuses a second copy", () => {
    const env = makeEnv();
    createPasskeyBridge(env);
    expect(createPasskeyBridge(env)).toBeNull();
  });
});

describe("context learning and DESTROY stamping", () => {
  it("announces nothing until the page says hello", () => {
    const { api } = start();
    expect(api.contextId()).toBeNull();
  });

  it("learns the context from HELLO and stamps DESTROY with it", () => {
    const { env, api, posted, onSwDisconnect } = start();
    for (const fn of env.__winHandlers) {
      fn({ source: env.window, data: { sender: SENDER_TAG, contextId: "ctx-page-1", type: MsgType.HELLO } });
    }
    expect(api.contextId()).toBe("ctx-page-1");
    onSwDisconnect();
    expect(posted[0].msg).toEqual({
      sender: SENDER_TAG,
      type: MsgType.DESTROY,
      contextId: "ctx-page-1",
    });
  });

  it("does not stamp an unstamped DESTROY before any hello or request", () => {
    const { posted, onSwDisconnect } = start();
    onSwDisconnect();
    expect(posted[0].msg.contextId).toBeNull();
  });

  it("rejects a HELLO with a junk or missing context id", () => {
    const { env, api } = start();
    for (const fn of env.__winHandlers) {
      fn({ source: env.window, data: { sender: SENDER_TAG, contextId: 42, type: MsgType.HELLO } });
      fn({ source: env.window, data: { sender: SENDER_TAG, type: MsgType.HELLO } });
    }
    expect(api.contextId()).toBeNull();
  });
});

describe("request forwarding", () => {
  it("stamps the trusted origin over the page's advisory block", async () => {
    const { env, api, sendMessage } = start();
    const { event } = pageRequest();
    event.source = env.window;
    await api.onPageMessage(event);
    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "passkey.getRequest",
        sessionId: "page-session-1",
        contextId: "ctx-page-1",
        requested: { origin: "https://rp.example", sameOriginWithAncestors: true },
      })
    );
  });

  it("forwards ACCEPT-time validation errors onto the page port", async () => {
    const { env, api, sendMessage } = start();
    sendMessage.mockResolvedValueOnce({ ok: true, payload: { error: "SecurityError" } });
    const { event, pagePort } = pageRequest();
    event.source = env.window;
    const got = [];
    pagePort.onmessage = (ev) => got.push(ev.data);
    await api.onPageMessage(event);
    await drain();
    expect(got).toHaveLength(1);
    expect(got[0].type).toBe(MsgType.RESPONSE);
    expect(got[0].data).toMatchObject({ type: "error", name: "SecurityError" });
    expect(got[0].sessionId).toBe("page-session-1");
    expect(got[0].contextId).toBe("ctx-page-1");
  });

  it("maps a handler crash (ok:false) to NotAllowedError", async () => {
    const { env, api, sendMessage } = start();
    sendMessage.mockResolvedValueOnce({ ok: false, error: "boom" });
    const { event, pagePort } = pageRequest();
    event.source = env.window;
    const got = [];
    pagePort.onmessage = (ev) => got.push(ev.data);
    await api.onPageMessage(event);
    await drain();
    expect(got[0].data).toMatchObject({ type: "error", name: "NotAllowedError" });
  });

  it("fails the page promise when the SW is unreachable", async () => {
    const { env, api, sendMessage } = start();
    sendMessage.mockRejectedValueOnce(new Error("extension context invalidated"));
    const { event, pagePort } = pageRequest();
    event.source = env.window;
    const got = [];
    pagePort.onmessage = (ev) => got.push(ev.data);
    await api.onPageMessage(event);
    await drain();
    expect(got[0].data).toMatchObject({ type: "error", name: "NotAllowedError" });
  });

  it("routes an inner-port ABORT to the SW", async () => {
    const { env, api, sendMessage } = start();
    const { event, pagePort } = pageRequest();
    event.source = env.window;
    await api.onPageMessage(event);
    // The page sends ABORT through its half of the paired channel.
    pagePort.postMessage({ sender: SENDER_TAG, type: MsgType.ABORT, sessionId: "page-session-1" });
    await drain();
    expect(sendMessage).toHaveBeenCalledWith({ action: "passkey.abortRequest", sessionId: "page-session-1" });
  });
});

describe("SW pushes", () => {
  it("delivers a RESPONSE push onto the matching page port", async () => {
    const { env, api, onSwMessage } = start();
    const { event, pagePort } = pageRequest();
    event.source = env.window;
    await api.onPageMessage(event);
    const got = [];
    pagePort.onmessage = (ev) => got.push(ev.data);
    onSwMessage({
      type: MsgType.RESPONSE,
      sessionId: "page-session-1",
      contextId: "ctx-page-1",
      data: { type: "success", credential: { rawId: "abc" } },
    });
    await drain();
    expect(got).toHaveLength(1);
    expect(got[0].data).toMatchObject({ type: "success" });
  });

  it("ignores a RESPONSE for an unknown session", () => {
    const { onSwMessage } = start();
    expect(() =>
      onSwMessage({ type: MsgType.RESPONSE, sessionId: "gone", contextId: "ctx", data: {} })
    ).not.toThrow();
  });

  it("forwards an SW DESTROY push to the page", () => {
    const { env, api, posted, onSwMessage } = start();
    const { event } = pageRequest();
    event.source = env.window;
    api.onPageMessage(event);
    onSwMessage({ type: MsgType.DESTROY, sessionId: "page-session-1" });
    expect(posted[0].msg).toMatchObject({ type: MsgType.DESTROY, contextId: "ctx-page-1" });
  });
});

describe("pick-result forwarding", () => {
  it("fails the page promise when a conditional pick reports a failed push", async () => {
    const { env, api, onRuntimeMessage } = start();
    const { event, pagePort } = pageRequest();
    event.source = env.window;
    await api.onPageMessage(event);
    const got = [];
    pagePort.onmessage = (ev) => got.push(ev.data);
    onRuntimeMessage({
      type: "baluard-passkey-pick-result",
      pushed: false,
      sessionId: "page-session-1",
      contextId: "ctx-page-1",
    });
    await drain();
    expect(got).toHaveLength(1);
    expect(got[0].data).toMatchObject({ type: "error", name: "NotAllowedError" });
    expect(got[0].contextId).toBe("ctx-page-1");
  });

  it("ignores pick results that succeeded", async () => {
    const { env, api, onRuntimeMessage } = start();
    const { event, pagePort } = pageRequest();
    event.source = env.window;
    await api.onPageMessage(event);
    const got = [];
    pagePort.onmessage = (ev) => got.push(ev.data);
    onRuntimeMessage({
      type: "baluard-passkey-pick-result",
      pushed: true,
      sessionId: "page-session-1",
      contextId: "ctx-page-1",
    });
    expect(got).toHaveLength(0);
  });
});

describe("setting-off destroy", () => {
  it("forwards the direct destroy message to the page", () => {
    const { env, posted, onRuntimeMessage } = start();
    for (const fn of env.__winHandlers) {
      fn({ source: env.window, data: { sender: SENDER_TAG, contextId: "ctx-page-1", type: MsgType.HELLO } });
    }
    onRuntimeMessage({ type: "baluard-passkey-destroy" });
    expect(posted[0].msg).toMatchObject({ type: MsgType.DESTROY, contextId: "ctx-page-1" });
  });
});
