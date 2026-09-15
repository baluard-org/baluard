// Unit tests for background.js (service worker).
//
// Pure-function coverage of the two pieces of logic worth pinning:
//   - compareVersions (semver-ish compare, used for the version handshake gate)
//   - classifyDisconnect (maps Chromium native-messaging disconnect reasons
//     to the friendly codes the popup uses for state mapping)
//   - buildError (turns a daemon response into a thrown Error with .code)
//
// The connectNative / send / port multiplexing path is exercised manually
// when a real extension is loaded; it's complex enough that an end-to-end
// integration test would need a fake NMH (a follow-up). The pure bits here
// are the highest-value regression surface.

import { describe, it, expect } from "vitest";
import {
  compareVersions,
  classifyDisconnect,
  buildError,
  senderUrl,
} from "../src/background.js";
import { originOf } from "../src/url.js";

describe("originOf (B1: fill-time origin binding)", () => {
  it("returns scheme+host+port", () => {
    expect(originOf("https://example.com/login")).toBe("https://example.com");
    expect(originOf("http://intranet.local:8080/x")).toBe("http://intranet.local:8080");
  });

  it("keeps scheme in the origin so https never equals http (downgrade fill blocked)", () => {
    expect(originOf("https://example.com/")).not.toBe(originOf("http://example.com/"));
  });

  it("keeps port in the origin", () => {
    expect(originOf("https://example.com/")).not.toBe(originOf("https://example.com:8443/"));
  });

  it("fails closed on unparseable URLs", () => {
    expect(originOf("")).toBe("");
    expect(originOf("not a url")).toBe("");
  });
});

describe("senderUrl (inline autofill sender gating)", () => {
  it("uses the privileged sender.tab.url", () => {
    const sender = { tab: { id: 7, url: "https://example.com/login" } };
    expect(senderUrl(sender)).toBe("https://example.com/login");
  });

  it("fails closed (empty) when there is no tab", () => {
    expect(senderUrl({})).toBe("");
    expect(senderUrl(null)).toBe("");
  });

  it("fails closed when the tab has no URL (chrome://, about:blank)", () => {
    expect(senderUrl({ tab: { id: 1 } })).toBe("");
    expect(senderUrl({ tab: { id: 1, url: "" } })).toBe("");
  });

  it("fails closed for non-http(s) URLs (extension pages, file:)", () => {
    expect(senderUrl({ tab: { id: 1, url: "chrome-extension://abc/popup.html" } })).toBe("");
    expect(senderUrl({ tab: { id: 1, url: "file:///etc/passwd" } })).toBe("");
  });

  it("keeps http pages eligible (not https-only, matches manifest)", () => {
    expect(senderUrl({ tab: { id: 1, url: "http://intranet.local/login" } })).toBe(
      "http://intranet.local/login"
    );
  });
});

describe("compareVersions", () => {
  it("returns 0 for equal versions", () => {
    expect(compareVersions("0.1.0", "0.1.0")).toBe(0);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  });

  it("returns negative when a < b (lower major)", () => {
    expect(compareVersions("0.1.0", "1.0.0")).toBeLessThan(0);
  });

  it("returns positive when a > b (higher minor)", () => {
    expect(compareVersions("0.2.0", "0.1.0")).toBeGreaterThan(0);
  });

  it("treats missing trailing components as 0", () => {
    expect(compareVersions("0.1", "0.1.0")).toBe(0);
    expect(compareVersions("0.1", "0.1.1")).toBeLessThan(0);
    expect(compareVersions("0.1.1", "0.1")).toBeGreaterThan(0);
  });

  it("compares major before minor before patch", () => {
    expect(compareVersions("2.0.0", "1.99.99")).toBeGreaterThan(0);
    expect(compareVersions("0.3.0", "0.2.99")).toBeGreaterThan(0);
  });
});

describe("classifyDisconnect", () => {
  it("maps 'not found' to no-daemon (manifest missing)", () => {
    expect(classifyDisconnect("Specified native messaging host not found.")).toBe("no-daemon");
  });

  it("maps 'forbidden' to no-daemon (NMH not installed)", () => {
    expect(classifyDisconnect("Access to the specified native messaging host is forbidden.")).toBe(
      "no-daemon"
    );
  });

  it("is case-insensitive", () => {
    expect(classifyDisconnect("HOST NOT FOUND")).toBe("no-daemon");
  });

  it("returns nmh-error for unrelated reasons", () => {
    expect(classifyDisconnect("")).toBe("nmh-error");
    expect(classifyDisconnect("pipe closed")).toBe("nmh-error");
    expect(classifyDisconnect(undefined)).toBe("nmh-error");
  });
});

describe("buildError", () => {
  it("uses the response error message verbatim", () => {
    const e = buildError({ error: "vault locked", code: "locked" });
    expect(e.message).toBe("vault locked");
    expect(e.code).toBe("locked");
  });

  it("falls back to 'unknown' when the response has no error", () => {
    const e = buildError({});
    expect(e.message).toBe("unknown");
    expect(e.code).toBe("proto");
  });

  it("falls back to proto code when the response has no code", () => {
    const e = buildError({ error: "boom" });
    expect(e.code).toBe("proto");
  });
});
// ── B7: version-skew gate (fail closed, queue until handshake) ──
//
// The connect() / send() path needs a controllable fake port: we patch
// chrome.runtime.connectNative, re-import the module fresh (vi.resetModules)
// so its top-level connect() binds to OUR port, then drive the handshake
// from the test.

import { vi, beforeEach, afterEach } from "vitest";

function makeFakePort() {
  const listeners = [];
  return {
    posted: [],
    postMessage(m) {
      this.posted.push(m);
    },
    onMessage: { addListener: (fn) => listeners.push(fn) },
    onDisconnect: { addListener: () => {} },
    reply(msg) {
      listeners.forEach((fn) => fn(msg));
    },
  };
}

async function freshBackground() {
  const port = makeFakePort();
  const original = global.chrome.runtime.connectNative;
  global.chrome.runtime.connectNative = () => port;
  vi.resetModules();
  const mod = await import("../src/background.js");
  global.chrome.runtime.connectNative = original;
  return { mod, port };
}

function pingReply(id, nmhVersion) {
  return {
    id: String(id),
    ok: true,
    payload: JSON.stringify({ nmh_version: nmhVersion }),
  };
}

describe("version handshake gate (B7)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("queues non-ping sends until the first ping resolves", async () => {
    const { mod, port } = await freshBackground();
    // Only the handshake ping has been posted so far.
    expect(port.posted.length).toBe(1);
    expect(port.posted[0].action).toBe("ping");

    const p = mod.send("bridge.match", { url: "https://example.com" });
    // Still queued: the action must NOT hit the port before the handshake.
    await new Promise((r) => setTimeout(r, 10));
    expect(port.posted.length).toBe(1);

    port.reply(pingReply(1, "0.1.0"));
    await new Promise((r) => setTimeout(r, 10));
    // Handshake done: the queued action dispatched.
    expect(port.posted.length).toBe(2);
    expect(port.posted[1].action).toBe("bridge.match");

    port.reply({ id: port.posted[1].id, ok: true, payload: "{}" });
    await expect(p).resolves.toBeTruthy();
  });

  it("rejects non-ping sends with version-skew when the NMH is old", async () => {
    const { mod, port } = await freshBackground();
    port.reply(pingReply(1, "0.0.1"));
    await new Promise((r) => setTimeout(r, 10));

    await expect(mod.send("vault.get", { id: "x" })).rejects.toMatchObject({
      code: "version-skew",
    });
    // Refused before reaching the port.
    expect(port.posted.filter((m) => m.action === "vault.get")).toHaveLength(0);
  });

  it("times the handshake out and rejects queued sends (cannot reach)", async () => {
    vi.useFakeTimers();
    const { mod } = await freshBackground();
    const p = mod.send("bridge.match", { url: "https://example.com" });
    const assertion = expect(p).rejects.toMatchObject({ code: "no-daemon" });
    await vi.advanceTimersByTimeAsync(5000);
    await assertion;
    // Real timers for afterEach restore; flush the rejection chain.
    await p.catch(() => {});
  });
});
