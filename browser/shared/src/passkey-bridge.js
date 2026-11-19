// Passkey bridge content script — isolated world, document_start.
//
// Forwards MAIN-world passkey ceremony requests to the service worker and
// pushes responses back over the paired MessageChannel port. Owns the one
// privilege split that makes the whole design safe: it stamps
// `origin` and `sameOriginWithAncestors` from the ISOLATED world, where the
// page cannot tamper with the read — the page-supplied `requested` block is
// advisory and is replaced wholesale.
//
// Lifecycle: a long-lived runtime port carries SW->page pushes (pending
// conditional responses, destroy). When the port dies (extension reload,
// unregister, SW teardown) the page script is told to restore the native
// navigator.credentials so the site is never stranded on a dead proxy.
// Every page-bound DESTROY carries the page context id the page requires;
// an unstamped destroy would be dropped and the natives would never come
// back. The esbuild IIFE strips these exports, so unit tests can drive the
// factory from this same source with fake chrome/window objects.

import { SENDER_TAG, MsgType } from "./passkey-common.js";

// Factory for testability: the IIFE entry passes the real globals, tests
// pass fakes. Returns null when the document is ineligible or another copy
// already runs.
export function createPasskeyBridge(env) {
  const win = env.window;
  const chromeApi = env.chrome;
  const loc = env.location;
  const doc = env.document;

  if (win.__baluardPasskeyBridge) return null;
  win.__baluardPasskeyBridge = true;

  // Mirror the page script's gates so a stray injection stays inert.
  if (doc.contentType && doc.contentType !== "text/html") return null;
  const hostname = loc.hostname;
  const isLocal =
    loc.protocol === "http:" &&
    (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]");
  if (loc.protocol !== "https:" && !isLocal) return null;

  // sessionId -> MessageChannel port to the page world.
  const pagePorts = new Map();
  // The page script's random context id, learned from the first forwarded
  // request. The page drops messages with a foreign or missing id, so a
  // DESTROY without it would never restore the natives.
  let pageContextId = null;

  // MV3 idles the service worker out after ~30s even with open runtime
  // ports, and that disconnect must NOT tear the wrap down or every tab
  // stops intercepting the moment the worker sleeps. A fresh connect()
  // wakes the worker and rebuilds the pipeline. A throw — or a context
  // that is already dead (extension reload/update) — restores the natives.
  // Reconnects are capped: a worker that keeps refusing the port (or a
  // context that dies without throwing) must converge on destroy instead
  // of spinning an IPC loop for the life of the document.
  let reconnectAttempts = 0;
  const RECONNECT_DELAYS_MS = [0, 500, 1000, 2000, 4000];
  let destroyed = false;
  let swPort = null;
  function onSwMessage(msg) {
    if (!msg || typeof msg.sessionId !== "string") return;
    if (msg.type === MsgType.DESTROY) {
      // Setting passkeys off: stop reconnecting too, or the bridge spins
      // against a worker that will keep refusing an unwanted pipeline.
      forwardDestroyOnce();
      return;
    }
    if (msg.type !== MsgType.RESPONSE) return;
    deliverToPage(msg.sessionId, msg.contextId, msg.data);
  }
  function forwardDestroyOnce() {
    if (destroyed) return;
    destroyed = true;
    forwardDestroy();
  }
  function onSwDisconnect(port) {
    // Stale ports from an earlier reset still fire their disconnects; only
    // the current pipeline may reconnect or count against the cap.
    if (port && port !== swPort) return;
    if (destroyed) return;
    try {
      // Chrome returns undefined (not a throw) for runtime.id on an
      // invalidated context; a throwing getter covers the rare rest.
      if (!chromeApi.runtime?.id) throw new Error("context invalidated");
    } catch {
      forwardDestroyOnce();
      return;
    }
    const attempt = reconnectAttempts;
    if (attempt >= RECONNECT_DELAYS_MS.length) {
      forwardDestroyOnce();
      return;
    }
    reconnectAttempts += 1;
    const delay = RECONNECT_DELAYS_MS[attempt];
    const gen = swPort;
    if (delay === 0) {
      try {
        connectSw();
      } catch {
        forwardDestroyOnce();
      }
      return;
    }
    setTimeout(() => {
      if (destroyed || swPort !== gen) return;
      try {
        connectSw();
      } catch {
        forwardDestroyOnce();
      }
    }, delay);
  }
  function connectSw() {
    swPort = chromeApi.runtime.connect({ name: "baluard-passkey" });
    swPort.onMessage.addListener(onSwMessage);
    swPort.onDisconnect.addListener(onSwDisconnect);
    // A port that survives a second is a healthy pipeline: reset the cap
    // so the next idle kill reconnects from the front of the schedule.
    const gen = swPort;
    setTimeout(() => {
      if (swPort === gen) reconnectAttempts = 0;
    }, 1000);
  }
  connectSw();

  chromeApi.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "baluard-passkey-destroy") {
      // Setting-off teardown path: the SW messages every tab directly (the
      // runtime port may already be gone on a freshly navigating page).
      // Marks the bridge dead so the disconnect handler stops reconnecting
      // against a worker that will keep refusing an unwanted pipeline.
      forwardDestroyOnce();
    }
    if (
      msg &&
      msg.type === "baluard-passkey-pick-result" &&
      msg.pushed === false &&
      typeof msg.sessionId === "string"
    ) {
      // A conditional pick whose SW assertion failed: fail the page promise
      // explicitly instead of leaving it dangling on a dead port push.
      deliverToPage(
        msg.sessionId,
        msg.contextId,
        { type: "error", name: "NotAllowedError", message: "Baluard could not complete the sign-in" }
      );
    }
    // No async response: fall through to other listeners.
  });

  function deliverToPage(sessionId, contextId, data) {
    const port = pagePorts.get(sessionId);
    if (!port) return;
    pagePorts.delete(sessionId);
    try {
      port.postMessage({
        sender: SENDER_TAG,
        contextId,
        type: MsgType.RESPONSE,
        sessionId,
        data,
      });
      port.close();
    } catch {}
  }

  function forwardDestroy() {
    try {
      win.postMessage({ sender: SENDER_TAG, type: MsgType.DESTROY, contextId: pageContextId }, loc.origin);
    } catch {}
  }

  const onPageMessage = async (event) => {
    if (event.source !== win) return;
    const msg = event.data;
    if (!msg || msg.sender !== SENDER_TAG) return;
    if (msg.type === MsgType.HELLO) {
      // Install-time context announcement (no ceremony attached).
      if (msg.contextId && typeof msg.contextId === "string") pageContextId = msg.contextId;
      return;
    }
    if (msg.type !== MsgType.CREATE && msg.type !== MsgType.GET) return;
    if (!msg.sessionId || !msg.data || typeof msg.data !== "object") return;
    if (!msg.contextId || typeof msg.contextId !== "string") return;
    pageContextId = msg.contextId;
    if (destroyed) {
      // Re-enable re-arms the wrap via fresh injection; this bridge stopped
      // reconnecting at destroy, so a live ceremony re-opens the channel.
      destroyed = false;
      reconnectAttempts = 0;
      // Drop any port that survived the destroy (its disconnect would
      // otherwise race the fresh one and count against the cap).
      try {
        swPort?.disconnect();
      } catch {}
      try {
        connectSw();
      } catch {}
    }

    const port = event.ports && event.ports[0];
    if (port) {
      pagePorts.set(msg.sessionId, port);
      port.onmessage = (ev) => {
        const inner = ev.data;
        if (!inner || inner.sender !== SENDER_TAG) return;
        if (inner.type === MsgType.ABORT && inner.sessionId) {
          chromeApi.runtime
            .sendMessage({ action: "passkey.abortRequest", sessionId: inner.sessionId })
            .catch(() => {});
        }
      };
    }

    // PRIVILEGE STAMP: origin and same-origin state come from THIS world,
    // never from the page's advisory `requested` block.
    const requested = {
      origin: loc.origin,
      sameOriginWithAncestors: win.self === win.top,
    };
    try {
      const res = await chromeApi.runtime.sendMessage({
        action: msg.type === MsgType.CREATE ? "passkey.createRequest" : "passkey.getRequest",
        sessionId: msg.sessionId,
        contextId: msg.contextId,
        options: msg.data.options,
        mediation: msg.data.mediation,
        requested,
      });
      // ACCEPT-time failures (validation, setting off, SW handler crash)
      // return an error payload instead of pushing: forward them onto the
      // page port so create()/get() never dangle.
      const payload = res && res.ok ? res.payload : null;
      if (payload && payload.error) {
        deliverToPage(msg.sessionId, msg.contextId, {
          type: "error",
          name: String(payload.error),
          message: "",
        });
        return;
      }
      if (res && res.ok === false) {
        deliverToPage(msg.sessionId, msg.contextId, {
          type: "error",
          name: "NotAllowedError",
          message: "Baluard unavailable",
        });
      }
    } catch {
      // SW unreachable: fail the ceremony on the page port so it never
      // hangs when the extension dies mid-request.
      deliverToPage(msg.sessionId, msg.contextId, {
        type: "error",
        name: "NotAllowedError",
        message: "Baluard unavailable",
      });
    }
  };

  win.addEventListener("message", (event) => {
    onPageMessage(event);
  });

  // Test hooks (stripped from the IIFE bundle).
  return {
    pagePorts,
    contextId: () => pageContextId,
    onPageMessage,
    forwardDestroy,
    deliverToPage,
  };
}

(() => {
  // Unit environments have no chrome API; the factory stays importable.
  if (typeof chrome === "undefined" || !chrome?.runtime?.connect) return;
  const api = createPasskeyBridge({ window, chrome, location, document });
  if (!api) return;
})();
