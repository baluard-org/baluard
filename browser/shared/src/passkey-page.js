// Passkey page script — runs in the page's MAIN world (world: "MAIN").
//
// Wraps navigator.credentials.create/get so WebAuthn ceremonies are offered
// to Baluard. Registered dynamically by the service worker ONLY while the
// `enablePasskeys` setting is on; the bridge (isolated world) restores the
// natives when the extension unregisters or reloads. The bundle is an IIFE
// (esbuild strips these exports), so unit tests can import the factory from
// this same source and drive it with fake environment objects.
//
// Security posture (mirrors the shipped Bitwarden page-script design):
//   - text/html + https/localhost only, never in sandboxed (opaque-origin)
//     frames, never for non-publicKey calls.
//   - Non-conditional errors from Baluard surface as DOMExceptions built in
//     the page world; a FallbackRequested error hands the ceremony to the
//     browser so hardware keys and OS passkeys stay reachable.
//   - Conditional mediation races the browser's own conditional UI: both
//     sides run in parallel and the loser is aborted (Bitwarden's
//     Promise.race pattern), so Baluard can neither strand the native sheet
//     nor hang the page when the vault is locked or empty.
//   - Responses rebuild PublicKeyCredential objects via prototype fixes so
//     site instanceof checks keep passing.

import {
  SENDER_TAG,
  MsgType,
  ErrName,
  normalizeCreationOptions,
  normalizeRequestOptions,
  assertionNeedsFallback,
  buildPublicKeyCredential,
} from "./passkey-common.js";

// Factory so the whole interception is unit-testable: the IIFE entry passes
// the real globals, tests pass fakes. Returns null when the document is
// ineligible or another copy already owns the wrap.
export function createPageInterception(env) {
  const win = env.window;
  const nav = env.navigator;
  const doc = env.document;
  const loc = env.location;
  const cryptoObj = env.crypto || globalThis.crypto;
  const DOMExceptionCtor = env.DOMException || globalThis.DOMException;
  const AbortControllerCtor = env.AbortController || globalThis.AbortController;
  const Chan = env.MessageChannel || globalThis.MessageChannel;

  if (win.__baluardPasskey) return null;
  win.__baluardPasskey = true;

  // ── eligibility gates (fail closed, silently) ──
  if (doc.contentType && doc.contentType !== "text/html") {
    win.__baluardPasskey = false;
    return null;
  }
  const hostname = loc.hostname;
  const isLocal =
    loc.protocol === "http:" &&
    (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]");
  if (loc.protocol !== "https:" && !isLocal) {
    win.__baluardPasskey = false;
    return null;
  }
  if (loc.origin === "null") {
    // Sandboxed iframe: opaque origin, WebAuthn is unavailable to it anyway.
    win.__baluardPasskey = false;
    return null;
  }
  const nativeCredentials = nav.credentials;
  if (
    !nativeCredentials ||
    typeof nativeCredentials.create !== "function" ||
    typeof nativeCredentials.get !== "function"
  ) {
    win.__baluardPasskey = false;
    return null;
  }

  const nativeCreate = nativeCredentials.create.bind(nativeCredentials);
  const nativeGet = nativeCredentials.get.bind(nativeCredentials);
  const wrapProto = Object.getPrototypeOf(nativeCredentials);
  const installedTargets = [];
  let nativesRestored = false;

  // Per-ceremony state: sessionId -> {port, resolve, reject, conditional,
  // originalOptions, mode, timer}.
  const pending = new Map();
  // Random per-context id: the bridge drops messages from unknown ids, so
  // page-world noise cannot inject into or hijack another context's session.
  const contextId =
    cryptoObj.randomUUID
      ? cryptoObj.randomUUID()
      : String(cryptoObj.getRandomValues(new Uint32Array(4)));
  const randomId = () =>
    cryptoObj.randomUUID
      ? cryptoObj.randomUUID()
      : String(cryptoObj.getRandomValues(new Uint32Array(4)));

  const Err = (name, message) => new DOMExceptionCtor(message || name, name);

  const restoreNatives = () => {
    if (nativesRestored) return;
    nativesRestored = true;
    for (const { target, prop, prevDesc, prevValue, fn, viaAssign } of installedTargets) {
      try {
        const cur = Object.getOwnPropertyDescriptor(target, prop);
        // Only restore if our wrapper is still the active value; never clobber
        // a hook installed after Baluard.
        if (viaAssign) {
          if (target[prop] !== fn) continue;
          target[prop] = prevDesc && "value" in prevDesc ? prevDesc.value : prevValue;
        } else {
          if (!cur || cur.value !== fn) continue;
          if (prevDesc) {
            Object.defineProperty(target, prop, prevDesc);
          } else {
            delete target[prop];
          }
        }
      } catch {}
    }
  };

  function settle(sessionId, fn) {
    const entry = pending.get(sessionId);
    if (!entry) return;
    pending.delete(sessionId);
    if (entry.timer) clearTimeout(entry.timer);
    try {
      entry.port.close();
    } catch {}
    fn(entry);
  }

  function respondError(entry, name, message) {
    const { originalOptions, mode } = entry;
    if (entry.conditional && name !== ErrName.FALLBACK) {
      // Conditional errors are swallowed: the native conditional race keeps
      // running and its own outcome settles the page promise.
      return;
    }
    if (name === ErrName.FALLBACK) {
      // Hand the ceremony to the browser. The bound natives call the REAL
      // implementation directly, so no restore happens here — restoring
      // would permanently unhook interception for this whole document.
      const call = mode === "create" ? nativeCreate : nativeGet;
      call(originalOptions).then(entry.resolve, entry.reject);
      return;
    }
    entry.reject(Err(name, message));
  }

  function deliverResponse(entry, data) {
    if (data && data.type === "success" && data.credential) {
      const cred = buildPublicKeyCredential(data.credential, entry.mode === "create");
      if (cred) entry.resolve(cred);
      else entry.reject(Err(ErrName.NOT_ALLOWED, "Bad response"));
      return;
    }
    if (data && data.type === "error") {
      respondError(entry, data.name || ErrName.NOT_ALLOWED, data.message);
      return;
    }
    entry.reject(Err(ErrName.NOT_ALLOWED, "Bad response"));
  }

  function onMessage(event) {
    if (event.source !== win) return;
    const msg = event.data;
    if (!msg || msg.sender !== SENDER_TAG || msg.contextId !== contextId) return;
    if (msg.type === MsgType.DESTROY) destroy();
  }

  function destroy() {
    if (typeof win.removeEventListener === "function") {
      win.removeEventListener("message", onMessage);
    }
    restoreNatives();
    for (const sessionId of Array.from(pending.keys())) {
      settle(sessionId, (entry) => {
        if (!entry.conditional) {
          entry.reject(Err(ErrName.NOT_ALLOWED, "Interrupted"));
        }
      });
    }
    // Allow a later re-registration cycle (setting toggled off + on).
    win.__baluardPasskey = false;
  }

  function wireAbortSignal(signal, sessionId, port) {
    if (!signal || typeof signal.addEventListener !== "function") return;
    if (signal.aborted) {
      throw new DOMExceptionCtor("The operation was aborted", "AbortError");
    }
    signal.addEventListener(
      "abort",
      () => {
        try {
          port.postMessage({
            sender: SENDER_TAG,
            contextId,
            type: MsgType.ABORT,
            sessionId,
          });
        } catch {}
        settle(sessionId, (entry) => entry.reject(Err("AbortError", "The operation was aborted")));
      },
      { once: true }
    );
  }

  function postToBridge(sessionId, type, normalized, originalOptions) {
    // The bridge (isolated world) stamps the trusted origin/sameOrigin
    // metadata itself; anything we claim in `requested` is advisory only.
    win.postMessage(
      {
        sender: SENDER_TAG,
        contextId,
        type,
        sessionId,
        data: {
          options: normalized.options,
          mediation: originalOptions.mediation,
          requested: {
            origin: loc.origin,
            sameOriginWithAncestors: win.self === win.top,
          },
        },
      },
      loc.origin,
      []
    );
  }

  // Announce the context id at install time so the bridge can stamp a
  // DESTROY (setting off, extension reload) before any ceremony runs —
  // the page drops unstamped messages, and a dropped DESTROY would strand
  // the wrap on a dead extension.
  function announce() {
    try {
      win.postMessage({ sender: SENDER_TAG, contextId, type: MsgType.HELLO }, loc.origin);
    } catch {}
  }

  // Page-side timeout: the SW enforces the clamped RP timeout too, but the
  // SW can be dead or the bridge port stale — this timer guarantees
  // create()/get() always settles. Conditional requests stay pending per
  // spec (the native race decides them).
  function armPageTimeout(sessionId, entry, normalized) {
    const ms =
      Number(normalized.options.timeout) || (normalized.requiresUv ? 300_000 : 120_000);
    entry.timer = setTimeout(() => {
      const e = pending.get(sessionId);
      if (!e) return;
      if (e.conditional) {
        pending.delete(sessionId);
        return;
      }
      try {
        e.port.postMessage({
          sender: SENDER_TAG,
          contextId,
          type: MsgType.ABORT,
          sessionId,
        });
      } catch {}
      settle(sessionId, (x) => x.reject(Err(ErrName.NOT_ALLOWED, "The operation timed out")));
    }, ms);
  }

  function request(mode, originalOptions) {
    if (nativesRestored) {
      const call = mode === "create" ? nativeCreate : nativeGet;
      return call(originalOptions);
    }
    const publicKey = originalOptions && originalOptions.publicKey;
    if (!publicKey || typeof publicKey !== "object") {
      // Not a WebAuthn ceremony: transparent passthrough.
      const call = mode === "create" ? nativeCreate : nativeGet;
      return call(originalOptions);
    }
    const conditional = mode === "get" && originalOptions.mediation === "conditional";
    const normalized =
      mode === "create" ? normalizeCreationOptions(publicKey) : normalizeRequestOptions(publicKey);
    if (!normalized.ok) {
      return Promise.reject(Err(normalized.errorName, "The operation was not supported"));
    }
    // Fallback is judged on the RAW options: normalization can drop a
    // malformed allowCredentials entry, and an empty list must never turn a
    // USB-only request into one Baluard claims.
    if (mode === "get" && assertionNeedsFallback(publicKey)) {
      // Only non-internal transports requested: no vault authenticator can
      // serve this; let the browser reach the hardware key. The bound
      // native call is already the real implementation, so the wrap stays.
      return nativeGet(originalOptions);
    }
    const sessionId = randomId();
    const channel = new Chan();
    const entry = {
      port: channel.port1,
      resolve: null,
      reject: null,
      conditional,
      originalOptions,
      mode,
      timer: null,
    };
    const promise = new Promise((resolve, reject) => {
      entry.resolve = resolve;
      entry.reject = reject;
    });
    pending.set(sessionId, entry);
    // Ceremony responses ride the paired port (page-world payloads never
    // share the window bus with other scripts).
    channel.port1.onmessage = (ev) => {
      const msg = ev.data;
      if (!msg || msg.sender !== SENDER_TAG || msg.contextId !== contextId) return;
      if (msg.type === MsgType.RESPONSE && msg.sessionId) {
        settle(msg.sessionId, (e) => deliverResponse(e, msg.data));
      }
    };
    try {
      wireAbortSignal(originalOptions.signal, sessionId, channel.port1);
    } catch (e) {
      pending.delete(sessionId);
      try {
        channel.port1.close();
      } catch {}
      return Promise.reject(e);
    }
    win.postMessage(
      {
        sender: SENDER_TAG,
        contextId,
        type: mode === "create" ? MsgType.CREATE : MsgType.GET,
        sessionId,
        data: {
          options: normalized.options,
          mediation: originalOptions.mediation,
          requested: {
            origin: loc.origin,
            sameOriginWithAncestors: win.self === win.top,
          },
        },
      },
      loc.origin,
      [channel.port2]
    );
    if (conditional) {
      return runConditionalRace(sessionId, entry, originalOptions, promise);
    }
    armPageTimeout(sessionId, entry, normalized);
    return promise;
  }

  function abortBaluard(sessionId, entry) {
    try {
      entry.port.postMessage({
        sender: SENDER_TAG,
        contextId,
        type: MsgType.ABORT,
        sessionId,
      });
    } catch {}
  }

  // Bitwarden-style conditional race: the browser's own conditional UI and
  // Baluard's candidates run in PARALLEL, each able to cancel the other.
  // Without the native leg the browser sheet would be suppressed whenever
  // the wrap is installed, and a locked/empty vault would hang the page.
  function runConditionalRace(sessionId, entry, originalOptions, baluardPromise) {
    const controller = new AbortControllerCtor();
    const userSignal = originalOptions.signal;
    if (userSignal && typeof userSignal.addEventListener === "function") {
      if (userSignal.aborted) controller.abort(userSignal.reason);
      else
        userSignal.addEventListener("abort", () => controller.abort(userSignal.reason), {
          once: true,
        });
    }
    let nativePromise;
    try {
      nativePromise = nativeGet({ ...originalOptions, signal: controller.signal });
    } catch (e) {
      abortBaluard(sessionId, entry);
      settle(sessionId, (x) => x.reject(e));
      return Promise.reject(e);
    }
    return Promise.race([baluardPromise, nativePromise]).then(
      (value) => {
        controller.abort();
        abortBaluard(sessionId, entry);
        return value;
      },
      (err) => {
        // The native rejection is authoritative (the user dismissed the
        // browser sheet or the browser lacks conditional support); a
        // Baluard-side conditional error never settles the race promise.
        controller.abort();
        abortBaluard(sessionId, entry);
        settle(sessionId, (x) => x.reject(err));
        throw err;
      }
    );
  }

  function wrapMethod(prop, mode) {
    const ownDesc = Object.getOwnPropertyDescriptor(nativeCredentials, prop);
    // An own property on navigator.credentials (e.g. another manager's
    // passthrough hook) shadows CredentialsContainer.prototype, so wrap
    // directly on the instance when an own property is present.
    const target = ownDesc ? nativeCredentials : wrapProto;
    const prevDesc = ownDesc || Object.getOwnPropertyDescriptor(wrapProto, prop) || null;
    const fn = function (options) {
      return request(mode, options);
    };
    Object.defineProperty(fn, "name", { value: prop, configurable: true });
    Object.defineProperty(fn, "__baluard", { value: true, configurable: true });
    const viaAssign = Boolean(
      ownDesc &&
        !ownDesc.configurable &&
        ((!ownDesc.get && !ownDesc.set && ownDesc.writable) || typeof ownDesc.set === "function")
    );
    const prevValue = viaAssign ? target[prop] : undefined;
    if (viaAssign) {
      target[prop] = fn;
      // A competing manager's setter may silently ignore writes when enabled.
      if (target[prop] !== fn) {
        throw new Error(`Cannot overwrite ${prop}`);
      }
    } else {
      Object.defineProperty(target, prop, {
        value: fn,
        writable: true,
        configurable: true,
      });
    }
    installedTargets.push({ target, prop, prevDesc, prevValue, fn, viaAssign });
  }

  function install() {
    try {
      wrapMethod("create", "create");
      wrapMethod("get", "get");
      win.addEventListener("message", onMessage);
      return true;
    } catch {
      // Cannot wrap safely: roll back any partial wrap and stay invisible.
      restoreNatives();
      win.__baluardPasskey = false;
      return false;
    }
  }

  // Test hooks (stripped consumers never see them; the IIFE bundle has no
  // exports).
  return {
    install,
    request,
    destroy,
    announce,
    contextId,
    pendingCount: () => pending.size,
    nativesRestored: () => nativesRestored,
  };
}

(() => {
  const api = createPageInterception({
    window,
    navigator,
    document,
    location,
    crypto,
    DOMException,
    AbortController,
    MessageChannel,
  });
  if (!api) return;
  if (api.install()) api.announce();
})();
