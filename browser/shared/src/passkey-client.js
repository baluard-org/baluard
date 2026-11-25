// Passkey client — the service worker's WebAuthn "client" role.
//
// Implements the spec's client algorithm on top of the daemon's provider
// routes: origin/rp.id validation, clientDataJSON construction (the
// extension's job — the daemon only signs), ceremony orchestration, and the
// picker UI (a popout window for modal ceremonies; the inline dropdown for
// conditional mediation).
//
// Trust rules (ADR 0095 browser extension):
//   - origin comes from `sender` tab metadata, never from page payloads;
//   - `user_verified` stays false: the picker pick proves presence, not
//     verification; the daemon fail-closes ceremonies whose RP demands UV
//     (passkey:uv-required) instead of trusting this flag;
//   - key material and counters never cross IPC; the daemon holds the
//     fresh credential behind the ceremony id until store_registered;
//   - an unreachable desktop hands the ceremony BACK to the browser
//     (FallbackRequested) so hardware keys keep working; a locked vault
//     keeps the ceremony pending in an unlock prompt.

import { originOf } from "./url.js";
import {
  ErrName,
  effectiveRpId,
  isValidWebAuthnOrigin,
} from "./passkey-common.js";

// Map a daemon error message to the page-facing DOMException name. A bare
// mapping keeps vault/extension internals out of page-visible error text.
function pageErrorName(daemonMessage) {
  const m = String(daemonMessage || "");
  if (m.includes("already exists")) return "excluded";
  return ErrName.NOT_ALLOWED;
}

export function createPasskeyClient(send, opts = {}) {
  const focusTab = opts.focusTab || defaultFocusTab;

  // storage.session seam for tests; undefined outside a browser (the
  // persistence helpers no-op then, matching the trail() idiom).
  const sessionStore = () => {
    if (opts.sessionStore) return opts.sessionStore;
    try {
      return chrome.storage.session;
    } catch {
      return null;
    }
  };

  // ── parked-session persistence ──
  // MV3 idles the SW away mid-parked conditional get; sessions.session
  // (memory-only, browser-lifetime, extension-private) lets a woke SW
  // resume them. Only page-known ceremony fields persist: no vault rows,
  // no handles, no post-pick state. Undecided conditional sessions only.
  const PARK_KEY = "pkParked";
  const PARK_FIELDS = [
    "id",
    "pageId",
    "contextId",
    "tabId",
    "mode",
    "conditional",
    "origin",
    "rpId",
    "requiresUv",
    "options",
  ];

  async function persistParked() {
    const store = sessionStore();
    if (!store) return;
    try {
      const parked = Array.from(sessions.values())
        .filter((s) => s.conditional && !s.decided)
        .map((s) => {
          const out = { expiresAt: s.expiresAt };
          for (const f of PARK_FIELDS) out[f] = s[f];
          return out;
        })
        .filter((entry) => {
          // A page-controlled options blob can be huge; drop oversized
          // entries individually instead of failing the whole write (a
          // failed write would strand finished sessions in storage).
          try {
            return JSON.stringify(entry).length <= 8192;
          } catch {
            return false;
          }
        });
      await store.set({ [PARK_KEY]: parked });
    } catch {}
  }

  // Absolute expiry, so a resume never extends the RP-declared clock.
  function expireConditional(session) {
    if (!sessions.has(session.id)) return;
    sessions.delete(session.id);
    persistParked();
  }

  async function restoreParked() {
    const store = sessionStore();
    if (!store) return 0;
    let parked;
    try {
      const got = await store.get(PARK_KEY);
      parked = got && Array.isArray(got[PARK_KEY]) ? got[PARK_KEY] : [];
    } catch {
      return 0;
    }
    const now = Date.now();
    let restored = 0;
    for (const e of parked) {
      // Fail closed on junk: every field is re-validated as if the entry
      // came off the wire, and anything not resumable is dropped.
      if (!e || typeof e !== "object") continue;
      if (typeof e.id !== "string" || !e.id || sessions.has(e.id)) continue;
      if (e.mode !== "get" || e.conditional !== true) continue;
      if (typeof e.tabId !== "number" || typeof e.origin !== "string") continue;
      if (!isValidWebAuthnOrigin(e.origin)) continue;
      if (typeof e.rpId !== "string" || !e.rpId) continue;
      if (typeof e.requiresUv !== "boolean") continue;
      if (!e.options || typeof e.options !== "object") continue;
      if (typeof e.expiresAt !== "number" || e.expiresAt <= now) continue;
      const session = {
        id: e.id,
        pageId: typeof e.pageId === "string" ? e.pageId : undefined,
        contextId: typeof e.contextId === "string" ? e.contextId : undefined,
        tabId: e.tabId,
        mode: "get",
        conditional: true,
        decided: null,
        options: e.options,
        origin: e.origin,
        rpId: e.rpId,
        requiresUv: e.requiresUv,
        expiresAt: e.expiresAt,
        rows: [],
      };
      sessions.set(session.id, session);
      session.timer = setTimeout(() => expireConditional(session), Math.max(0, e.expiresAt - now));
      restored += 1;
    }
    if (restored > 0) trail(`parked: resumed ${restored} after SW restart`);
    // Rewrite the cleaned list so dropped entries cannot come back.
    await persistParked();
    return restored;
  }

  // Boot-order gate: every ceremony entry point awaits the restore so a
  // waking SW never answers from an empty map. storage.session.get is an
  // in-memory read; the promise memoizes so late calls pay nothing.
  let restoreReady = null;
  let restoreHasSettled = false;
  function awaitingRestore() {
    if (!restoreReady) {
      restoreReady = restoreParked()
        .then((n) => {
          restoreHasSettled = true;
          return n;
        })
        .catch(() => {
          restoreHasSettled = true;
        });
    }
    return restoreReady;
  }

  // False only in the first moments of a SW life (before the first restore
  // attempt lands); callers use it to hold off destructive cleanup while
  // the bridge reconnect is still in flight.
  const restoreSettled = () => restoreHasSettled;

  async function clearParked() {
    const store = sessionStore();
    if (!store) return;
    try {
      await store.remove(PARK_KEY);
    } catch {}
  }

  // SW-side breadcrumb trail: content-script consoles are invisible to
  // page-level capture and Playwright's worker console events proved
  // unreliable, so ceremony decisions also land in storage.session where
  // any extension page (and the e2e driver) can read them.
  async function trail(msg) {
    try {
      self.__pkTrail = self.__pkTrail || [];
      self.__pkTrail.push(`${new Date().toISOString().slice(11, 19)} ${msg}`);
      await chrome.storage.session.set({ pkTrail: self.__pkTrail.slice(-40) });
    } catch {}
  }

  // sessionId -> session; tabId -> runtime port pushed by the bridge.
  const sessions = new Map();
  const tabPorts = new Map();

  // ── bridge port plumbing ──
  function onBridgePort(port) {
    const tabId = port.sender && port.sender.tab && port.sender.tab.id;
    if (typeof tabId !== "number") {
      try {
        port.disconnect();
      } catch {}
      return;
    }
    tabPorts.set(tabId, port);
    port.onDisconnect.addListener(() => {
      if (tabPorts.get(tabId) === port) tabPorts.delete(tabId);
    });
  }

  function push(session, msg) {
    const port = tabPorts.get(session.tabId);
    if (!port) {
      trail(`push: no bridge port for tab ${session.tabId} (${msg.type})`);
      return false;
    }
    try {
      // The page port map keys on the page-chosen sessionId.
      port.postMessage({ sessionId: session.pageId, contextId: session.contextId, ...msg });
      trail(`push: sent ${msg.type} to tab ${session.tabId}`);
      return true;
    } catch (e) {
      trail(`push: failed ${msg.type}: ${String(e)}`);
      return false;
    }
  }

  function pushSuccess(session, credential) {
    const delivered = push(session, { type: "response", data: { type: "success", credential } });
    finish(session);
    return delivered;
  }

  function pushError(session, name, message) {
    const delivered = push(session, { type: "response", data: { type: "error", name, message } });
    finish(session);
    return delivered;
  }

  function pushFallback(session) {
    const delivered = push(session, {
      type: "response",
      data: { type: "error", name: ErrName.FALLBACK, message: "handed to the browser" },
    });
    finish(session);
    return delivered;
  }

  function finish(session) {
    if (session.timer) {
      clearTimeout(session.timer);
      session.timer = null;
    }
    sessions.delete(session.id);
    closeSessionWindow(session);
    focusTab(session.tabId);
    persistParked();
  }

  // ── daemon plumbing ──
  async function daemon(action, payload) {
    const r = await send(action, payload);
    const raw = typeof r === "string" ? r : (r && r.payload) || "{}";
    try {
      return JSON.parse(raw);
    } catch {
      throw Object.assign(new Error("unparseable daemon response"), { code: "proto" });
    }
  }

  // Normalizes daemon send() failures into {code, message} for the flows
  // below (send rejects with Error + code already set for NMH-level ones).
  function classify(e) {
    const c = {
      code: e && e.code ? String(e.code) : "proto",
      message: String((e && e.message) || ""),
    };
    // Every daemon-failure branch below silently shapes page-facing errors;
    // this is the one place the raw reason stays diagnosable.
    console.warn(`[baluard-passkey] daemon ${c.code}: ${c.message}`);
    return c;
  }

  function buildClientData(type, challenge, origin) {
    const json = JSON.stringify({ type, challenge, origin, crossOrigin: false });
    // Standard base64url without padding, bytes of the UTF-8 JSON.
    let bin = "";
    for (const b of new TextEncoder().encode(json)) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function listPasskeys(rpId) {
    try {
      return await daemon("passkey.list", { rp_id: rpId });
    } catch (e) {
      throw classify(e);
    }
  }

  function rowsForRequest(rows, options) {
    // A credential whose private key never synced cannot sign; offering it
    // would only produce a daemon failure after the user picked it.
    const signable = rows.filter((r) => !r.private_key_missing);
    const allow = options && options.allowCredentials;
    if (!Array.isArray(allow) || allow.length === 0) return signable;
    const wanted = new Set(allow.map((d) => d.id));
    return signable.filter((r) => wanted.has(r.credential_id));
  }

  function rowView(r) {
    return {
      credential_id: r.credential_id,
      cipher_id: r.id,
      name: r.login_name || r.pk_name || r.rp_name || "Passkey",
      username: r.user_name || "",
      vault_slug: r.vault_slug || "",
    };
  }

  // ── validation shared by both ceremonies ──
  // Returns {session, options, origin, rpId} or throws {name} for the page.
  function validateRequest(sender, payload, mode) {
    // Top frames only in v1 (the design's scope cut); the bridge stamps the
    // isolated-world truth, so this is a belt-and-suspenders sender check.
    if (sender && typeof sender.frameId === "number" && sender.frameId !== 0) {
      throw { name: ErrName.SECURITY };
    }
    // sender.origin is the sending document's scheme+host+port as seen from
    // the isolated world. The tab url always describes the top frame and can
    // drift from the sending document, so it is fallback-only.
    const origin =
      typeof sender?.origin === "string" && sender.origin !== "" && sender.origin !== "null"
        ? sender.origin
        : originOf(senderUrlOf(sender));
    if (!isValidWebAuthnOrigin(origin)) {
      throw { name: ErrName.SECURITY };
    }
    if (payload.requested && payload.requested.sameOriginWithAncestors === false) {
      throw { name: ErrName.NOT_ALLOWED };
    }
    const options = payload.options;
    if (!options || typeof options !== "object") {
      throw { name: ErrName.INVALID };
    }
    const host = new URL(origin).hostname;
    const rpId = effectiveRpId(host, mode === "create" ? options.rp && options.rp.id : options.rpId);
    if (!rpId) {
      throw { name: ErrName.SECURITY };
    }
    const session = {
      // The SW mints ceremony ids; the page-chosen sessionId survives only
      // as a per-tab port key, so a hostile page can neither collide with
      // nor guess another tab's (or the popout's) session identity.
      id: mintSessionId(),
      pageId: payload.sessionId,
      contextId: payload.contextId,
      tabId: sender && sender.tab && sender.tab.id,
      mode,
      options,
      origin,
      rpId,
      requiresUv:
        mode === "create"
          ? options.authenticatorSelection?.userVerification === "required"
          : options.userVerification === "required",
      decided: null,
    };
    supersedeTabSessions(session.tabId, session.id);
    sessions.set(session.id, session);
    armTimeout(session);
    persistParked();
    return session;
  }

  const mintSessionId = () =>
    crypto.randomUUID
      ? crypto.randomUUID()
      : Array.from(crypto.getRandomValues(new Uint32Array(4)), (n) => n.toString(16)).join("");

  // One active request per tab (the Bitwarden rule): a newer ceremony on
  // the same tab interrupts the older one, closing its popout and telling
  // its page port so the site's promise never dangles.
  function supersedeTabSessions(tabId, keepId) {
    if (typeof tabId !== "number") return;
    for (const other of Array.from(sessions.values())) {
      if (other.tabId !== tabId || other.id === keepId) continue;
      if (other.timer) clearTimeout(other.timer);
      sessions.delete(other.id);
      push(other, {
        type: "response",
        data: { type: "error", name: ErrName.NOT_ALLOWED, message: "superseded" },
      });
      closeSessionWindow(other);
    }
    persistParked();
  }

  // The RP-declared timeout is clamped at normalization time; enforce it
  // here so a stuck popout cannot hold the session (and the window) open
  // forever. Conditional ceremonies keep the page pending per spec; only
  // the candidate offering stops.
  function armTimeout(session) {
    const ms =
      Number(session.options && session.options.timeout) ||
      (session.requiresUv ? 300_000 : 120_000);
    session.expiresAt = Date.now() + ms;
    session.timer = setTimeout(() => {
      if (!sessions.has(session.id)) return;
      if (session.conditional) {
        expireConditional(session);
        return;
      }
      pushError(session, ErrName.NOT_ALLOWED, "timed out");
    }, ms);
  }

  function senderUrlOf(sender) {
    const url = sender && sender.tab && sender.tab.url;
    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return "";
    return url;
  }

  // ── registration ──
  async function handleCreateRequest(sender, payload) {
    await awaitingRestore();
    let session;
    try {
      session = validateRequest(sender, payload, "create");
    } catch (nameErr) {
      return { error: nameErr.name };
    }
    try {
      await listPasskeys(session.rpId);
      // Site-matched logins are the "save into existing entry" choices;
      // vault_slug rides each row so the save pins the right vault.
      const match = await daemon("bridge.match", { url: senderUrlOf(sender) });
      session.siteRows = (match.matches || []).map((m) => ({
        cipher_id: m.id,
        name: m.name,
        username: m.username,
        vault_slug: m.vault_slug || "",
      }));
    } catch (c) {
      if (c.code === "locked") return prepareUnlock(session);
      // Unpaired or unreachable: the feature is not set up for this
      // browser, so hand the ceremony back to the platform authenticator
      // instead of dead-ending the page.
      if (
        c.code === "no-daemon" ||
        c.code === "nmh-error" ||
        c.code === "version-skew" ||
        c.code === "not-paired"
      ) {
        pushFallback(session);
        return { accepted: true };
      }
      console.warn("[baluard-passkey] register list failed:", c.code, c.message);
      pushError(session, ErrName.NOT_ALLOWED, "Baluard could not read the vault");
      return { accepted: true };
    }
    // Confirm-then-sign: the popout collects the save target; nothing is
    // signed until the user decides, so a closed popout falls back cleanly.
    openModal(session, "confirmRegister");
    return { accepted: true };
  }

  async function runRegistration(session, decision) {
    const target = decision.cipher_id
      ? { cipher_id: decision.cipher_id }
      : { new_login: decision.new_login || { name: (session.options.rp && session.options.rp.name) || session.rpId } };
    try {
      const clientData = buildClientData(
        "webauthn.create",
        session.options.challenge,
        session.origin
      );
      const reg = await daemon("passkey.provider_register", {
        request_json: JSON.stringify(session.options),
        origin: session.origin,
        client_data_json_b64: clientData,
        user_verified: false,
        vault_slug: decision.vault_slug || "",
      });
      await daemon("passkey.store_registered", {
        ceremony_id: reg.ceremony_id,
        cipher_id: target.cipher_id,
        new_login: target.new_login,
        vault_slug: decision.vault_slug || "",
      });
      pushSuccess(session, reg.attestation_response);
    } catch (e) {
      const c = e && e.code ? e : classify(e);
      if (c.code === "locked") {
        openModal(session, "locked");
        return;
      }
      if (pageErrorName(c.message) === "excluded") {
        openModal(session, "excluded");
        return;
      }
      if (String(c.message).includes("passkey:uv-required")) {
        pushError(
          session,
          ErrName.NOT_ALLOWED,
          "This site requires user verification that Baluard cannot provide",
        );
        return;
      }
      pushError(session, ErrName.NOT_ALLOWED, "Baluard could not save the passkey");
    }
  }

  // ── assertion ──
  async function handleGetRequest(sender, payload) {
    await awaitingRestore();
    let session;
    try {
      session = validateRequest(sender, payload, "get");
    } catch (nameErr) {
      return { error: nameErr.name };
    }
    if (payload.mediation === "conditional") {
      // Conditional mediation: hold the request open, surface candidates in
      // the inline dropdown; errors stay silent (the browser's native
      // conditional sheet races ours). The dropdown may ask for candidates
      // while the list is still in flight, so the fetch rides the session
      // as a promise the inline reader can await.
      session.conditional = true;
      persistParked();
      session.rowsPromise = (async () => {
        try {
          const rows = await listPasskeys(session.rpId);
          session.rows = rowsForRequest(rows, session.options).map(rowView);
        } catch (e) {
          trail(`cond: list failed ${e && e.code ? e.code : e && e.message}`);
          session.rows = [];
        }
      })();
      return { accepted: true };
    }
    let rows;
    try {
      rows = await listPasskeys(session.rpId);
    } catch (c) {
      if (c.code === "locked") return prepareUnlock(session);
      if (
        c.code === "no-daemon" ||
        c.code === "nmh-error" ||
        c.code === "version-skew" ||
        c.code === "not-paired"
      ) {
        pushFallback(session);
        return { accepted: true };
      }
      pushError(session, ErrName.NOT_ALLOWED, "Baluard could not read the vault");
      return { accepted: true };
    }
    const usable = rowsForRequest(rows, session.options).map(rowView);
    if (usable.length === 0) {
      openModal(session, "notFound");
      return { accepted: true };
    }
    // Bitwarden parity: a credential is never served without an explicit
    // user decision, even when only one candidate exists.
    session.rows = usable;
    openModal(session, "pickAssertion");
    return { accepted: true };
  }

  async function runAssertion(session, row) {
    try {
      const clientData = buildClientData("webauthn.get", session.options.challenge, session.origin);
      const assertion = await daemon("passkey.provider_assert", {
        request_json: JSON.stringify(session.options),
        origin: session.origin,
        credential_id: row.credential_id,
        client_data_json_b64: clientData,
        user_verified: false,
        vault_slug: row.vault_slug || "",
      });
      // Counter persistence is advisory: synced passkeys carry counter 0
      // and shared-vault viewers are write-gated, so a refusal must not
      // fail an assertion that was already issued. Mobile skips it too.
      try {
        await daemon("passkey.consume_assertion", {
          ceremony_id: assertion.ceremony_id,
          vault_slug: row.vault_slug || "",
        });
      } catch (e) {
        console.warn("[baluard-passkey] counter persistence skipped:", e && e.message);
      }
      return pushSuccess(session, assertion.assertion_response);
    } catch (e) {
      const c = e && e.code ? e : classify(e);
      if (c.code === "locked") {
        session.pendingRow = row;
        openModal(session, "locked");
        return false;
      }
      if (String(c.message).includes("passkey:uv-required")) {
        return pushError(
          session,
          ErrName.NOT_ALLOWED,
          "This site requires user verification that Baluard cannot provide",
        );
      }
      return pushError(session, pageErrorName(c.message), "Baluard could not complete the sign-in");
    }
  }

  // ── conditional continuation (inline dropdown) ──
  // Conditional continuation (inline dropdown). The session's parked
  // origin must match the asking document: tab ids survive navigation, so
  // a restored session must never surface to a page it was not parked for.
  function activeConditionalForTab(sender) {
    const tabId = sender && sender.tab && sender.tab.id;
    const origin =
      typeof sender?.origin === "string" && sender.origin !== "" && sender.origin !== "null"
        ? sender.origin
        : originOf(senderUrlOf(sender));
    for (const s of sessions.values()) {
      if (s.conditional && s.tabId === tabId && !s.decided && s.origin === origin) return s;
    }
    return null;
  }

  async function handleInlinePasskeys(sender) {
    await awaitingRestore();
    const session = activeConditionalForTab(sender);
    if (!session) return { rows: [] };
    // The candidate list may still be in flight; wait for it rather than
    // rendering a menu without the passkey rows the user is waiting for.
    if (session.rowsPromise) await session.rowsPromise;
    // An unlock can land between request time and dropdown open (the first
    // list ran while locked and cached nothing), so an empty list retries
    // once per open.
    if ((!session.rows || session.rows.length === 0) && !session.relisting) {
      session.relisting = true;
      try {
        const rows = await listPasskeys(session.rpId);
        session.rows = rowsForRequest(rows, session.options).map(rowView);
      } catch {
        // Still nothing; the next dropdown open retries after the unlock.
      }
      session.relisting = false;
    }
    return { rows: session.rows || [], sessionId: session.id };
  }

  async function handleInlinePick(sender, credentialId) {
    await awaitingRestore();
    trail(`pick: tab=${sender && sender.tab && sender.tab.id} cred=${credentialId}`);
    const session = activeConditionalForTab(sender);
    if (!session) {
      trail("pick: no active conditional session");
      return { error: "no session" };
    }
    const row = (session.rows || []).find((r) => r.credential_id === credentialId);
    if (!row) {
      trail("pick: unknown credential");
      return { error: "unknown credential" };
    }
    trail("pick: session ok, asserting (presence only)");
    session.decided = "inline";
    // Decide-point persist: a pick in flight must not resurrect as an
    // undecided parked session if the SW dies mid-assertion.
    persistParked();
    const pushed = await runAssertion(session, row);
    trail(`pick: done pushed=${pushed !== false}`);
    // Report the outcome on a second channel: the runtime-port push can
    // silently die (stale port after an SW restart), and the pick side has
    // no other way to know.
    try {
      chrome.tabs.sendMessage(session.tabId, {
        type: "baluard-passkey-pick-result",
        pushed: pushed !== false,
        // The bridge forwards a failure onto the page port; both ids are
        // needed to address the right MessageChannel session.
        sessionId: session.pageId,
        contextId: session.contextId,
      });
    } catch {}
    return { accepted: true, pushed: pushed !== false };
  }

  // ── popout session state (the popup app reads + decides) ──
  function uiState(sessionId) {
    const s = sessions.get(sessionId);
    if (!s) return { gone: true };
    return {
      id: s.id,
      kind: s.uiKind,
      rpId: s.rpId,
      rpName: (s.mode === "create" && s.options.rp && s.options.rp.name) || s.rpId,
      userName: s.mode === "create" ? (s.options.user && s.options.user.name) || "" : "",
      rows: s.rows || [],
      siteRows: s.siteRows || [],
    };
  }

  function openModal(session, uiKind) {
    session.uiKind = uiKind;
    openPopout(session);
  }

  // Default popout: anchored near the tab's window. The window id lands
  // asynchronously; pendingWindow lets closeSessionWindow close it even if
  // the ceremony finished first, and the post-create check kills an orphan
  // window whose session already ended.
  async function openPopoutDefault(session) {
    const url = chrome.runtime.getURL(`popup.html#/passkey/${encodeURIComponent(session.id)}`);
    const create = (left, top) =>
      chrome.windows.create({
        url,
        type: "popup",
        width: 400,
        height: 560,
        left: Math.max(0, left),
        top: Math.max(0, top),
        focused: true,
      });
    const anchor = await new Promise((resolve) => {
      chrome.tabs.get(session.tabId, (tab) => {
        if (chrome.runtime.lastError || !tab || typeof tab.windowId !== "number") return resolve(null);
        chrome.windows.get(tab.windowId, { populate: false }, (tabWindow) => {
          if (chrome.runtime.lastError || !tabWindow) return resolve(null);
          resolve({ left: tabWindow.left || 0, top: tabWindow.top || 0 });
        });
      });
    });
    const pending = create(anchor ? anchor.left + 80 : 100, anchor ? anchor.top + 80 : 100);
    session.pendingWindow = pending;
    try {
      const w = await pending;
      session.pendingWindow = null;
      if (!w || typeof w.id !== "number") return;
      if (!sessions.has(session.id)) {
        try {
          chrome.windows.remove(w.id);
        } catch {}
        return;
      }
      session.windowId = w.id;
    } catch {
      session.pendingWindow = null;
    }
  }
  const openPopout = opts.openPopout || openPopoutDefault;

  // Locked vault: the extension cannot unlock (the desktop app owns the
  // master password). Keep the ceremony pending; the popout offers retry.
  function prepareUnlock(session) {
    session.uiKind = "locked";
    openModal(session, "locked");
    return { accepted: true };
  }

  async function uiDecide(sessionId, decision) {
    const s = sessions.get(sessionId);
    if (!s) return { error: "gone" };
    const kind = decision && decision.kind;
    if (kind === "retryUnlock") {
      // Re-probe the vault, then reopen whichever view the session needs.
      try {
        if (s.mode === "create") {
          await listPasskeys(s.rpId);
          s.uiKind = "confirmRegister";
          return { ok: true, state: uiState(sessionId) };
        }
        if (s.pendingRow) {
          const row = s.pendingRow;
          s.pendingRow = null;
          s.uiKind = undefined;
          closeSessionWindow(s);
          await runAssertion(s, row);
          return { ok: true };
        }
        const rows = rowsForRequest(await listPasskeys(s.rpId), s.options).map(rowView);
        if (rows.length === 0) {
          s.uiKind = "notFound";
        } else {
          s.rows = rows;
          s.uiKind = "pickAssertion";
        }
        return { ok: true, state: uiState(sessionId) };
      } catch {
        s.uiKind = "locked";
        return { ok: true, state: uiState(sessionId) };
      }
    }
    if (kind === "confirmRegister") {
      closeSessionWindow(s);
      await runRegistration(s, decision);
      return { ok: true };
    }
    if (kind === "pickAssertion") {
      const row = (s.rows || []).find((r) => r.credential_id === decision.credential_id);
      if (!row) return { error: "unknown credential" };
      closeSessionWindow(s);
      await runAssertion(s, row);
      return { ok: true };
    }
    if (kind === "dismiss") {
      // Info screens (not-found / excluded) decline the ceremony.
      pushError(s, ErrName.NOT_ALLOWED, "declined in Baluard");
      return { ok: true };
    }
    if (kind === "cancel") {
      pushFallback(s);
      return { ok: true };
    }
    return { error: "unknown decision" };
  }

  function closeSessionWindow(s) {
    if (s.pendingWindow) {
      // The window id lands asynchronously; closing mid-create hands the
      // close over to the create promise so nothing leaks.
      const pending = s.pendingWindow;
      s.pendingWindow = null;
      pending
        .then((w) => {
          try {
            chrome.windows.remove(w.id);
          } catch {}
        })
        .catch(() => {});
      return;
    }
    if (typeof s.windowId === "number") {
      try {
        chrome.windows.remove(s.windowId);
      } catch {}
      s.windowId = undefined;
    }
  }

  function popoutClosed(windowId) {
    for (const s of sessions.values()) {
      if (s.windowId !== windowId) continue;
      s.windowId = undefined;
      if (!s.decided) pushFallback(s);
      else finish(s);
    }
  }

  function cleanupTab(tabId) {
    for (const s of Array.from(sessions.values())) {
      if (s.tabId === tabId) {
        if (s.timer) clearTimeout(s.timer);
        sessions.delete(s.id);
        closeSessionWindow(s);
      }
    }
    tabPorts.delete(tabId);
    persistParked();
  }

  // Test seam + window.onRemoved wiring. Awaiting the restore here stops
  // a queued tab-removed event from resurrecting a dead tab's entry.
  async function cleanupTabAfterRestore(tabId) {
    await awaitingRestore();
    cleanupTab(tabId);
  }

  function activeSessions() {
    return Array.from(sessions.values());
  }

  async function handleAbortRequest(sender, sessionId) {
    await awaitingRestore();
    // The bridge aborts with the page-chosen id; match within the tab.
    const s = Array.from(sessions.values()).find(
      (x) => x.pageId === sessionId && (!sender || !sender.tab || x.tabId === sender.tab.id)
    );
    if (s) {
      if (s.timer) clearTimeout(s.timer);
      sessions.delete(s.id);
      closeSessionWindow(s);
      persistParked();
    }
    return { ok: true };
  }

  return {
    onBridgePort,
    handleCreateRequest,
    handleGetRequest,
    handleAbortRequest,
    handleInlinePasskeys,
    handleInlinePick,
    uiState,
    uiDecide,
    popoutClosed,
    cleanupTab: cleanupTabAfterRestore,
    restoreParked,
    restoreSettled,
    clearParked,
    hasTabPort: (tabId) => tabPorts.has(tabId),
    activeSessions,
  };
}

// ── default browser shims (overridable in tests) ──
function defaultFocusTab(tabId) {
  if (typeof tabId !== "number") return;
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab) return;
    chrome.tabs.update(tabId, { active: true });
    if (typeof tab.windowId === "number") chrome.windows.update(tab.windowId, { focused: true });
  });
}
