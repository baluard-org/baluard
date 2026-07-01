import { createContext, createSignal, useContext } from "solid-js";

// Conflict resolution queue — the human-in-the-loop backstop for the rare case
// where the sync engine cannot auto-merge an item edited on two devices.
//
// SECURITY: pending conflicts carry NO secret values. Each field entry is a
// label + a `sensitive` flag only. Passwords/TOTP/card numbers are masked at
// the source (daemon side, when wired) and never cross IPC. See
// docs/plan-conflict-resolution-panel.md (§ Security).
//
// DECISION granularity is per-entry: keep local / keep remote / keep both.
//
// The shape below is the contract the daemon's future `sync.conflict` route
// will produce. Until that route exists, use `mockSample()` to review the UX.

const ConflictResolutionContext = createContext();

/**
  * @typedef {Object} ConflictField
  * @property {string} key        Field identifier ("password", "notes", ...).
  * @property {string} label      Human-readable, i18n'd field label.
  * @property {boolean} sensitive True => mask; value must never be shown/sent.
  *
  * @typedef {Object} PendingConflict
  * @property {string} cipherId     Opaque id, never displayed.
  * @property {string} name         Entry display name (plaintext metadata).
  * @property {string} cipherType   "login" | "card" | ... (icon + label).
  * @property {boolean} typeChanged One side changed the entry kind entirely.
  * @property {ConflictField[]} fields Conflicting field labels.
  * @property {string|null} localDevice  Friendly device name for plain language.
  * @property {string|null} remoteDevice Friendly device name.
  *
  * @typedef {"keep_local"|"keep_remote"|"keep_both"} ConflictVerdict
  */

export function ConflictResolutionProvider(props) {
  // Queue of pending conflicts. The panel resolves one at a time (1 of N).
  const [pending, setPending] = createSignal(
    /** @type {PendingConflict[]} */ ([]),
  );

  /** True when there is at least one conflict awaiting a user decision. */
  const hasPending = () => pending().length > 0;

  /** The current (first) conflict, or null. */
  const current = () => pending()[0] ?? null;

  /**
    * Enqueue conflicts surfaced by the sync engine. Idempotent on cipherId:
    * a cipher already in the queue is not duplicated.
    * @param {PendingConflict | PendingConflict[]} conflicts
    */
  function enqueue(conflicts) {
    const list = Array.isArray(conflicts) ? conflicts : [conflicts];
    setPending((prev) => {
      const seen = new Set(prev.map((c) => c.cipherId));
      const merged = [...prev];
      for (const c of list) {
        if (c && !seen.has(c.cipherId)) {
          merged.push(c);
          seen.add(c.cipherId);
        }
      }
      return merged;
    });
  }

  /**
    * Resolve the current conflict with a verdict. Invokes the caller-supplied
    * resolver (the future IPC call) and drops the conflict from the queue.
    * @param {ConflictVerdict} verdict
    * @param {(conflict: PendingConflict, verdict: ConflictVerdict) => Promise<void>|void} [resolver]
    */
  async function resolve(verdict, resolver) {
    const head = current();
    if (!head) return;
    try {
      if (resolver) await resolver(head, verdict);
    } finally {
      setPending((prev) => prev.filter((c) => c.cipherId !== head.cipherId));
    }
  }

  /** Drop everything (e.g. on vault lock / switch). */
  function clear() {
    setPending([]);
  }

  const value = {
    pending,
    hasPending,
    current,
    count: () => pending().length,
    enqueue,
    resolve,
    clear,
  };

  return (
    <ConflictResolutionContext.Provider value={value}>
      {props.children}
    </ConflictResolutionContext.Provider>
  );
}

export function useConflictResolution() {
  const ctx = useContext(ConflictResolutionContext);
  if (!ctx) {
    throw new Error(
      "useConflictResolution must be used within ConflictResolutionProvider",
    );
  }
  return ctx;
}

// ── Mock for UX review (no backend yet) ──────────────────────────────────
// Call enqueue(mockSampleConflict()) from a dev trigger to see the panel.
export function mockSampleConflict(overrides = {}) {
  return {
    cipherId: "mock-" + Math.random().toString(36).slice(2, 8),
    name: "GitHub",
    cipherType: "login",
    typeChanged: false,
    fields: [
      { key: "password", label: "Password", sensitive: true },
      { key: "notes", label: "Notes", sensitive: false },
    ],
    localDevice: "This Mac",
    remoteDevice: "iPhone",
    ...overrides,
  };
}

export function mockSampleTypeChange() {
  return mockSampleConflict({
    cipherId: "mock-type-" + Math.random().toString(36).slice(2, 8),
    name: "Bank login",
    cipherType: "login",
    typeChanged: true,
    fields: [],
  });
}
