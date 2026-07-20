// Global chrome.* / navigator.clipboard mock for the browser extension tests.
// Loaded via vitest's `setupFiles` so the mock exists before any source file
// is imported (the source files' top-level IIFEs register chrome listeners
// at import time).

const noop = () => {};

const chromeMock = {
  runtime: {
    sendMessage: (_msg, cb) => {
      // In tests we don't auto-fire listeners — call sites that need a
      // response stub it explicitly via mockChromeSendMessage below.
      if (cb) cb();
    },
    onMessage: { addListener: noop, removeListener: noop, hasListener: () => false },
    connectNative: () => ({
      postMessage: noop,
      onMessage: { addListener: noop },
      onDisconnect: { addListener: noop },
    }),
    lastError: null,
  },
  storage: {
    local: {
      get: (_keys, cb) => cb && cb({}),
      set: (_obj, cb) => cb && cb(),
    },
  },
  tabs: {
    query: (_opts, cb) => cb && cb([]),
    sendMessage: noop,
    get: (id, cb) => cb && cb({ id, url: "" }),
    onActivated: { addListener: noop },
    onUpdated: { addListener: noop },
  },
  action: {
    setBadgeText: noop,
    setBadgeBackgroundColor: noop,
  },
  scripting: { executeScript: noop },
  offscreen: {
    createDocument: async () => undefined,
    hasDocument: async () => false,
  },
  alarms: {
    create: noop,
    onAlarm: { addListener: noop },
  },
  i18n: { getUILanguage: () => "en" },
};

globalThis.chrome = chromeMock;

// navigator.clipboard.writeText — Promise-based mock. Tests can override
// globalThis.navigator.clipboard.writeText directly to assert on calls.
if (!globalThis.navigator) globalThis.navigator = {};
if (!globalThis.navigator.clipboard) {
  globalThis.navigator.clipboard = {
    writeText: async (_text) => undefined,
  };
}