import { createSignal } from "solid-js";

let nextId = 0;

// ── Toast signal ──
const [toasts, setToasts] = createSignal([]);

/**
 * Push a toast notification.
 * @param {"success"|"error"|"warning"|"info"} type
 * @param {string} message
 * @param {object} [opts]
 * @param {number} [opts.duration=4000]  Auto-dismiss ms (0 = manual only)
 * @param {boolean} [opts.manual=false]   Show dismiss button
 */
export function toast(type, message, opts = {}) {
  const id = ++nextId;
  const duration = opts.duration ?? 4000;
  const manual = opts.manual ?? false;

  const entry = { id, type, message, manual };
  setToasts(prev => [...prev, entry]);

  if (duration > 0) {
    setTimeout(() => dismiss(id), duration);
  }

  return id;
}

/** Dismiss a specific toast by id. */
export function dismiss(id) {
  setToasts(prev => prev.filter(t => t.id !== id));
}

/** Convenience shortcuts */
export const toastSuccess = (msg, opts) => toast("success", msg, opts);
export const toastError   = (msg, opts) => toast("error",   msg, { duration: 6000, manual: true, ...opts });
export const toastWarning = (msg, opts) => toast("warning", msg, { duration: 5000, ...opts });
export const toastInfo    = (msg, opts) => toast("info",    msg, { duration: 7000, ...opts });

export { toasts };
