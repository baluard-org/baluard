// Shown-once secrets held across unexpected unmounts. The OS stealing
// focus fires lock-on-blur, which unmounts a ceremony mid-showing and
// would destroy the only display of the phrase (the 2026-10-01 review).
// Process memory only — never persisted. Entries are keyed by ceremony
// kind ("kit" | "recovery") so one ceremony can never surface another's
// phrase. The holder clears a kind when the user confirms storage; the
// vault switch path clears everything so a phrase can never resurface
// on a different vault.
let held = {}; // kind -> value

export function holdPhrase(kind, value) {
  held[kind] = value;
}

export function takeHeldPhrase(kind) {
  return held[kind] ?? null;
}

export function clearHeldPhrase(kind) {
  if (kind) {
    delete held[kind];
  } else {
    held = {};
  }
}
