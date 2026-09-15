// Shared DEV-only transition diagnostics (code-health R7).
// Warns when a transition is missing from the table — in dev builds only.
// The state write ALWAYS runs: prod drops the check via import.meta.env.DEV,
// and the guard must never gate the write itself.
export function makeTransitionGuard(table, tag) {
  return (from, to, set) => {
    if (import.meta.env.DEV && !table[from]?.includes(to)) {
      console.warn(`[${tag}] Invalid transition: ${from} → ${to}`);
    }
    set(to);
  };
}
