# Plan: Frontend Candidates A–D

## Context

Four refactor candidates from `docs/architecture-decisions.md` (D11). All are pure frontend refactors — no behavioral changes, no Rust/daemon changes.

**Current state**: Build passes, 64/64 tests pass.

---

## Candidate D: SVG Icon Component (start here — lowest risk, immediate readability win)

**Problem**: 70 inline `<svg>` elements across 13 files. VaultView has 24. Categories array is 13 lines of mostly SVG path data.

**Approach**: Create `components/Icon.jsx` with named icon components. Each icon is a function that takes `class` and optional props.

```jsx
// components/Icon.jsx
export function IconLock(props) { return <svg {...props}>...</svg>; }
export function IconKey(props) { return <svg {...props}>...</svg>; }
// etc.

// Usage:
import { IconLock } from "./Icon.jsx";
<IconLock class="w-4 h-4 shrink-0" />
```

**Files to create**: `desktop/src/components/Icon.jsx`

**Files to modify**: All 13 components that use inline SVGs. The categories array in VaultView drops from 13 lines of SVG soup to `{ name: "Login", icon: <IconLock class="w-4 h-4 shrink-0" /> }`.

**Reuse**: All existing icons — extract every unique SVG path into a named export.

**Steps**:
- [ ] Create `Icon.jsx` with all unique icons as named exports
- [ ] Migrate VaultView categories array (biggest win)
- [ ] Migrate VaultView inline SVGs (24 instances)
- [ ] Migrate remaining 12 components
- [ ] Build + test

---

## Candidate B: Filter Pipeline

**Problem**: 45 lines of filter logic embedded in VaultView as a computed `filteredCiphers()`. Category-to-type mapping duplicated across VaultView (filter) and payload.js (buildKind). Zero tests for this logic.

**Approach**: Extract to `lib/filters.js` as pure, testable functions.

```js
// lib/filters.js
export const CATEGORY_TYPE_MAP = {
  "Login": "login", "Card": "card", "Identity": "identity",
  "Secure note": "secureNote", "SSH key": "sshKey",
  "Bank account": "bankAccount", "Driver license": "driversLicense",
  "Passport & ID": "passport",
};

export function filterByCategory(ciphers, category) { ... }
export function filterByFolder(ciphers, folders, folderId) { ... }  // includes descendants
export function searchCiphers(ciphers, query) { ... }
```

**Files to create**: `desktop/src/lib/filters.js`

**Files to modify**: `VaultView.jsx` (replace inline `filteredCiphers` with composed calls)

**Steps**:
- [ ] Create `lib/filters.js` with `CATEGORY_TYPE_MAP`, `filterByCategory`, `filterByFolder`, `searchCiphers`
- [ ] Write vitest tests for each function (this is the main value — currently untested)
- [ ] Update VaultView to import and compose: `searchCiphers(filterByFolder(filterByCategory(source, cat), folders, folder), query)`
- [ ] Build + test

---

## Candidate C: Screen State Machine

**Problem**: Two ad-hoc state machines. `status` has 6 states with transitions scattered across AuthContext. `activePane` has 4 states with transitions in VaultContext + CipherDetail + VaultView. The store split simplified `lock()` via structural reset, but `activePane` transitions are still unprotected.

**Approach**: Not a full state machine library. Just a documented lookup table + guard function for each machine. Keep it pragmatic.

```js
// AuthContext.jsx — document valid transitions
const VALID_AUTH_TRANSITIONS = {
  locked:   ["unlocking", "init"],
  unlocking: ["unlocked", "locked"],
  unlocked: ["locked"],
  init:     ["creating"],
  creating: ["recovery", "init"],
  recovery: ["init", "locked"],
};

function authTransition(from, to) {
  if (!VALID_AUTH_TRANSITIONS[from]?.includes(to)) {
    console.warn(`Invalid auth transition: ${from} → ${to}`);
  }
  return to;
}
```

Same pattern for `activePane` in VaultContext.

**Files to modify**: `AuthContext.jsx`, `VaultContext.jsx`

**No new files needed.**

**Steps**:
- [ ] Add `VALID_AUTH_TRANSITIONS` table + `authTransition()` guard to AuthContext
- [ ] Wrap all `setStatus()` calls through `authTransition()`
- [ ] Add `VALID_PANE_TRANSITIONS` table + `vaultTransition()` guard to VaultContext
- [ ] Wrap all `setActivePane()` calls through `vaultTransition()`
- [ ] Build + test

---

## Candidate A: Mega-Form Refactor (highest impact, most complex)

**Problem**: `AddEditCipherForm.jsx` is 850 lines. `CipherDetail.startEdit()` is 80 lines mapping structured → flat. `payload.buildKind()` is 100 lines mapping flat → structured. Three files must agree on 60+ field names. No type safety. Adding a cipher type requires editing all 3.

**Approach**: Extract a `lib/cipherSchema.js` that defines field schemas per cipher type. The schema is the single source of truth for:
1. Field names (flat buffer keys)
2. Labels and placeholders (i18n keys)
3. Mapping from structured daemon response → flat buffer (replaces startEdit)
4. Mapping from flat buffer → structured payload (replaces buildKind)

```js
// lib/cipherSchema.js
export const CIPHER_SCHEMAS = {
  login: {
    typeKey: "login",
    fields: [
      { key: "username", label: "entry.user", placeholder: "entry.usernamePlaceholder" },
      { key: "password", label: "entry.pass", placeholder: "entry.passwordPlaceholder", type: "password" },
      { key: "totp_uri", label: "TOTP URI", placeholder: "otpauth://totp/...", mono: true },
    ],
    lists: ["uris"],
    fromKind(kind) {
      const d = kind.login || kind.Login || {};
      return { username: d.username, password: d.password, uris: d.uris, totp_uri: d.totp_uri };
    },
    toKind(flat) {
      return { type: "login", data: { username: flat.username, password: flat.password, uris: flat.uris, totp_uri: flat.totp_uri } };
    },
  },
  // ... 7 more types
};
```

Then:
- `CipherDetail.startEdit()` becomes `CIPHER_SCHEMAS[type].fromKind(cipher.kind)` + common fields
- `payload.buildKind()` becomes `CIPHER_SCHEMAS[type].toKind(flatBuffer)`
- `AddEditCipherForm` iterates `CIPHER_SCHEMAS[type].fields` to render inputs instead of 8 `<Show>` blocks

**Files to create**: `desktop/src/lib/cipherSchema.js`

**Files to modify**:
- `AddEditCipherForm.jsx` — replace 8 `<Show>` blocks with schema-driven rendering
- `CipherDetail.jsx` — replace 80-line startEdit with schema `fromKind()`
- `lib/payload.js` — replace 100-line `buildKind` with schema `toKind()`

**Steps**:
- [ ] Create `lib/cipherSchema.js` with all 8 type schemas (fields, fromKind, toKind)
- [ ] Write vitest tests for `fromKind` and `toKind` roundtrips per type
- [ ] Update `CipherDetail.startEdit()` to use schema
- [ ] Update `payload.buildKind()` to use schema
- [ ] Rewrite `AddEditCipherForm.jsx` — schema-driven field rendering
- [ ] Build + test

---

## Execution Order

D → B → C → A

Rationale: D and B are independent, low-risk, and provide immediate value (D: readability, B: testability). C is small and prepares the ground for understanding state flow. A is the biggest refactor and benefits from having B, C, D done first (cleaner diff, schema can reference CATEGORY_TYPE_MAP from B).

## Verification

After each candidate:
- `npx vite build` — must pass
- `npx vitest run` — all 64+ tests must pass
- For B and A: new tests must be added for extracted logic

## What stays untouched

- `daemon.js`, `utils.js`, `app.css` — per frontend constraints
- `i18n/` keys — no new keys, just reuse existing
- `AuthContext.jsx` / `VaultContext.jsx` — unchanged except Candidate C
- `context/errorSignal.js`, `context/themeSignal.js` — unchanged
