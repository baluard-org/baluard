# Browser Extension Code Health Review: YAGNI / KISS / DRY / Dead Code

Scope: `browser/shared/src` (background service worker, content scripts, popup), `browser/shared/manifest.base.json`, `browser/shared/vite.config.js`, `browser/chrome` + `browser/firefox` packaging. Companion to the desktop and mobile code-health docs; same method.

Baseline at `8474903`: vitest 96/96 green, `npm run build` (chrome + firefox) green, dists rebuilt. The dists are committed per B11 and guarded by the `dist-css.test.js` canary, so the implementation commit must include refreshed dists.

Method: file-by-file read of all six source modules plus manifests and build config; scripted dead-key sweep over the popup string tables (with a property-access pass — `strings.foo` usage does not show up in a `t("foo")` grep); usage greps for every export.

## 1. Dead code (delete)

| ID | Item | Evidence | Action |
|----|------|----------|--------|
| D1 | `browser/chrome/package.json` + `browser/firefox/package.json` | Zero references: builds run from `browser/shared` (justfile `test-browser` / `extension-build`), there is no workspace config, and no script or doc mentions them | Delete both files |
| D2 | popup.jsx STRINGS `openApp` (en + es) | Defined, never rendered. The no-daemon view uses `appRequired`; downloads use `downloadApp` | Delete from both locales |
| D3 | popup.jsx STRINGS `search` (en + es) | Defined, never rendered — the popup has no search input (matches list is unfiltered). YAGNI leftover | Delete from both locales |
| D4 | inline.js `stillOnField` | Always `false`: the enclosing `if` already requires `e.target !== targetInput`, so `if (!stillOnField && …)` is a constant-true branch around a dead variable | Delete variable + branch, keep the hide logic |
| D5 | content.js re-export block | `export { fillLoginForm, visibleInputs, isTextLike, isVisible, setNativeValue }` exists only so tests can import helpers through content.js. Point `content.test.js` at `autofill.js` (the actual home) and delete the re-export; content.js keeps only its fill-executor IIFE | Delete re-export, retarget the test imports |
| D6 | background.js `CLEAR_CHOICES` + hand-rolled validation in `getClipboardClearSeconds` | Exact duplicate of `settings.js` `CLEAR_SECONDS_CHOICES` + `normalizeClearSeconds`. The "must not import settings.js" comment is stale: `vite.config.js` esbuild-BUNDLES background.js (`bundle: true`) with imports resolved — it is not "copied verbatim" | Import `normalizeClearSeconds` from settings.js, drop the local copy, fix the stale comment |
| D7 | Debug `console.log` chatter | popup.jsx ×6 (`refresh silent=`, `connect() called`, `pair_complete resolved OK`, `connect failed:`, `boot cached=`, `isStillUnpaired=`) and background.js ×4 (`ping raw resp:`, `parsed nmh_version:`, `onMessage`, `no pending entry for id`). Request ids and protocol payloads log to the page-independent SW/popup consoles in production | Delete the `console.log` calls; keep every `console.warn`/`console.error` (real failures, all justified) |
| D8 | autofill.js stale half-comment in `fillLoginForm` | "Best-effort: submit the form if there's a submit button…" is immediately revoked by "We do NOT auto-submit". The first sentence promises the opposite of the behavior | Trim to the actual rule |

Deliberately NOT dead (checked, keep): `statusKeyFor` switch (unit-tested), `settings.js` `CLEAR_SECONDS_CHOICES` export (used by tests + `normalizeClearSeconds`), the popup STRINGS table split from inline.js STRINGS (separate bundles, self-contained by design), `dist-css.test.js` canary (guards a real, shipped bug class), `getLastState` legacy-scalar branch (migration guard for older cached values).

## 2. i18n

The extension carries two self-contained string tables (popup STRINGS ~51 keys ×2 locales, inline STRINGS 10 keys ×2 locales — content scripts cannot fetch locale JSON, so this shape is correct).

- Parity: en/es exact in both tables; the inline `statusKeyFor` outputs all resolve.
- Dead keys: `openApp` + `search` (D2/D3). One sweep caveat recorded for the future: `wrongCode`/`pairExpired` are consumed via `strings.foo` property access, not `t("foo")` — a literal-key grep alone reports them dead. The audit must include property-access passes.
- No hardcoded user-facing strings outside the two tables (the SW has no UI; badge + alerts never surface raw text).

## 3. DRY violations

| ID | Duplication | Fix |
|----|-------------|-----|
| R1 | `originOf(url)` duplicated identically in background.js (exported, tested) and popup.jsx (private, untested) | Move to a tiny shared module both bundles import (both go through bundlers that resolve imports); popup gains test coverage by proxy |
| R2 | background.js re-implements the settings read three times (`settingEnabled`, `getClipboardClearSeconds`, `syncInlineScript`) and re-validates the clear-seconds choice (see D6) | Use settings.js `getSettings` + `normalizeClearSeconds` for the seconds path; fold the three storage reads through one local `readSettings()` helper |
| R3 | inline.js `isVisibleField` duplicates autofill.js `isVisible` line for line. The "local copies" comment predates the bundler setup — inline.js already imports five helpers from autofill.js | Delete the local copy, import `isVisible` |
| R4 | Clipboard auto-clear fallback timer (`normalizeClearSeconds` + `setTimeout` overwrite-with-space) appears in popup.jsx and inline.js | Accepted duplication: three lines, two different execution contexts (popup document vs page), and extracting it saves less than the indirection costs. Noted, not actioned |

## 4. KISS / YAGNI

| ID | Item | Verdict |
|----|------|---------|
| K1 | `connect()` calls `detectBrowser()` twice for `name` and `browser` fields of pair_complete | Hoist one `const browser = detectBrowser()`. Note: `name === browser` looks odd but matches what the daemon's device list expects today; not changed |
| K2 | popup.jsx is 817 lines mixing string tables, state machine, actions, and view | Deferred: it is a single conventional popup surface, tested through the popup-*.test.jsx files; splitting buys structure, not clarity, at this size |
| K3 | `statusKeyFor` switch vs map | Leave: switch is clear and unit-tested |
| K4 | `CACHEABLE_STATES` includes `"connecting"` while the comment above it says transient states are "never cached" | The code is right (boot() resumes held pairings within the TTL); the comment is wrong. Fix the comment, not the code |

## 5. Packaging / build

- `vite.config.js`: sound. The esbuild IIFE step exists for a real reason (Firefox `background.scripts` classic-page compatibility; exports are a syntax error there) — do not "simplify" it away.
- `manifest.base.json` + firefox extra: the offscreen permission subtraction for Firefox matches the B8 fallback in background.js. Keep.
- Icon pipeline (sharp trim + centered composite) is deliberate; the comment explains why the desktop logo tile is not reused. Keep.
- The stale "copied verbatim" claims in background.js/vite.config comments are corrected by D6/R2 (background.js IS bundled).

## 6. Suggested execution order

1. Deletions (D1–D8) + comment fixes (K4). Run vitest + build; commit dists.
2. DRY (R1 shared origin module, R2 settings reuse, R3 import isVisible). Run vitest + build; commit dists.
3. K1 micro-cleanup. Final vitest + build.
4. Manual smoke is NOT available in this environment (no browser with the NMH paired) — the vitest suite plus both target builds are the gate; flag that in the commit body.

One commit for the pass (`refactor(browser): …`), dists included, after peer review of this document.

## Peer review

### Peer review A

First pass returned no output (tool-side stall, known issue with file-reading turns); a bounded retry scoped to the packaging section completed: AGREE on all five sections, and an independent read of `vite.config.js` confirmed the stale-"copied verbatim"-comment claim (esbuild IIFE bundling at lines 65-78).

### Peer review B

AGREE on all five sections; every D/R/K item independently verified against source, no false positives. Two additions folded in:

1. The orphan `package.json` claim was checked beyond the repo tree I had swept: `.github/workflows/extension.yml` and the justfile only touch `browser/shared` and treat `browser/{chrome,firefox}/dist` as build OUTPUT — the two `package.json` files are referenced nowhere.
2. D6 safety confirmed: esbuild IIFE bundling resolves and inlines `import` statements (only `export` is a syntax error on Firefox's classic event page), and both modules use the same `"settings"` storage key — no divergence. Minor note adopted: keep background.js's "exported for unit tests" comment accurate when the export list changes in the R2 edit.
