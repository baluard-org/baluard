# Desktop Code Health Review: YAGNI / KISS / DRY / Dead Code

Scope: `desktop/src` (SolidJS frontend), `desktop/src-tauri` (Rust shell), `desktop/src/i18n/locales`. Companion to `docs/mobile-code-health-review.md` (same method: mechanical sweeps first, then file-by-file read).

Baseline at `e7e00a3`: vitest 229/229 green, `vite build` green. Every change in this pass must leave that true.

Method notes: unused-symbol counts come from ripgrep over `src` with tests and the defining file excluded; the i18n audit is a script that flattens both locale files and cross-checks every `t()` call site, `cipherSchema` label keys, and concatenated-key prefixes (`t("categories." + id)` style). Peer-review section at the end records what the reviewers found and what was accepted or withdrawn.

## 1. Dead code (delete)

| ID | Item | Evidence | Action |
|----|------|----------|--------|
| D1 | `components/ImportExportButton.jsx` (80 lines) | Zero references anywhere. Its logic lives on, hand-inlined, in `SettingsModal.doImport`/`doExport` (`vault.import`, `vault.export`) | Delete file |
| D2 | `lib/payload.js: buildSettingsPayload` | Only the definition + export. `SettingsModal` builds `settings.set` payloads inline (the other named consumer, `AutoLockButton`, is itself dead — D13) | Delete |
| D3 | `lib/helpers.js: typeLabel` + `TYPE_LABELS` | Only the definition. Cipher type labels render via `t("types.*")` / `t("categories.*")`. Test cleanup: `__tests__/helpers.test.js` exists purely to test `typeLabel` — delete the file with the function (peer review) | Delete both + the test file |
| D4 | `components/Primitives.jsx: FormGroup` | Only the definition; `Button`/`Input` are adopted by 7 components (keep those) | Delete FormGroup |
| D5 | `context/toastSignal.js: toastInfo` | Only the definition + export line. Test mocks import it (`__tests__/helpers/render.jsx`, `VaultSwitcher.test.jsx`, `SshKeyGenerator.test.jsx`) — update the mocks in the same change (peer review) | Delete + fix mocks |
| D6 | `lib/daemon.js: lockAllVaults` + `src-tauri/src/lib.rs: lock_all_vaults` command | JS wrapper: tests only. Rust command: registered in `invoke_handler` but nothing calls it; the blur path fires the daemon's `vaults.on_app_blur` route directly (lib.rs ~1060), which is the policy-aware behavior we actually want | Delete wrapper, command, registration, and the `lockAllVaults` describe-block in `__tests__/disableAutofill.test.js` (that test file also no longer matches its name's subject; renaming is optional). Reviewer caveat, accepted: the command is the only place that clears the frontend `SessionStore` token cache alongside a daemon lock-all — when the documented OS suspend/screen-lock hooks land, they must do that clearing explicitly |
| D7 | `context/VaultSwitcherContext.jsx: loading` signal | Created, exposed, never set. Always `false` | Delete signal + store entry |
| D8 | `components/Icon.jsx`: 7 unused icons | `IconDatabase`, `IconExclaim`, `IconFire`, `IconLink`, `IconPlay`, `IconShieldCheck`, `IconUser` — zero references | Delete the functions |
| D9 | `AddEditCipherForm.jsx: renderSchemaFields()` (~35 lines) | Defined, never called. The generic path is the inline `<For each={layoutRows()}>` renderer (which additionally supports `field.generator`); login and card are hand-rendered | Delete |
| D10 | `lib/conflictDevTriggers.jsx` duplicated comment | The "opt-in via localStorage" note appears twice back to back | Trim one |
| D11 | `lib/payload.js` stacked doc comments above `buildKind` | Two consecutive `/** … */` blocks for the same function (merge leftover) | Trim one |
| D12 | `lib/vaultTimeout.js` doubled doc sentences above `normalizeVaultTimeout` | Same rationale restated twice across two comment blocks | Merge into one |
| D13 | `components/AutoLockButton.jsx` (103 lines) — found in peer review, verified | Zero importers; nothing renders it (removed from the layout earlier). Its quick-unlock arm also uses `prompt()` (see former R2). `lib/vaultTimeout.js` header comment still names it as a consumer — fix the comment in the same change | Delete file |

Deliberately NOT dead (checked, keep): `ConsolePanel` (used by `ConflictResolutionPanel` + `RepromptModal`), `ConflictBanner` (mounted in `VaultView`), `ThemeToggleFloating` (all four auth screens), `Transition` (documented vendored shim for Solid 2.0), `conflictMocks.js`/`conflictDevTriggers.jsx` (dev-only, dynamically imported behind `import.meta.env.DEV`, kept out of prod bundles by design), `update_tray_icon` (real work on Linux/Windows), `selectSource`/`CATEGORY_TYPE_MAP`/`ERROR_PATTERNS` (used; the latter via the pattern table).

## 2. i18n

Parity is perfect: EN and ES both carry 586 keys, zero one-sided keys, zero missing keys referenced by literal `t()` calls.

The problem is ~52 dead keys and a set of hardcoded user-visible strings that never got keys. Audit caveat learned the hard way: the static audit must allowlist every `t("prefix." + x)` concatenation shape — it initially missed `providerLabel()`'s `t("sync." + map[key])` (caught in peer review).

### 2.1 Dead keys (defined, never referenced)

| Family | Keys | Why they died | Disposition |
|--------|------|---------------|-------------|
| `bridge_ext.*` (18) | activeVault, appRequired(+Desc), connect(+Desc), copied, copyPassword, copyTotp, copyUsername, fill, locked(+Desc), noMatches, notPaired(+Desc), search, versionSkew(+Desc) | Browser-extension UI strings that landed in the DESKTOP locale files. The extension has its own i18n; `BridgeTab` uses none of them | Delete all 18 from both locales |
| `sync.*` (14) | patTitle, patInstructions, patGenerateToken, patPlaceholder, patConnecting, pulling, pushing, selectRepo, connect, statusNotConnected, statusRemoteOnly, scopeNoteApi, errorRepoCreateFailed, advancedSectionHint | Leftovers from the pre-`providerConnect.js` SyncTab UI; today's SyncTab references none of them. NOT dead (peer-review correction): `providerGitHub/GitLab/Codeberg` resolve via `providerLabel()`'s `t("sync." + map[key])` in SetupScreen, SyncTab, and CloneFromProviderScreen — they stay | Delete the 14; keep the 3 provider names |
| `entry.*` (8) | add, addTag, addUri, removeUri, uris, uriPlaceholder, totpUri, sshKeyCopied | Keys were created for `AddEditCipherForm` but the form hardcodes the English strings instead (see 2.2) | Wire the ones whose UI exists (addUri, removeUri, uris, uriPlaceholder, totpUri), delete the rest (add, addTag, sshKeyCopied) |
| `vault.*` (7) | addEntry, familyVault, headerOptions, myVault, statusUnlocked, vaultsTitle, entryCount_plural | No static references. Caveat: `entryCount_plural` IS requested at runtime — `pickPlural` derives the `_plural` variant key dynamically when `count !== 1`, so static audits cannot see it. It stays | Delete the 6 static-dead keys; keep `entryCount_plural` (audit false positive) |
| `setup.*` (2) | submitting, syncFailed | No references | Delete |
| misc (5) | `create.languageLabel`, `generator.lengthLabel`, `generator.wordsLabel`, `autosync.pending`, `autosync.pending_plural` | No references (the form/model pickers hardcode or dropped the feature) | Delete |

Net: locales shrink from 586 to ~534 keys, then grow back a handful with the new keys from 2.2.
### 2.2 Hardcoded English that must be keyed

- `AddEditCipherForm`: "Length:", "Generate New", "URIs", "Add URI" (×2), match-strategy select options (Default/Domain/Host/Starts with/Exact/Regex/Never), "TOTP URI", "Cardholder Name", "Card Number", "Month", "Year", "Hide password"/"Show password", "Remove URI" (title), "Boolean toggle" (aria-label). Note the absurdity: `cipherSchema.card.fields` already carries i18n keys (`fields.cardholder`, `fields.cardNumber`, …) and the hand-written `renderCardFields` ignores them and hardcodes the English.
- `SshKeyGenerator`: "Fingerprint", "Public Key", "Private Key", "Show private key", "Default" badge.
- `CopyableField`: "Hide", "Show", "Copy to clipboard" (tooltips).
- `CipherDetail`: "Download" (title).

All new keys go in BOTH locales in the same change (repo rule).

## 3. DRY violations

| ID | Duplication | Fix |
|----|-------------|-----|
| R1 | Copy-then-flash-feedback state machine hand-rolled 7×: `CopyButton` (global), `SshKeyGenerator` local `CopyButton` (a second component of the same name!), `CipherDetail.CopyNotesButton` (a third — peer-review find), `CopyableField` inline, `GeneratorModal`, `RecoveryScreen`, `CipherDetail` attachments | One shared `CopyIconButton` (or a `rememberCopied()` signal helper) in `components/`; every site consumes it. The global `CopyButton` becomes it; the `SshKeyGenerator`-local and `CopyNotesButton` shadows are deleted outright |
| R2 | ~~Quick-Unlock enable flow duplicated, `AutoLockButton` uses `prompt()`~~ WITHDRAWN — moot | The whole `AutoLockButton` is dead (D13, found in peer review); deletion resolves the `prompt()` phishing-shape issue for free. Settings keeps the only Quick-Unlock flow (inline password input, the correct one) |
| R4 | `SettingsModal`: five tab buttons repeat the identical 9-line active/inactive class ternary | Local `TabButton` component in the file |
| R5 | `VaultView` hand-rolls two inline confirm dialogs (delete-tag, empty-trash) while `DeleteConfirmModal`/`ArchiveConfirmModal` exist as components | Extract one `ConfirmModal` primitive (title, body, confirmLabel, onConfirm, danger) and use it for all four |
| R6 | `VaultContext` CRUD: seven catch blocks with identical `toastError(sanitizeError(e, t))` + `return false` shape | Optional: tiny `guarded(fn, t)` wrapper. Acceptable to leave; note only |
| R7 | `AuthContext` (`VALID_AUTH_TRANSITIONS`) and `VaultContext` (`VALID_PANE_TRANSITIONS`) implement the same guard mechanism twice, comment says "Dev-only guard", but neither is DEV-gated: the tables and `console.warn` ship in production. Real table bug while here: `VALID_PANE_TRANSITIONS` lacks `detail → add`, so clicking + New while viewing an entry warns on a perfectly legal transition (`VaultView.jsx:113`) | Two fixes: (1) add `"add"` to `detail`'s allowed list; (2) extract one `guardTransition(...)` in `lib/` and DEV-gate ONLY the `console.warn` — never the state write itself (review precision point: a careless gate that short-circuits `setStatus` would break real transitions in prod) |
| R8 | `slug.js`: `suggestSlug` and `cleanSlug` duplicate the 15-line normalize loop | Extract `slugChars(input)` |
| R9 | `payload.js`: `buildAddPayload`/`buildUpdatePayload` identical except `id` | `buildUpdatePayload(id, c) = { id, ...buildAddPayload(c) }` |
| R10 | `CopyButton` default tooltip key is `recovery.copyToClipboard` for every copy surface in the app | Rename to `common.copy` (mechanical, both locales) |
| R11 | `providerLabel()` triplicated: `SetupScreen.jsx:21`, `SyncTab.jsx:~442`, `CloneFromProviderScreen.jsx:~155` — same `{github,gitlab,codeberg} → i18n key` map and same `t("sync." + …)` lookup (peer review) | Extract to a small `lib/providers.js` helper `providerLabel(t, key)`; all three import it |
| R12 | `LoginScreen` and `SwitchUnlockModal` overlap on per-vault Quick-Unlock status probing + unlock handling (peer review). Partially duplicated — the surfaces differ (full unlock screen vs in-place switch modal) | Verify the exact overlap during implementation; extract only if a clean shared hook (`useVaultQuickUnlock(slug)`) falls out. Defer if it forces a shape |

Accepted duplication (documented, do not churn): `MUTATION_ACTIONS` in `daemon.js` hand-mirrors the daemon's `COVER_MUTATION_ACTIONS` (cross-language, comment points at the source of truth); generated wordlists duplicated per platform (generated from canonical core sources by script); `providerConnect.js` already extracted what SyncTab and CloneFromProviderScreen used to duplicate.

## 4. KISS / YAGNI

| ID | Item | Verdict |
|----|------|---------|
| K1 | `AuthContext.createVault` reads the confirm field via `document.getElementById("create-confirm")` — DOM spelunking inside the context layer | Move the length/mismatch validation into `CreateVaultScreen` (which owns the inputs); the context keeps password signals only |
| K2 | `AddEditCipherForm` has three field-rendering paths (dead `renderSchemaFields`, generic inline `For`, hand-written login + card). Full schema unification would be a large refactor | This pass: delete the dead one (D9), keep two paths. Unification deferred; it interacts with the card layout and generator plumbing |
| K3 | `VaultContext.updateCipher` does `refreshCiphers()` then a second `vault.get` round-trip to fetch the updated cipher for the detail pane | `list_full` already returned the fresh cipher; find it in the refreshed list and skip the second IPC. Low risk, do it |
| K4 | `unlock()` clears the login input via a `loginPasswordRef` ref handed to the context (`setLoginPasswordRef`) | Layering smell; harmless. Clearing can move to `LoginScreen`'s own success path. Optional; not required this pass |
| K5 | Conflict mock plumbing (`__mock` flag, `headIsMock`) in the prod context and panel | Tiny and load-bearing for the dev trigger's no-op resolver. DEV-gate the panel's `headIsMock` branch so prod DCEs it; keep the context stamp |
| K6 | `onSettled` used everywhere for mount effects (Solid 2.0 idiom, apparently renamed `onMount`) | Consistent across the codebase; leave |
| K7 | `SyncTab` is 976 lines with a 16-setter manual reset on vault switch | Works, recently hardened (session-scope reset, slug races). Decomposition is a real project, not cleanup. Deferred |
| K8 | `CipherDetail` receives `setActivePane`/`selectedCategory` as props while `useVault()` is already in scope inside it | Prop/context mixing. Mechanical simplification, optional, do only if touched anyway |

## 5. Rust shell (`src-tauri`)

- `lock_all_vaults` command: dead (D6). The blur path's `vaults.on_app_blur` + daemon-side policy is the live mechanism.
- `update_tray_icon`: real (swaps tray PNG per theme on Linux/Windows); the `themeSignal.js` fire-and-forget call is correct.
- Blur-lock debounce (`BlurLockState`, `BLUR_LOCK_DELAY`): coherent, documented; OS suspend/screen-lock hooks are explicitly a documented follow-up, not dead code.
- Desktop prefs (tray-only): load/save/apply split is clean; best-effort persistence matches the theme/locale pattern.
- Daemon sidecar lifecycle (pgrep exact-match kill, socket cleanup, stdout piping): has hard-won comments; leave alone.
- No dead Rust found beyond D6.

## 6. Suggested execution order

1. **Pure deletions** (D1–D13, dead i18n keys with no UI to wire: `bridge_ext.*`, 14 `sync.*` leftovers, `setup.*`, misc; plus the test-file/mock cleanup from D3/D5/D6). Run vitest + build.
2. **i18n wiring** (2.2 strings get keys in EN+ES; adopt the five `entry.*` keys; R10 rename). Run vitest + build.
3. **DRY extractions** (R1 CopyIconButton, R4 TabButton, R5 ConfirmModal, R7 DEV-gated guard + pane-table fix, R8 slugChars, R9 payload merge, R11 providerLabel). Run vitest + build after each extraction; `SettingsModal.test.jsx`, `GeneratorModal.test.jsx`, `SshKeyGenerator.test.jsx` cover the riskiest ones.
4. **KISS fixes** (K1, K3; K5 DEV-gate). Final vitest + build.
5. Manual smoke via `just desktop-debug`: unlock, quick-unlock from Settings, auto-lock popover, copy feedback on a TOTP and a password, conflict dev trigger still renders, theme toggle from Settings and login screen.

Single commit at the end, Conventional Commits, matching the mobile pass format (`refactor(desktop): …`), after peer review of this document.

## Peer review

### Peer review A

Verdict: AGREE-WITH-CHANGES overall. Three findings accepted after verification on this machine:

1. **`AutoLockButton.jsx` is entirely dead** (zero importers; removed from the layout in an earlier commit). My sweep missed it — the component-usage pass never included it in the candidate list. This converts R2/R3 from refactors into plain deletions (D13) and resolves the `prompt()` phishing-shape problem for free.
2. **`sync.providerGitHub/GitLab/Codeberg` are live** — `providerLabel()` resolves them via `t("sync." + map[key])` in three files; the audit's concatenation allowlist missed that shape. Dead-key count corrected 55 → 52; 17 `sync.*` dead keys corrected to 14. Also surfaced `providerLabel()` triplication as new R11.
3. **Test cleanup must ride with the deletions**: `toastInfo` is imported by three test mocks, `typeLabel` is the sole subject of `helpers.test.js`, and the `lockAllVaults` block lives in `disableAutofill.test.js`. Folded into D3/D5/D6.

Caveat accepted, not acted on: D6's command is the only place that clears the frontend `SessionStore` with a lock-all; noted in D6 + section 5 as a requirement for the future OS-suspend hooks. `VALID_PANE_TRANSITIONS` missing `detail → add` was the reviewer's catch too — verified against `VaultView.jsx:113` and folded into R7. R12 (LoginScreen/SwitchUnlockModal quick-unlock overlap) added as a verify-during-implementation item.

### Peer review B

Verdict: AGREE with sections 2-5; AGREE-WITH-CHANGES on section 1. Independently re-verified D3, D4, D6, D7, D8, D9 as genuinely dead with no dynamic references, and confirmed `vaults.on_app_blur` (lib.rs:1075) as the live blur-lock path, i.e. D6 is safe to delete. Two accepted additions:

1. **Execution-order gap**: deleting D3 without `helpers.test.js` breaks vitest — the doc's own gate. Folded into D3.
2. **R7 phrasing risk**: "DEV-gate the guard" is ambiguous — the gate must cover only the `console.warn`, never the `setStatus`/`setPane` write, or prod transitions would short-circuit. Wording tightened in R7.

Confirmed correct (against my earlier caution): R2's `prompt()` finding is real and in code — moot only because D13 supersedes it. No false positives found in the reviewer's independent spot-checks; `IconLink` vs `IconLinkSimple` near-name trap noted as correctly handled.
