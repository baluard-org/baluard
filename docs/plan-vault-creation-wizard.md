# Vault Creation Wizard

> Status: **Implemented**
> Last updated: 2026-06-10
> Reviewed by: peer review (session `wizard-review`)

## Goal

Multi-step vault creation wizard for both CLI and desktop. Collects master password, recovery phrase acknowledgment, user profile, and preferences in a guided flow. CLI-first parity: every field works from both surfaces.

## Design Decisions

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Where to write profile/prefs | **Split path**: CLI chains writes in `VaultCreator` builder; Desktop uses `settings.set` + `profile.update` IPC post-creation | Desktop collects profile AFTER vault.create (step 3), so payload cannot include it. CLI collects everything before `execute()` |
| 2 | CLI interaction model | Hybrid: flags + interactive fallback | Scriptable with flags, friendly when interactive. Skip prompts when no TTY |
| 3 | Avatar in wizard | Skip, defer to Settings | Rarely urgent on first run. Users find it naturally in Settings |
| 4 | Desktop step count | 3 steps | Lean first-run. Profile + preferences combined |
| 5 | Component architecture | Add `SetupScreen.jsx`, keep status-switched pattern | Follows existing convention. Minimal refactor |
| 6 | Crash between creation and profile write | Accept gap | Profile is cosmetic. Missing = defaults. User sets it in Settings later |
| 7 | Non-interactive CLI | Skip prompts, use flags + defaults | `BALUARD_PASSWORD` + flags, no prompts. Error if password missing without TTY |
| 8 | Recovery phrase confirmation (CLI) | Print to stdout, no confirmation | CLI users are responsible. Piped/CI would break with confirmation prompt |
| 9 | Language | Auto-detect OS locale, show selector on Step 1 | Users experience the wizard in their language immediately |
| 10 | Theme values | `light`, `dark`, `system` (default) | `system` matches OS preference. Validated as `ThemeMode` enum |
| 11 | Language persistence | Plaintext `meta/locale` file | Encrypted settings unreadable before unlock. Login screen needs locale. Plaintext file is safe (not secret data) |
| 12 | Device name | Default `"this-device"` (unchanged) | Device name is cosmetic in single-device flow. Renaming via `devices rename` if needed |

## Wizard Flow

```
CLI (baluard init)                          Desktop
──────────────────────────────────          ──────────────────────────────────
Step 1: Password + Language                 Step 1: Language selector
  password (prompt/flag/env)                  (auto-detected, editable)
  --lang (auto-detected/fallback en)          Password + confirm
  → all data collected                        → vault.create IPC (password only)
Step 2: Recovery phrase                     Step 2: Recovery phrase display
  printed to stdout                           + checkbox confirmation
Step 3: Profile + Preferences               Step 3: Profile + Preferences
  --name (prompt/flag)                        Display name, subtitle (optional)
  --subtitle (prompt/flag)                    Theme: light/dark/system
  --theme (prompt/flag, default: system)      Auto-lock timeout
  --auto-lock (prompt/flag, default: 15)      → settings.set + profile.update IPC
  → VaultCreator::execute() with profile      → startVaultPrefetch()
    + prefs chained                            → transition to "unlocked"
```

**Key difference**: CLI has all data before calling `VaultCreator`. Desktop creates the vault first, then applies profile/prefs via separate IPC calls.

## CLI Flags

```
baluard init [OPTIONS]

Options:
  --profile <kdf>        KDF profile: mobile-low, desktop-std, desktop-high [default: desktop-std]
  --name <string>        Display name (shown in sidebar)
  --subtitle <string>    Subtitle/role (shown under name)
  --theme <value>        Theme: light, dark, system [default: system]
  --lang <code>          Language: en, es [default: auto-detect, fallback en]
  --auto-lock <minutes>  Auto-lock timeout in minutes [default: 15]
  --password <string>    Master password (warning: visible in process list)
```

Environment variable `BALUARD_PASSWORD` bypasses all password prompts.

Non-interactive behavior (piped stdin / CI): uses flag values or defaults. No prompts. Prints recovery phrase to stdout. **Error with clear message if no password available** (no `BALUARD_PASSWORD`, no `--password`, no TTY).

## OS Language Detection

| Surface | Method | Fallback |
|---------|--------|----------|
| CLI | `$LANGUAGE` > `$LC_ALL` > `$LC_MESSAGES` > `$LANG` (parse `es_CL.UTF-8` → `es`) | `en` |
| Desktop | `navigator.language` (parse `es-CL` → `es`) | `en` |

Mapping: match first 2 characters against available locales (`en`, `es`). No match → `en`.

`$LANGUAGE` is checked first (GNU gettext priority order). It may contain a colon-separated list (`LANGUAGE=es_CL:es:en`) - use first matching entry.

## Language Persistence

Language is the only preference that must be readable before vault unlock (login screen). Storage:

| Location | Format | Written by |
|----------|--------|------------|
| `meta/locale` | Plaintext file, single line (e.g. `es`) | CLI: VaultCreator. Desktop: SetupScreen submit |
| `VaultSettings.lang` | Encrypted in `settings.enc` | Not stored here. Redundant and inaccessible before unlock |

On every launch, i18n context reads: `meta/locale` file → OS detection fallback. On vault creation wizard completion, `meta/locale` is written.

## Theme Validation

Theme is currently `Option<String>` in `VaultSettings` with no validation. Add a `ThemeMode` enum:

```rust
// crates/baluard-core/src/types.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    Light,
    Dark,
    System,
}
```

Change `VaultSettings.theme` from `Option<String>` to `Option<ThemeMode>`. Serde rejects unknown variants at deserialization. Add migration for existing `"light"`/`"dark"`/`"system"` string values.

## Implementation Phases

### Phase 0: Schema Changes (prerequisite)

Before any wizard work:

1. **Add `lang` to `VaultSettings`** - `manifest.rs`: add `pub lang: Option<String>` with `skip_serializing_if`
2. **Add `ThemeMode` enum** - `types.rs`: new enum, `serde(rename_all = "lowercase")`
3. **Change `VaultSettings.theme` to `Option<ThemeMode>`** - `manifest.rs`: type change, serde handles backward compat
4. **Add `meta/locale` write/read** - `VaultHandle`: `save_locale(lang: &str)` and `load_locale() -> Option<String>` methods. Plaintext file, no encryption needed.
5. **Update `settings_set` daemon handler** - `state.rs`: accept `lang` field, pass through
6. **Migration**: existing string theme values (`"light"`, `"dark"`, `"system"`) deserialized via `rename_all = "lowercase"` - no migration needed if serde handles it

**Files changed**: `crates/baluard-core/src/types.rs`, `crates/baluard-core/src/vault/manifest.rs`, `crates/baluard-core/src/vault/handle.rs`, `crates/baluard-daemon/src/state.rs`

### Phase 1: Core - VaultCreator Builder Extension (CLI path only)

Extend `VaultCreator` in `crates/baluard-core/src/vault/creation.rs`:

- Add `.profile(display_name: Option<String>, subtitle: Option<String>)` builder method
- Add `.preferences(theme: Option<ThemeMode>, lang: Option<String>, auto_lock_minutes: Option<u32>)` builder method
- Store as fields on `VaultCreator` struct (default `None`)
- In `execute()`, after vault files are written and before returning:
  - If profile fields set: call `handle.save_profile()` with `UserProfile`
  - If preference fields set: call `handle.save_settings()` with `VaultSettings`
  - If lang set: call `handle.save_locale(&lang)`
- Add unit test: create vault with profile + prefs, reopen, verify round-trip
- Add unit test: create vault, verify `meta/locale` file exists and is correct

**Files changed**: `crates/baluard-core/src/vault/creation.rs`

### Phase 2: CLI - Hybrid Wizard

Extend `init` command in `crates/baluard-cli/`:

- Add flags to `Init` variant in `main.rs`: `--name`, `--subtitle`, `--theme`, `--lang`, `--auto-lock`
- Add `detect_locale() -> String` function (parse `$LANGUAGE` > `$LC_ALL` > `$LC_MESSAGES` > `$LANG`)
- Add `is_tty() -> bool` helper using `atty` or `std::io::stdin().is_terminal()`
- Update `handle_init()`:
  - Pass profile/preferences to `VaultCreator` builder
  - For each missing flag with TTY: prompt interactively (skip optional fields if user presses Enter)
  - For missing flags without TTY: use defaults
  - **Error if no password** and no TTY: `eprintln!("error: no password available. Set BALUARD_PASSWORD or run interactively.")` + exit 1
- **Enforce 8-char minimum** (currently warning-only). Match desktop behavior: reject passwords < 8 chars.

**Files changed**: `crates/baluard-cli/src/main.rs`, `crates/baluard-cli/src/commands/mod.rs`

### Phase 3: Desktop - 3-Step Wizard

#### Step 1: `CreateVaultScreen.jsx` (modify)
- Add language selector dropdown at top (auto-detected from `navigator.language`, editable)
- Language change applies immediately to wizard UI via i18n context
- **Verify i18n reactivity**: ensure `useI18n()` uses a reactive signal for locale. If locale is static (module-level), refactor to signal-based locale switching so `t()` calls re-render
- Keep existing password + confirm form
- **Enforce 8-char minimum** with inline validation message (already done in AuthContext)

#### Step 2: `RecoveryScreen.jsx` (modify)
- **Change "Continue" button handler**: transition to `"setup"` instead of `"unlocked"`
- **Zero recovery phrase signal**: call `setRecoveryPhrase("")` in the transition handler before moving to setup
- Add transition `recovery → setup` to `VALID_AUTH_TRANSITIONS`

#### Step 3: `SetupScreen.jsx` (new)
- Display name input (optional)
- Subtitle input (optional)
- Theme selector: 3 options (Light / Dark / System, default System)
- Auto-lock input: number field with default 15
- Submit button: "Start using Baluard"
- **On submit**:
  1. Call `daemon("settings.set", ...)` with theme + auto_lock + lang
  2. Call `daemon("profile.update", ...)` with display_name + subtitle (if set)
  3. Write `meta/locale` via dedicated daemon route or Tauri command
  4. Call `startVaultPrefetch()` (currently only called in `unlock()` path)
  5. Transition to `"unlocked"`
- FocusTrap applied

#### State Machine Updates (`AuthContext.jsx`)

Updated `VALID_AUTH_TRANSITIONS`:
```js
const VALID_AUTH_TRANSITIONS = {
  locked:    ["unlocking", "init"],
  unlocking: ["unlocked", "locked"],
  unlocked:  ["locked"],
  init:      ["creating", "locked"],
  creating:  ["recovery", "init"],
  recovery:  ["setup", "init", "locked"],  // added "setup"
  setup:     ["unlocked", "locked"],        // NEW
};
```

#### App.jsx Restructure

Replace nested `<Show>` fallback chain with explicit status matching:
```jsx
<Show when={auth.status() === "init" || auth.status() === "creating"}>
  <CreateVaultScreen />
</Show>
<Show when={auth.status() === "recovery"}>
  <RecoveryScreen />
</Show>
<Show when={auth.status() === "setup"}>
  <SetupScreen />
</Show>
```

#### i18n
- Add wizard keys to `en.json` AND `es.json` simultaneously (no deferred translations):
  - `setup.title`, `setup.profileSection`, `setup.displayNamePlaceholder`, `setup.subtitlePlaceholder`
  - `setup.prefsSection`, `setup.themeLight`, `setup.themeDark`, `setup.themeSystem`
  - `setup.autoLockLabel`, `setup.autoLockMinutes`, `setup.submit`
  - `create.languageLabel`, `create.languageEn`, `create.languageEs`

**Files changed**: `desktop/src/components/CreateVaultScreen.jsx`, `desktop/src/components/RecoveryScreen.jsx`, `desktop/src/components/SetupScreen.jsx` (new), `desktop/src/context/AuthContext.jsx`, `desktop/src/App.jsx`, `desktop/src/i18n/index.jsx` (reactivity fix), `desktop/src/i18n/locales/en.json`, `desktop/src/i18n/locales/es.json`

### Phase 4: Daemon - Post-Creation Profile Routes

**No changes to `vault.create` payload.** Profile and preferences are applied post-creation via existing routes:

- `settings.set` - already accepts `theme`, `auto_lock_minutes`. Add `lang` field support.
- `profile.update` - already accepts `display_name`, `subtitle`.
- **New**: `locale.save` route - writes plaintext `meta/locale` file (needed because `settings.set` writes encrypted data, unreadable before unlock)

The `vault.create` handler and `create_vault()` in `state.rs` remain **unchanged**. No new fields in the creation payload.

**Files changed**: `crates/baluard-daemon/src/handler.rs` (add `locale.save` route)

## Defaults Summary

| Field | Default | Notes |
|-------|---------|-------|
| Master password | Required | Min 8 chars, **enforced** (hard error, not warning) |
| KDF profile | `desktop-std` | Existing default |
| Display name | `None` | Sidebar falls back to "Baluard" |
| Subtitle | `None` | Hidden when unset |
| Theme | `system` | Follows OS preference. `ThemeMode` enum |
| Language | Auto-detect, fallback `en` | Persisted in plaintext `meta/locale` |
| Auto-lock | `15` minutes | `None` = disabled |

## Test Plan

| Test | Surface | What it verifies |
|------|---------|------------------|
| Unit: profile round-trip | Core | Create vault with profile, reopen, verify fields |
| Unit: preferences round-trip | Core | Create vault with prefs, reopen, verify theme/lang/auto-lock |
| Unit: locale file I/O | Core | `save_locale("es")` then `load_locale()` returns `"es"` |
| Unit: locale detection | CLI | `$LANGUAGE=es_CL:es:en` → `es`, `$LANG=en_US.UTF-8` → `en`, all unset → `en` |
| Unit: theme validation | Core | `ThemeMode` serde: `light`/`dark`/`system` accepted, `invalid` rejected |
| Unit: theme backward compat | Core | Existing `"system"` string in settings.enc deserializes to `ThemeMode::System` |
| Integration: full CLI wizard | CLI | `baluard init` with all flags, verify vault + profile + prefs + locale file |
| Integration: non-interactive | CLI | Piped with `BALUARD_PASSWORD`, no prompts, all defaults |
| Integration: no password no TTY | CLI | `BALUARD_PASSWORD` unset, stdin piped → error message + exit 1 |
| Integration: password too short | CLI | 5-char password → error (not warning) |
| Component: language selector | Desktop | Switch language, verify UI updates immediately (reactivity) |
| Component: theme selector | Desktop | Select dark/light/system, verify applied after creation |
| Component: setup → unlocked | Desktop | Submit SetupScreen triggers settings.set + profile.update + prefetch |
| E2E: full wizard flow | Desktop | Complete 3-step wizard, close app, reopen, verify login screen uses saved locale |
| E2E: locale persistence | Desktop | Set language to `es` in wizard, close, reopen → login screen in Spanish |

## Peer Review Log

| Date | Reviewer | Session | Findings |
|------|----------|---------|----------|
| 2026-06-10 | peer | `wizard-review` | 13 issues: 3 breaking (step 3 data in step 1 payload, `lang` field missing, RecoveryScreen unchanged), 4 high (state machine gaps, prefetch missing, device_name hardcoded, phrase not zeroed), 6 medium/low. All addressed in this revision. |
