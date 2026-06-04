# Frontend Architecture Refactor Candidates

**Date:** 2026-06-04
**Scope:** `desktop/src/` (3,466 lines across 18 SolidJS components)
**Trigger:** SolidJS usage analysis. Reducing complexity without changing framework.

---

## Context

The desktop frontend is a SolidJS + Tailwind v4 app running inside Tauri v2.
All IPC goes through `daemon(action, payload)` which calls `invoke("daemon_request")` 
on the Rust side, hitting the daemon over a Unix domain socket. Request/response. No SSE, no streaming.

The app has 18 components, 1 context provider (30+ signals), 1 actions hook (243 lines), 
and 2 utility libraries (payload builder, helpers). Total: 3,466 lines.

**Current dependency graph:**

```
main.jsx
  └─ I18nProvider
       └─ App
            └─ AppProvider (30+ signals in one context)
                 └─ AppInner
                      ├─ LoginScreen
                      ├─ CreateVaultScreen
                      ├─ RecoveryScreen
                      └─ VaultView
                           ├─ FolderTree
                           ├─ CipherRow
                           ├─ CipherDetail (499 lines)
                           ├─ AddEditCipherForm (798 lines)
                           ├─ DeleteConfirmModal
                           ├─ GeneratorModal
                           ├─ RepromptModal
                           └─ SettingsModal
                                └─ DeviceFleetPanel
```

Every component calls `useApp()` to access the shared store.
`useActions()` is a free function hook that reads/writes the same store.

---

## Candidate 1: The God Store

**Cluster:** `context/AppContext.jsx` (102 lines) + `hooks/useActions.js` (243 lines)

### Problem

30+ signals in a single provider. No grouping, no boundaries.
Every component destructures from the same `useApp()` call.

The store mixes:
- **Auth lifecycle:** status (locked/unlocked/init/creating/recovery), error, vaultInfo
- **Cipher data:** ciphers, trashCiphers, archivedCiphers, deviceFleet, selfDeviceId
- **Navigation:** activePane (welcome/detail/add/edit), selectedCategory, selectedFolder
- **Form buffer:** newCipher (60+ field flat object), createPassword, recoveryPhrase
- **UI toggles:** showDeleteConfirm, showReprompt, showGenerator, showSettingsModal
- **User prefs:** theme
- **View state:** viewCipher, searchQuery, folders, repromptCallback, revokeWarning

`useActions` (243 lines) accesses 15+ signals and mutates them freely.
It handles screen transitions (`setActivePane("welcome")`), data fetching 
(`refreshCiphers`), error handling, and form validation in a single hook.

### Why It Matters

- Reading any component requires understanding which of the 30 signals it uses
- `useActions` is untestable without mocking the entire AppContext
- `newCipher` signal is a 60+ field flat object. Every keystroke on any field 
  calls `setNewCipher({ ...newCipher(), field: value })` which spreads the entire object
- Adding a new feature requires adding signals to the god store, expanding the 
  destructure list in every component that touches it

### Coupling Details

**Dependency category:** Functional cohesion violation. Concepts that change for 
different reasons (auth lifecycle vs form editing vs view filtering vs user prefs) 
are jammed into one reactive namespace.

**Shared types:** The `newCipher` flat buffer format is an implicit contract between 
AppContext, AddEditCipherForm, CipherDetail.startEdit, and payload.js. No type 
definition exists anywhere.

**Call patterns:** Every component does:
```js
const { signal1, signal2, setSignal3, ... } = useApp();
```
Some components destructure 12+ signals.

### Test Impact

- `useActions`: Zero tests. Untestable without full context mock.
- `payload.js`: Has tests. Works because it's pure functions.
- The barrier to testing any component is "mock the entire 30-signal store".

### Proposed Direction

Split into focused stores with clear ownership:

| Store | Signals | Owner |
|---|---|---|
| AuthStore | status, error, vaultInfo, biometricAvailable | App.jsx, LoginScreen |
| CipherStore | ciphers, trashCiphers, archivedCiphers, folders, deviceFleet | useActions, VaultView |
| NavigationStore | activePane, selectedCategory, selectedFolder, searchQuery | VaultView |
| FormStore | newCipher + typed accessors | AddEditCipherForm, CipherDetail |
| UIStore | showDeleteConfirm, showReprompt, showGenerator, showSettingsModal, theme | Modals |

This enables testing each store in isolation. Actions become methods on their 
owning store rather than a monolithic hook.

---

## Candidate 2: The Mega-Form

**Cluster:** `components/AddEditCipherForm.jsx` (798 lines) + `lib/payload.js` + 
`CipherDetail.jsx` startEdit() (~100 lines)

### Problem

8 cipher types with ~10 fields each, all rendered by a single 798-line component.
The form writes into a flat `newCipher` signal with 60+ keys. Every cipher type 
has its own `<Show when={cipherType() === "X"}>` block with inline form fields.

The mapping between this flat buffer and the structured CipherKind format happens 
in three places:

1. **Form → payload:** `buildKind(c)` in payload.js maps flat fields to structured 
   `{ type: "login", data: { username, password, uris, ... } }`
2. **Structured → flat:** CipherDetail.startEdit() does the inverse: reads the 
   structured cipher response and maps it to the flat buffer format (~100 lines)
3. **Form display:** AddEditCipherForm reads from the flat buffer to populate inputs

These three must agree on exact field names. Change one, break three files.

### Why It Matters

- 798 lines in a single component. The largest file in the frontend.
- `onInput={e => setNewCipher({ ...newCipher(), field: e.target.value })}` repeated ~80 times
- No type safety on the flat buffer. A typo in a field name silently creates a new key
- Adding a new cipher type requires changes in 3 files with no compile-time guarantees
- The URIs and custom fields sub-lists use local refs + signal sync pattern (mutation 
  outside reactive tracking, then force signal update). This is fragile.

### Coupling Details

**Dependency category:** Temporal/content coupling. The form, the payload builder, 
and CipherDetail.startEdit must all agree on the exact field names of the flat buffer.

**Implicit contract (undocumented):**

```
Login:      name, username, password, uris[], totp_uri, notes
Card:       name, cardholder_name, cardNumber, cardBrand, expMonth, expYear, cvv, notes
Identity:   name, idTitle, firstName, middleName, lastName, username, company, email, 
            phone, address1-3, city, state, postalCode, country, ssn, passportNumber, 
            licenseNumber, notes
SSH Key:    name, publicKey, privateKey, fingerprint, notes
Bank:       name, bankName, nameOnAccount, accountType, accountNumber, routingNumber, 
            branchNumber, bankPin, swiftCode, iban, bankPhone, notes
Driver Lic: name, dlFirstName, dlMiddleName, dlLastName, dlDob, dlNumber, dlCountry, 
            dlState, dlIssueDate, dlExpDate, dlAuthority, dlClass, notes
Passport:   name, ppSurname, ppGivenName, ppDob, ppSex, ppBirthPlace, ppNationality, 
            ppCountry, ppNumber, ppType, ppNationalId, ppAuthority, ppIssueDate, ppExpDate, notes
SecureNote: name, notes
```

**Shared by:** AddEditCipherForm (renders), CipherDetail.startEdit (populates), 
payload.js buildKind (serializes), payload.js buildAddPayload/buildUpdatePayload (wraps)

### Test Impact

- `payload.js`: Has tests for buildKind, buildAddPayload, etc.
- CipherDetail.startEdit mapping: Zero tests. 100+ lines of field assignment.
- The form component itself: Zero tests.
- The flat buffer format: No schema, no validation, no tests.

### Proposed Direction

Introduce a typed cipher form model that encapsulates the mapping:

```
CipherForm
  ├─ fromCipher(cipherResponse) → CipherForm   (replaces startEdit)
  ├─ toPayload() → { name, kind, ... }          (replaces buildKind + buildAddPayload)
  ├─ updateField(path, value)                    (replaces setNewCipher spread)
  └─ validate() → errors[]                       (currently inline)
```

Each cipher type defines its own field schema. The mapping lives in one place.
The form component renders from the schema. Adding a new cipher type becomes 
"add a schema entry" instead of "edit 3 files with 100+ lines each."

---

## Candidate 3: Inline SVG Icon Sprawl

**Cluster:** VaultView.jsx (categories array: 12 inline SVGs), 
AddEditCipherForm.jsx (add menu: 8 inline SVGs), every other component

### Problem

Every component that needs an icon duplicates the full SVG markup inline.
The categories array in VaultView is 40 lines of JSX, 90% of which is SVG path data.
The add menu in VaultView duplicates most of the same icons.

Rough count: ~200 lines of inline SVG across the codebase.

### Why It Matters

- Reading VaultView, the categories array is 60% SVG markup by line count
- The actual logic (category name, onClick handler) is buried in SVG noise
- Changing an icon requires finding and replacing it in multiple files
- No visual consistency guarantee: each inline copy is independent

### Coupling Details

**Dependency category:** Content duplication. Same visual element, no shared definition.

**Duplicated icons:** Lock, key, shield, card, identity, note, folder, trash, 
settings gear, search magnifier, plus, chevron. Each appears 2-5 times.

### Test Impact

No functional impact. Pure readability and maintainability issue.

### Proposed Direction

Create `components/Icon.jsx` with named icon components:

```jsx
<Icon name="lock" class="w-4 h-4" />
<Icon name="key" class="w-4 h-4" />
```

One source of truth per icon. Categories array goes from 40 lines to 12.
Add menu from 40 lines to 10.

Low priority but high readability win.

---

## Candidate 4: The Filter Pipeline

**Cluster:** VaultView.jsx lines 81-140 (filteredCiphers computed), 
AppContext signals: selectedCategory, selectedFolder, folders, searchQuery, 
ciphers, trashCiphers, archivedCiphers

### Problem

60 lines of business logic embedded directly in a view component:

1. **Source selection:** Trash → trashCiphers, Archive → archivedCiphers, else → ciphers
2. **Category filtering:** Chain of `if/else if` comparing hardcoded strings against `cipher.type`
3. **Folder filtering:** BFS descent through folder tree to collect descendant IDs, then filter
4. **Text search:** Filter against name, username, URIs, notes with `.toLowerCase().includes()`

This is core data-shaping logic. It's untested and untestable inside VaultView.

### Why It Matters

- Category matching uses hardcoded string comparisons. The mapping between UI category 
  name ("SSH key") and cipher type string ("sshKey") is scattered across if/else chain
- Folder descent (BFS) is non-trivial logic that should be testable
- Adding a new cipher type requires finding and updating this if/else chain
- Search only matches 4 fields. Adding search scope (e.g., custom fields) requires 
  editing inline filter logic in a view component

### Coupling Details

**Dependency category:** Procedural coupling. The filter reads 7 signals and produces 
a derived list. It cannot be tested or reused outside VaultView.

**The if/else chain:**

```js
if (cat === "Favorites") list = list.filter(c => c.favorite || c._meta?.favorite);
else if (cat === "Login") list = list.filter(c => (c.type || c._meta?.type) === "login");
else if (cat === "Card") list = list.filter(c => (c.type || c._meta?.type) === "card");
// ... 8 more branches
```

This mapping also exists in CipherRow.jsx (for icon/type display) and 
CipherDetail.jsx (for type label display). Three places, same mapping.

### Test Impact

Zero tests for the filter logic. This is the core data-shaping function in the app.

### Proposed Direction

Extract to `lib/filters.js` as pure functions:

```
filterByCategory(ciphers, category) → ciphers
filterByFolder(ciphers, folders, folderId) → ciphers  // includes descendants
searchCiphers(ciphers, query) → ciphers
```

Then in VaultView: `filteredCiphers = searchCiphers(filterByFolder(filterByCategory(source, cat), ...), query)`

Each function testable in isolation. Category-to-type mapping becomes a single 
lookup table shared with CipherRow and CipherDetail.

---

## Candidate 5: Screen State Machine

**Cluster:** App.jsx (status: locked/unlocked/init/creating/recovery), 
VaultView.jsx (activePane: welcome/detail/add/edit), 
AppContext (status + activePane signals), 
useActions (transitions scattered across 15+ function calls)

### Problem

Two parallel state machines with no formal definition:

**Machine 1 - App status (top-level screens):**
```
locked → unlocking → unlocked
init → creating → recovery
locked → init (vault.open fails)
```

**Machine 2 - VaultView activePane (sub-views):**
```
welcome → detail (cipher selected)
welcome → add (new cipher)
detail → edit (edit button)
edit → detail (save)
add/edit → welcome (cancel/save)
```

They interact: locking resets activePane to "welcome", clears viewCipher.
The transitions are scattered across useActions, CipherDetail, AddEditCipherForm, VaultView.

### Why It Matters

- Reading `lock()` in useActions, it sets 6 different signals in sequence. Miss one, 
  the UI is in an inconsistent state
- `setRevokeWarning(null)` was added to `lock()` as a bugfix (state not cleared)
- There's no way to verify that every transition leaves the system in a valid state
- Adding a new screen/pane requires knowing all the places that reset state on transitions

### Coupling Details

**Dependency category:** Temporal coupling. Screen transitions must happen in the 
right order (lock → reset pane → clear cipher → clear warning) but there's no 
enforced ordering.

**Transition sites:**

| Action | Where | Signals mutated |
|---|---|---|
| lock | useActions.lock() | status, ciphers, vaultInfo, viewCipher, activePane, showDeleteConfirm, revokeWarning |
| unlock | useActions.unlock() | status, ciphers, vaultInfo |
| create vault | useActions.createVault() | status, recoveryPhrase, error |
| select cipher | useActions.getCipher() | viewCipher, activePane |
| start add | VaultView.startAdd() | newCipher, activePane, showAddMenu |
| start edit | CipherDetail.startEdit() | newCipher, activePane |
| save | useActions.addCipher/updateCipher() | newCipher, activePane, ciphers, viewCipher |
| delete | useActions.deleteCipher() | viewCipher, activePane, showDeleteConfirm, ciphers |

8 different transition sites. Each knows which signals to mutate. No shared definition 
of valid states or valid transitions.

### Test Impact

No state machine tests. Transition correctness verified only by manual testing.
State inconsistency bugs have already occurred (the revokeWarning bug).

### Proposed Direction

Define explicit state machines with transition functions:

```
// Only valid transitions are possible
appTransition(status, event) → newStatus
vaultTransition(pane, event) → newPane + sideEffects
```

Each transition function returns exactly what should change. No scattered `setX` calls.
Invalid transitions throw (development mode). State graph is documented and testable.

---

## Priority Matrix

| # | Candidate | Effort | Testability Gain | Risk Reduction | Recommended Order |
|---|---|---|---|---|---|
| 1 | God Store | High | High | High | **1st** (foundation) |
| 4 | Filter Pipeline | Low | Medium | Medium | **2nd** (quick win, unblocks thinking) |
| 5 | Screen State Machine | Medium | Medium | Medium | **3rd** (depends on 1) |
| 2 | Mega-Form | High | High | High | **4th** (depends on 1) |
| 3 | SVG Icons | Low | Low | Low | **5th** (cosmetic) |

Candidate 1 is the prerequisite. Splitting the store enables focused testing of 
everything else. Doing 4 first as a quick win is viable since it's pure extraction.

---

## Constraints for Any Refactor

1. **SolidJS stays.** No framework migration.
2. **No behavioral changes.** Same UI, same IPC, same daemon protocol.
3. **Incremental.** Each step should be independently verifiable (build + test).
4. **Tailwind classes untouched.** Only JS/JSX structure changes.
5. **i18n keys unchanged.** Only component boundaries shift.
6. **daemon.js untouched.** The IPC layer is clean. Don't touch it.
7. **Tests must grow.** Each refactor must add tests for what was previously untested.
