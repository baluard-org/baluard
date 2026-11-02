# ADR 0013. Frontend Refactor Candidates

> Status: Accepted (completed 2026-06-04); follow-up items partly resolved, see Consequences

## Context

After the store split (ADR 0012), four frontend refactor candidates were analyzed, prioritized, and executed, labelled A to D in the original analysis: A cipher schema, B filter pipeline, C state transition guards, and D SVG icon component. They reduce duplicated SVG markup, filtering logic, state transition handling, and cipher field mapping. The cipher field mapping was the costliest problem, because the mapping between the structured daemon `kind` object and the flat form fields was an implicit contract spread over three files.

## Decision

The frontend adopted these refactors (D, B, C, and A in execution order):

- **SVG icons:** `components/Icon.jsx` exports more than 40 named SVG icons. It replaced 67 of 70 inline SVGs across 12 components. The category array in `VaultView` was reduced from 13 lines of SVG markup to named imports.
- **Filter pipeline:** `lib/filters.js` provides pure functions `selectSource`, `filterByCategory`, `filterByFolder`, and `searchCiphers`. `CATEGORY_TYPE_MAP` is the single mapping from UI category names to daemon cipher type strings. It replaces a 45-line inline filter in `VaultView` with a six-line composed pipeline. Vitest covers the helper functions.
- **State transition guards:** `VALID_AUTH_TRANSITIONS` in `AuthContext` defines seven states and valid edges, including `init -> locked` and `recovery -> setup`. `VALID_PANE_TRANSITIONS` in `VaultContext` defines four pane states. `guardedSetStatus` and `guardedSetPane` wrap internal transitions and issue a development-only `console.warn` for invalid transitions.
- **Cipher schema:** `lib/cipherSchema.js` defines schemas for all eight cipher types. Each schema provides `fields[]`, `fromKind` for structured-to-flat conversion, and `toKind` for flat-to-structured conversion. `CipherDetail.startEdit()` uses `cipherToFlat()` instead of an 80-line manual field mapping, and `payload.buildKind()` uses `schema.toKind()` instead of a 100-line if/else chain. Vitest includes round-trip tests for all eight types. The schema is the single source for field-name mappings that were previously an implicit contract across three files.

At completion, the cipher schema did not yet drive form rendering; `AddEditCipherForm.jsx` retained eight `<Show>` blocks, one per cipher type. Three follow-ups were recorded as open:

- Schema-driven form rendering: replace the eight `<Show>` blocks with schema-driven field iteration, estimated to reduce about 850 lines to about 300.
- `filteredCiphers` in `VaultView` could use `createMemo` because it was called twice per render.
- Transition guards are advisory only, because raw setters are still exported for external navigation.

The frontend constraints that governed all four refactors, and that remain the working rules for later frontend refactors, are:

1. SolidJS stays; no framework migration.
2. No external state library; only SolidJS primitives (`createSignal`, `createContext`, `createEffect`).
3. No behavioral change in a refactor: same UI, same IPC, same daemon protocol.
4. Each refactor is incremental and independently verifiable through build and tests.
5. `daemon.js`, `payload.js`, `utils.js`, `app.css`, and the i18n keys are touch-free zones for refactors. The record itself is not consistent on this point: the cipher-schema refactor replaced the body of `payload.buildKind()`, so the rule is best read as "do not change the public contract of these files".
6. Tests must grow: each refactor adds tests for logic that was previously untested.

## Consequences

The completed refactors centralize icon exports, filtering, state transition rules, and cipher field mappings.

Status of the three open follow-ups, checked against the code on 2026-11-02:

- Memoization: resolved. `filteredCiphers` in `VaultView` is a `createMemo`.
- Form rendering: partly resolved. `AddEditCipherForm.jsx` obtains the schema through `getSchema(cipherType())` and renders the generic types from `layoutRows()`. Login, card, and SSH key keep dedicated rendering blocks. The file is about 710 lines, so the 300-line estimate was not reached.
- Transition guards: still advisory by design. The shared `makeTransitionGuard` in `lib/transitionGuard.js` warns only in development builds, and the state write always runs, so a guard can never block a transition in production. The tables have grown with the product: the auth table has eight states (a `welcome` state was added) and the pane table has four.

## References

- ADR 0012 for the store split these refactors build on.
- ADR 0015 for the `FocusTrap` component and ADR 0017 for the toast signal, which were introduced in the same period.
