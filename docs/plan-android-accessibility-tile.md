# Plan: Android Accessibility Fill: quick-settings tile (Phase 6.5)

Status: 2026-09-16, revised same day. Esteban's final call: mimic Bitwarden's CURRENT approach, accessibility = quick-settings tile ONLY, opt-in, default OFF. The overlay pill is explicitly DROPPED (do not fight current Play rules; Bitwarden themselves removed it in the 2023 rewrite). The analysis below keeps both generations for the record.

## 0. How Bitwarden does it (analysis, source-verified)

Two generations exist in Bitwarden's repos; the difference is the whole design question.

Legacy Xamarin (`bitwarden/mobile`, the model chosen here):

- Service config subscribes `typeViewFocused|typeViewClicked|typeWindowStateChanged|typeWindowContentChanged`, `canRetrieveWindowContent=true`.
- On field focus/click, the node is classified (platform `isPassword` flag, EditText class, id/hint keywords). Username or password field -> the service adds an overlay pill via `WindowManager` (`TYPE_APPLICATION_OVERLAY`, `NotFocusable|NotTouchModal`), anchored just above the focused field's screen bounds, re-anchored as content changes, dismissed on unrelated events, package switch, or fill.
- Permissions: accessibility (user enables in system settings) PLUS `SYSTEM_ALERT_WINDOW` ("draw over other apps"), probed via `Settings.canDrawOverlays` with AppOps fallback.
- Pill tap -> picker activity -> credentials typed with `AccessibilityNodeInfo` `ACTION_SET_TEXT` (username + every password node). TOTP is clipboard-only, copied at selection, never typed.
- URI for matching: browsers scraped from their URL-bar node (a per-browser table), everything else `androidapp://<package>`.

Modern Kotlin (`bitwarden/android`): the overlay, the draw-over permission and the passive field-focus listener are all GONE. The service only hears `typeWindowStateChanged`, idles unless the user armed it from the Autofill quick-settings tile, then scrapes the URI, opens the in-app picker, and fills on the next window change. TOTP clipboard-only. A first-launch full-screen disclosure plus a per-enable accept/decline dialog, `isAccessibilityTool="false"`, package block lists, and content parsed strictly after an explicit user action. That redesign is a Play-policy and privacy posture, not an accident.

Consequences of shipping BOTH models (Esteban's call): the tile flow keeps Bitwarden-modern's tight posture (parse only after an explicit tap, no extra permission); the overlay flow carries `SYSTEM_ALERT_WINDOW` and a passive focus listener. Mitigations adopted from the modern app regardless of model: honest disclosure before enable, strict dismissal rules, block lists for our own package/systemui/launchers, no content logging ever, `isAccessibilityTool=false`, and per-model Baluard-side flags so a system-enabled service with both flags off is inert.

## 1. Baluard architecture decisions

D1. **Runs in the `:autofill` process.** `BaluardAccessibilityService` declares `android:process=":autofill"` alongside the autofill service, `AutofillActivity` and `AutofillSession`: the overlay flow reuses the same unlocked session, the same biometric trampoline and the same KEK-only unlock invariant. The master-password KDF never runs there (plan §3.2 of the mobile doc, unchanged).

D2. **Baluard-side gate, default OFF.** The system accessibility switch alone does nothing. `AccessibilityFill.enabled` (SharedPreferences, readable from both processes, checked on every event) must be ON. Feature off = the service idles even while enabled system-side.

D3. **Detection reuses `FieldHeuristics`.** `AccessibilityNodeInfo` maps onto the existing `FieldView` shape (platform `isPassword` flag, `className` EditText check, `idEntry`, `hint`, `text`). Username or Password classification makes the field eligible for the pill. Only our package, `com.android.systemui` and launchers are skipped.

D4. **Pill = plain Views, one instance.** A two-line pill ("Fill with Baluard" + icon) added via `WindowManager` with `TYPE_APPLICATION_OVERLAY|NotFocusable|NotTouchModal`, positioned above the field bounds (below if clamped), re-anchored on `typeWindowContentChanged`, dismissed on focus loss, package switch, fill, or feature/permission loss. No re-anchoring timer (Bitwarden's 250 ms handler is noise we skip; content-change events cover movement).

D5. **Picker lives in the same process, plain Views.** `AutofillActivity` gains an `A11Y_PICKER` mode: biometric unlock if needed (existing flow), then a plain-View list of `AutofillSession.matches(target)` rows. No Compose in this process (D9 of the autofill plan holds). Selection is handed back through an in-process singleton (`AutofillA11yBridge`), never an Intent (credentials must not ride intents).

D6. **Fill = fresh scan + `ACTION_SET_TEXT`.** After picker selection the service waits for the window-state change back to the target app, re-scans the current node tree (no stale node reuse, Bitwarden's lesson), and sets the username into the first username node and the password into every password node. TOTP, when present, goes to the clipboard at selection time (existing clipboard auto-clear prefs honored) with a toast. TOTP is never typed.

D7. **Target URI: starter browser table + package fallback.** v1 scrapes URL-bar nodes for Chrome/Chromium-family and Firefox-family via resource-id (5-ish entries), everything else `androidapp://<package>`. The table is data, grows with dogfooding.

D8. **Disclosure before enable.** Each toggle only turns on after an accept/decline dialog in plain language: what the service can see, that it reads fields only after you tap them (overlay) or use the tile, that nothing seen is stored or sent, and how to turn it off. Overlay permission is requested as a follow-up row when the pill cannot be drawn. `isAccessibilityTool="false"` in the service config; the service description string says what it does.

D9. **One service, two armed flows.** A single `BaluardAccessibilityService` subscribes to the union of events (focus/click for the pill, window-state/content for the tile flow and re-anchoring). Both flows share the URI scrape, the picker, the fill engine and the TOTP path; the two Baluard-side flags (`AccessibilityFill.overlayEnabled`, `AccessibilityFill.tileEnabled`) gate their respective behaviors independently.

D10. **Tile flow = Bitwarden-modern mechanics.** `BaluardA11yTileService` (QS tile, `:autofill` process) arms a parse action in-process and fires a NoDisplay trampoline to collapse the shade; the next window-state change scrapes the URI, checks for fillable fields, and opens the picker. Selection re-arms a fill action; the window change back to the target app completes it. Pending state lives in the in-process bridge only; process death cancels it.

D11. **Overlay flow: dropped.** The pill requires SYSTEM_ALERT_WINDOW plus an always-listening focus monitor, the two things Bitwarden removed to stay clean with Play. The shared fill engine (D10) is unaffected; if a field-anchored trigger is ever wanted, it would ride on the framework popup, not an overlay.

D12. **Credentials never ride intents.** The picker stores only the chosen cipher id in the in-process bridge; the service fetches username/password/TOTP from `AutofillSession` at fill time.

A4. Settings: two toggles with per-toggle disclosure, accessibility-settings deep link, overlay-permission row, en/es strings. Verify: full opt-in journey from a clean install.

A5. Device matrix + docs progress flip (with the Phase 6 autofill device pass).

## 2. Settings parity with Bitwarden's Autofill screen (source-verified mechanics)

The section mirrors Bitwarden's current Autofill screen, plus our tile:

S1. **Autofill services** toggle row. Checked state mirrors `AutofillRole.isEnabled()` (resume-refreshed); flipping it on opens the system provider picker. Description text under the row, Bitwarden wording adapted.

S2. **Display autofill suggestions** dropdown: Inline (shows in keyboard) / Popup (shows over input field). Bitwarden mechanics, simplified for our minSdk: the manifest ALWAYS declares `supportsInlineSuggestions="true"`; the stored pref (default INLINE, matching Bitwarden's default) only gates whether datasets attach keyboard chips. INLINE -> read `fillRequest.inlineSuggestionsRequest.inlinePresentationSpecs`, distribute across datasets (last-spec reuse, cap 5) and attach `InlinePresentation` chips IN ADDITION to the RemoteViews menu (never instead of); an IME without v1 inline UI degrades silently to the dropdown. Popup -> no specs, current dropdown path. API guards: `Presentations` builder is API 33+ (API 32 keeps the deprecated `setInlinePresentation` on Dataset.Builder).

S3. **Use Brave autofill integration**: NOT a stored setting. It is a live mirror of Brave's own third-party-autofill switch, probed via Brave's content provider (`content://<pkg>.AutofillThirdPartyModeContentProvider/autofill_third_party_mode`, column `autofill_third_party_state` != 0 = on). Row shown whenever a Brave package is installed (Esteban: if detection is impossible, keep the option present); switch state mirrors the probe, and tapping opens Brave's own settings via `ACTION_APPLICATION_PREFERENCES` + `setPackage`. Zero fill-time branching (Bitwarden has none either); the row is enablement guidance. Also declare `<compatibility-package>` entries (Brave channels + Chrome family) in the service configuration XML, the OS-level browser-compat list.

S4. **Use accessibility** + overlay toggle (A3/A4) and **Quick settings fill tile** toggle (A2) slot in below, per the sections above; each opt-in, each disclosed.

## 3. Build order

A1. Shared skeleton: service + manifest + config XML + `AccessibilityFill` prefs gates (two flags) + node mapping onto `FieldHeuristics` + `A11yUri` starter browser table (pure, unit-tested). Verify: build, unit tests, service appears in system accessibility list.

A2. Tile flow: `BaluardA11yTileService` + NoDisplay trampoline + parse + picker + fill engine + TOTP clipboard. Verify: device end-to-end fill in Chrome and a native app from the tile.

A3. ~~Overlay flow~~ dropped (see D11): no pill, no SYSTEM_ALERT_WINDOW anywhere.

A4. Settings: "Use accessibility" toggle with per-enable disclosure + accessibility-settings deep link, "Quick settings fill tile" toggle, en/es strings, service description strings. Verify: full opt-in journey from a clean install.

A5. Device matrix + docs progress flip (with the Phase 6 autofill device pass).

## 4. Out of scope (v1)

- URL-bar scraping beyond the starter browser table; per-site username view-id tables (Bitwarden ports a ~80-site legacy table we do not need yet).
- Typing TOTP into OTP fields (clipboard only, same as Bitwarden).
- iOS: the a11y concept does not exist there; Phase 7 unaffected.
