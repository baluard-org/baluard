# ADR 0091. Android Accessibility Fill Tile

> Status: Accepted (2026-09-16). Implemented, verified on a device in Chrome and a native app, and hardened after code review (thread safety, Android 14 dispatch, token protection, retry limits). The overlay-pill variant was considered and explicitly dropped.

## Context

Some Android applications do not expose reliable Autofill structures. Accessibility APIs can provide a user-triggered fallback that reads visible field metadata and enters selected credentials.

Two generations of this pattern exist in the Bitwarden code bases, and the difference is the whole design question. The legacy mobile client subscribes to view-focus, view-click, window-state, and window-content events with window retrieval enabled. It classifies the focused node and draws an overlay pill through `WindowManager` (`TYPE_APPLICATION_OVERLAY`) anchored above the field, re-anchored as content changes. That requires the accessibility permission plus `SYSTEM_ALERT_WINDOW` ("draw over other apps"). The modern client removed the overlay, the draw-over permission, and the passive focus listener. Its service hears only window-state changes, idles unless the user armed it from a quick-settings tile, then scrapes the target URI, opens an in-app picker, and fills on the next window change, with a first-launch disclosure, a per-enable accept or decline dialog, `isAccessibilityTool="false"`, package block lists, and content parsed strictly after an explicit user action. That redesign is a store-policy and privacy posture, not an accident. In both generations TOTP is copied to the clipboard and never typed, and the target URI is scraped from a per-browser URL-bar table for browsers and `androidapp://<package>` for everything else.

Passive field monitoring and overlay controls require broad permissions and expose more page content than an explicit user-triggered flow. A quick-settings tile provides an explicit arming action without a draw-over permission.

## Decision

### Service, gate, and process

Implement one `BaluardAccessibilityService` in the `:autofill` process, alongside the autofill service, `AutofillActivity`, and `AutofillSession`. It shares the unlocked session, the biometric trampoline, the KEK-only unlock invariant (the master-password KDF never runs there), URI matching, picker, and fill mechanisms with Android Autofill (see ADR 0090).

The system accessibility switch is insufficient to activate filling. Require the Baluard-side `AccessibilityFill` opt-in flag, default OFF, stored where both processes can read it (a filesystem flag, because `SharedPreferences` caches per process), and check it on every service event. With the flag off, the service idles even while enabled in system settings. The tile also refuses to arm unless both the flag and the system service are on. The service configuration subscribes only to window-state changes (`typeWindowStateChanged`), not to focus, click, or window-content events. It must not log viewed content. Declare `isAccessibilityTool="false"`, since this is an autofill fallback and not an accessibility tool, and provide a plain-language service description.

Settings refresh the Android Autofill role state when resumed and link to the relevant system settings page. The accessibility preference remains independent of the Android Autofill provider selection.

### Tile flow

`BaluardA11yTileService` arms a one-shot parse action and launches a NoDisplay trampoline to collapse the quick-settings shade. On Android 14 and later with a target SDK of 34 or higher, `startActivityAndCollapse(Intent)` is rejected, so the tile branches to the `PendingIntent` overload on that version and uses the `Intent` form below it. On the next window-state change the service identifies the target URI and eligible fields, then opens the picker. Selection arms a fill action, and the return window-state change completes the fill. Pending actions live only in an in-process bridge and are cancelled on process death.

The tile action checks that a fillable field exists before opening the picker, which avoids presenting credentials in a window where the service cannot enter them. Tapping the tile is the explicit consent signal for reading the current window; merely enabling the system service does not arm parsing. The tile is an alternative entry point to the same credential selection path, not an independent credential store or matching implementation.

### Field detection and target URI

Map `AccessibilityNodeInfo` to the existing `FieldView` shape (platform password flag, EditText class, resource entry ID, hint, and text) and reuse `FieldHeuristics` to identify username and password fields. The node walk is bounded in depth and in children per node. Skip Baluard, `com.android.systemui`, and launcher packages.

For browsers in the starter browser table (Chrome and Chromium family, Firefox family), scrape the URL bar by resource ID. For all other applications, use `androidapp://<package>`. URL-bar extraction is limited to the known browser-family resource identifiers and does not scan arbitrary visible text for URL-like strings. Expand the table only from device use. Broad per-site username view-ID tables (Bitwarden's legacy client carries roughly 80 entries) are not added in v1.

### Fill

After selection, wait for the window-state transition back to the target application, re-scan the current node tree, and never reuse stale node references. Set the username on the first username node and the password on every password node with `ACTION_SET_TEXT`. Retries are capped at three bounded attempts per selection, after which the pending fill is discarded. TOTP is copied to the clipboard only, at selection time with a toast, and never typed into OTP fields; the existing clipboard auto-clear preference applies. Session decrypts run on a background coroutine scope (`AutofillSession.scope`), never blocking the accessibility service's main looper, to avoid an ANR.

The picker runs in `AutofillActivity` using plain Views, with no Compose in this process. If the process is locked, use the existing biometric trampoline and KEK-only unlock path. The picker hands its result to the service through an in-process singleton (`AutofillA11yBridge`) that stores only the selected cipher ID; credentials never ride Intent extras or an exported activity result, which keeps plaintext out of Intent transport. The service fetches username, password, and TOTP from `AutofillSession` immediately before filling.

### Consent and settings

Each enable action requires an accept-or-decline disclosure in plain language: what the service can see, when it reads fields, that nothing seen is stored or sent, and how to disable the feature. It is shown on every transition from disabled to enabled, and declining leaves the preference disabled and returns the user to settings. Settings link to Android accessibility settings. System permission revocation or loss of the Baluard-side flag immediately makes the service inert and dismisses pending work. TalkBack labels cover the tile, picker rows, and settings controls, and the service description and disclosure use the shared localized string dictionaries.

### Rejected: the overlay pill

The overlay-pill model is rejected. Do not request `SYSTEM_ALERT_WINDOW`, display a floating pill, or continuously monitor field focus. The pill needs the draw-over permission plus an always-listening focus monitor, the two things Bitwarden removed to stay clean with the store. An earlier draft shipped both models behind two independent flags; it was cut before release. The shared fill engine is unaffected, and if a field-anchored trigger is ever wanted it should ride on the framework autofill popup, not an overlay. There is no overlay-permission settings row and no periodic re-anchoring timer. The tile flow is the only accessibility fill path.

## Consequences

Users can invoke filling in applications where Autofill is unavailable, while content parsing starts only after an explicit tile action. The flow shares existing security and matching code.

Accessibility service access remains broad by platform design, so explicit disclosure, the opt-in gate, package exclusions, bounded retries, and no-content-logging are required. Fills depend on target applications exposing usable node trees, and unknown browsers fall back to the package URI until the table grows.

Out of scope: URL-bar scraping beyond the starter table, per-site view-ID tables, typing TOTP into OTP fields, and iOS, which has no equivalent accessibility fill service.

## References

- `docs/adr/0089-mobile-apps.md`
- `docs/adr/0090-android-autofill.md`
- `docs/adr/0028-android-autofill-quick-settings-accessibility-architecture.md`
- `mobile/androidApp/src/androidMain/kotlin/xyz/actitud/baluard/autofill/`
- `mobile/androidApp/src/main/res/xml/accessibility_service.xml`
