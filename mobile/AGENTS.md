# mobile/AGENTS.md

Agent guidance for the Baluard mobile app (Kotlin Multiplatform, Compose) and its
Maestro E2E harness (`e2e/mobile/`, `mobile/scripts/run-maestro.sh`). The repo-root
AGENTS.md governs everything else.

## Maestro on this box — hard-won transport rules

### The adb server and Maestro cannot share the phones

Maestro's device layer (DADB) opens the phones' USB device nodes **directly**. A
running adb server holds those same interfaces, and the Maestro driver then dies at
its first RPC (`DeviceServerDiedException` at `deviceInfo`, ~200ms, no
`commands.json` in the Maestro tests dir). An **orphaned `bin/maestro` process**
from a killed run holds them identically. Symptoms look like dead phones, dead
drivers, or dead USB — they are none of these.

- `run-maestro.sh` already handles this: it kills stale maestro launchers and runs
  `adb kill-server` before every flow. The next plain adb client restarts the
  server on demand.
- Never run adb commands **during** a Maestro flow. Probe between flows, or the
  adb client you spawn re-arms the conflict.
- On a multi-device host, Maestro ignores `ANDROID_SERIAL`; the runner passes
  `--udid`. Verify which device a run actually drove by checking **both** phones'
  screens/logcat — never trust the flow log alone.

### `inputText` wedges on long strings

Maestro's `inputText` types per-key through the IME. Past roughly ~1000 characters
in one call the command stops mid-stream (typing visibly stalls, the step never
returns) — the 1356-char join-intro code wedges deterministically. It is not app
jank: the Compose fields are passthrough and logcat shows zero Choreographer skips.

- Split long text into **chunks of ~200 chars** in separate `inputText` steps
  (`${BALUARD_E2E_INTRO_1}` … `_8`), `hideKeyboard` after the last chunk only.
- Fallback if chunking ever wedges too: `adb shell input text '<chunk>'` between
  flow segments (base64url chars need no shell escaping), keeping the app
  foregrounded so field focus survives.

### `inputText` has no element targeting — tap first, then type

`inputText` types into whichever field currently holds focus. An `id:` key on
an `inputText` step is silently discarded (commands.json records only the
text), so `- inputText: {id: ..., text: ...}` fills the focused field, not
the named one. Screens whose first field auto-focuses (create form) will
swallow every input into that field. The reliable pattern is one field at a
time: `tapOn` the field, `inputText`, `hideKeyboard` before moving to the
next tap — the `hideKeyboard` matters because the open IME pushes lower
fields behind it where their taps drift (this exact race is why a taller
create form broke flows that had worked for weeks).

### Maestro's clipboard commands do not touch the device clipboard

`setClipboard` writes Maestro's **internal** clipboard only, and `pasteText` replays
it through the same per-key IME path as `inputText` (upstream issue
mobile-dev-inc/Maestro#3640). Neither can transfer text into a field the way a user
paste would — do not reach for them for long-string transfers. The app's own copy
buttons (platform `copyToClipboard`) are the real clipboard; driving a paste from
the harness would need an app-side hook, not a Maestro feature.

## Flow-authoring checklist (every new flow inherits all of it)

New flows that skip these rediscover solved failures:

1. `launchApp` cold-starts (stopApp defaults true). The Android system
   compatibility dialog re-arms on every cold start — an optional
   `tapOn: {id: android:id/button2, optional: true}` right after launch.
2. `hideKeyboard` before any tap sitting below a text field — the IME covers it and
   the element vanishes from the a11y tree.
3. `scrollUntilVisible` (selector nested under `element:`) before below-the-fold
   asserts **and** taps; uiautomator carries only visible nodes. Skip the trailing
   `waitForAnimationToEnd` on screens with live-polling UI (join requests, sync
   indicators) — they never settle and the wait itself becomes the failing step;
   let scrollUntilVisible carry it.
4. `extendedWaitUntil` with a generous timeout after anything network-backed
   (clone, post-clone screens) — never a bare `assertVisible`.
5. `- back` plus an `extendedWaitUntil` on a hub marker before hub taps after
   probing a sub-screen.
6. Final asserts target vault-hub markers (the vault's own title, the SHARED
   section), never the app name.
7. Author `text:` selectors only (`textRegex` is internal, invalid in YAML).
   Compose SectionCard titles render UPPERCASE; concatenated rows render one text
   node — match the whole string or a regex on `text:`.
8. New flow parameters must be named `BALUARD_E2E_*` at authoring time — the runner
   forwards `MASTER_PW` plus unstripped `BALUARD_E2E_*` only, and an unresolved
   `${VAR}` types the literal `"undefined"`.
9. Read results from the per-flow `commands.json` under `~/.maestro/tests/<ts>/` —
   the orchestrator's exit code is not evidence (trailing `echo EXIT=$?` launders
   failures; a run whose tests dir is missing executed nothing).

## Mobile app notes

- Rust-side logging never reaches logcat on Android; only the e2e-gated
  `platformLogE` calls surface. The diagnosis channels: `DeviceCode` (device-flow
  code), `JoinSpace` (intro code), `JoinInvite` (invite code), `JoinPoll` (raw poll
  response), `ProviderFlow` (clone failures), `ContactCard` (contact card).
- Sync nudges: every mutation surface that writes `meta/` artifacts must arm the
  debounced push on success (`onSyncNudge` → `App.kt` `notifyMutation`), and a
  vault whose remote is attached after creation needs the explicit autosync
  activation in `setup_sync` — the unlock-time activation skips remote-less
  vaults. A remote tree missing artifacts that exist on-device is the signature of
  a missing nudge, not a gitignore problem (`meta/invites`, `settings-pub.json`,
  `space-shape.json` are tracked).
- Sync failures are invisible by design (runCatching-wrapped, no logging): diagnose
  from remote-side forensics (GitHub contents API, `ls-remote` with the PAT in the
  URL because plain ls-remote silently returns empty under a pushInsteadOf SSH
  rewrite), never from device logs.
- A Rust-side fix is invisible on-device until `build-android-apk.sh --e2e
  --install` reruns (the APK embeds the runtime as a cdylib); a phone-side assert
  failing right after a Rust fix is stale-APK until proven otherwise.
