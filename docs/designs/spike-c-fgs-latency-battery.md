# Spike C — Foreground service type, practical limits, and keepalive latency/battery

**Status:** research spike (no code or manifest changed — verified)
**Date:** 2026-11-19/20 (all web sources accessed 2026-11-19/20 unless otherwise dated)
**Context:** Baluard (KMP Android app, `targetSdk 36` / `compileSdk 36`, `minSdk 32`, play + fdroid flavors) wants to hold a WSS connection (25 s keepalive ping) via a relay so a paired desktop browser extension can use the phone as its unlock authority over the internet. Today `androidApp/src/androidMain/AndroidManifest.xml` declares **no** `FOREGROUND_SERVICE` permission and **no** `foregroundServiceType`.

---

## 1. Verdict table

| # | Question | Verdict | Primary source (URL + page date) |
|---|----------|---------|----------------------------------|
| 1 | Which FGS type in 2026 for "persistent outbound WSS so a paired desktop can request secrets"? | **`connectedDevice` is the primary recommendation; `specialUse` is the fallback if Play rejects it; `dataSync` is disqualified as a 24/7 type (6 h/24 h cap since Android 15; app crashes on overrun).** | developer.android.com/develop/background-work/services/fgs/service-types (upd. 2026-10-28); /fgs/timeout (upd. 2026-10-28); support.google.com/googleplay/android-developer/answer/13392821 (Play Console FGS declaration, upd. 2025) |
| 1a | Is `dataSync` deprecated/restricted in 2026? | Not deprecated, but **time-capped**: 6 h per 24 h rolling, shared across the app's dataSync services; reset only when the user opens the app. No 2026 carve-out for communication use cases exists; Android 16/17 added **no** new FGS types. | developer.android.com/develop/background-work/services/fgs/timeout (upd. 2026-10-28); /develop/background-work/services/fgs/changes (upd. 2026-10-28); /about/versions/17/behavior-changes-17 (upd. 2026-11-11) |
| 1b | F-Droid flavor may use any type? | **Yes — platform rules apply identically, but there is no Play Console declaration/review.** F-Droid still enforces its own metadata review on some FGS misuse (e.g. `systemExempted`). Platform runtime prerequisites (e.g. `connectedDevice` prerequisites) must still be met or the system throws `SecurityException`. | developer.android.com/develop/background-work/services/fgs/troubleshooting (upd. 2026-11-16); forum.f-droid.org/t/misuse-of-foreground-service-with-systemexempt-permissions-background-workaround-v-31-0/34514 (2025) |
| 2 | Practical limits (Android 13–17)? | FGS notification is **dismissible by default** on 13+; Task-Manager "Stop" kills the whole app with no callback. **Doze suspends network access for ALL apps incl. FGS** (empirically confirmed); OEM killers (Xiaomi/Samsung) still require whitelisting; Android 16 job-quota change; Play vitals won't flag an FGS-state app; data-safety declaration needed for the secret transfer. | developer.android.com/about/versions/13/behavior-changes-all (upd. 2026-10-28); source.android.com/docs/core/power/platform_mgmt (accessed 2026-11-19); dontkillmyapp.com/samsung & /xiaomi (accessed 2026-11-19) |
| 3 | 25 s keepalive latency/battery on WiFi vs cellular? | **WiFi: effectively free** (measured: RTT ≈ 16–25 ms full HTTPS round trip; app-attributed battery ≈ **0.3 %/day**, net-of-baseline ≈ 0.15 %/day; WiFi radio asleep 99.6 % of wall time). **Cellular: 25 s is too aggressive** — RRC inactivity timers (≈ 5 s 3G / ≈ 11.6 s LTE) keep the radio high-power between pings; real-world dogfood data shows ≈ 5 %/h on 4G for WSS-keepalive FGS apps. **Make the interval adaptive.** | This report's empirical section (Galaxy S25 Ultra, Android 17, 2026-11-19); feng-qian.github.io/paper/periodic_www12.pdf (WWW 2012); github.com/binwiederhier/ntfy/issues/687 (2023, updated 2025-02-19) |

---

## 2. Question 1 — Foreground service type

### 2.1 Candidate-by-candidate

**`dataSync` — disqualified for a persistent connection.**
- Platform behavior (Android 15+, targeting API 35+): `dataSync` FGS may run **6 h total per 24 h**; the budget is shared across all of the app's `dataSync` services; on timeout the system calls `Service.onTimeout(int,int)` and the service has "a few seconds" to call `stopSelf()`; otherwise the system throws `RemoteServiceException` ("A foreground service of type dataSync did not stop within its timeout") — the troubleshooter doc states the user sees a crash dialog. After exhaustion, starting another `dataSync` FGS throws `ForegroundServiceStartNotAllowedException: "Time limit already exhausted …"` **until the user brings the app to the foreground** (which resets the timer).
  - Sources: https://developer.android.com/develop/background-work/services/fgs/timeout and https://developer.android.com/about/versions/15/behavior-changes-15 (both "Last updated 2026-10-28 UTC"); https://developer.android.com/develop/background-work/services/fgs/troubleshooting (upd. 2026-11-16).
- A 24/7 unlock-authority connection therefore dies (or crashes the app) after ≤ 6 h if the user doesn't open Baluard daily. Play policy also explicitly exempts only "dataSync only when using Play Asset Delivery features" from its FGS use criteria — no communication carve-out.
  - Source: https://support.google.com/googleplay/android-developer/answer/9888379 (Device and Network Abuse, accessed 2026-11-19).
- 2026 status: not deprecated (still listed as a normal type), but the timeout doc says the restriction "currently" applies only to `dataSync`/`mediaProcessing`. Android 16 and 17 behavior-change lists contain **no new FGS types and no dataSync exceptions** (16: job-quota change only; 17: no FGS changes) — https://developer.android.com/develop/background-work/services/fgs/changes (upd. 2026-10-28), https://developer.android.com/about/versions/17/behavior-changes-17 (upd. 2026-11-11).
- **Data point in favor (contextual):** a community networking app recently *switched away from* `connectedDevice` *to* `dataSync` for "continuous network data transfer" (github.com/dimadesu/bond-bunny PR #115) — so `dataSync` is *the accurate taxonomy* for generic network transfer, but the 6 h cap makes it unusable as the *always-on* mechanism for this feature.

**`connectedDevice` — recommended primary.**
- Platform description: "Interactions with external devices that require a Bluetooth, NFC, IR, USB, **or network connection**." A paired desktop browser (extension) reachable over the internet through a relay is an external device reached over a network connection.
  - Source: https://developer.android.com/develop/background-work/services/fgs/service-types (upd. 2026-10-28).
- **Runtime prerequisites are trivially satisfiable:** at least one of `CHANGE_NETWORK_STATE` / `CHANGE_WIFI_STATE` / `CHANGE_WIFI_MULTICAST_STATE` / `NFC` / `TRANSMIT_IR` declared in the manifest (no runtime grant needed), or one of the BT/UWB runtime permissions, or `UsbManager.requestPermission()`. Declaring `CHANGE_WIFI_STATE` (or `CHANGE_WIFI_MULTICAST_STATE`) satisfies the prerequisite outright. Same source.
- **No time limit** — the timeout page lists only `dataSync` and `mediaProcessing`. https://developer.android.com/develop/background-work/services/fgs/timeout (upd. 2026-10-28).
- Play declaration path: Play Console use case "**Continuous Data Transfer to an External Device**" — "Interactions with external devices including data transfer that require a Bluetooth, NFC, IR, USB, or network connection." Video must "show the user pairing and connecting to an external device directly inside the app." Baluard's pairing (scan/confirm pairing with the desktop extension) fits this video requirement.
  - Source: https://support.google.com/googleplay/android-developer/answer/13392821 (Play Console Help, accessed 2026-11-19).
- Real-world precedent: **KDE Connect** — the canonical phone↔desktop companion app — declares `foregroundServiceType="connectedDevice"` + `FOREGROUND_SERVICE_CONNECTED_DEVICE` and ships on both Play and F-Droid (manifest inspected 2026-11-19, master branch: `KDE/kdeconnect-android`, `src/main/AndroidManifest.xml`).
- Caveat: Play's FGS policy criteria still apply — the use must be user-perceptible, stoppable, and "run only as long as necessary." An always-on service the user explicitly enabled for the unlock-authority feature, with a clear ongoing notification and a Stop affordance, is defensible (see 2.3).

**`specialUse` — viable fallback; review risk unknown/unfavorable odds unquantified.**
- Platform: no runtime prerequisites; requires `FOREGROUND_SERVICE_SPECIAL_USE` plus a free-form use-case string via `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="…"/>`; "All foreground service types are subject to review."
  - Sources: https://developer.android.com/develop/background-work/services/fgs/service-types (upd. 2026-10-28); https://support.google.com/googleplay/android-developer/answer/13392821.
- Play review reality: **no published approval rate exists** (accessed 2026-11-19; could not find any Google-published statistic). Anecdotes show mixed outcomes — e.g. a downloader app whose `specialUse` use was approved-with-violation, with reviewers pushing developers toward WorkManager/deferrable designs (stackoverflow.com/questions/77778015, 2024). For a password manager, "keep a socket open indefinitely" is exactly the shape a reviewer calls deferrable ("can't be interrupted … without causing a negative user experience" is the criterion it must satisfy). Risk: medium.
- On **F-Droid**: `specialUse` needs no Play review at all (there is no Play Console for that flavor); only the platform checks the property exists, not its content.

**`remoteMessaging` — tempting on paper, wrong on substance.**
- Play's own use-case row is strikingly close: "Relay text communication to another device … allow users to send text messages via a web client by scanning a QR code and establishing a connection between the web client and the phone. **Not limited to SMS.**"
  - Source: https://support.google.com/googleplay/android-developer/answer/13392821.
- But the platform description is "Transfer **text messages** from one device to another … continuity of a user's **messaging** tasks" (service-types page, upd. 2026-10-28). Secrets delivered on request are not messaging continuity; declaring remoteMessaging for an unlock-authority channel risks a policy-violation finding for type misuse. Not recommended.

**`mediaPlayback` / others — no.** No playback occurs; Android 17 additionally hardens background audio (https://developer.android.com/about/versions/17/behavior-changes-17, upd. 2026-11-11). `systemExempted` is reserved for system roles (service-types page). FGS type declarations became mandatory for all apps targeting Android 14+ (https://developer.android.com/about/versions/14/changes/fgs-types-required).

### 2.2 Android 15/16/17 deltas affecting the choice (2026 view)

- Android 15: `dataSync`/`mediaProcessing` 6 h timeout; `BOOT_COMPLETED` no longer launches `dataSync`, `camera`, `mediaPlayback`, `phoneCall`, `mediaProjection`, `microphone` FGS (behavior-changes-15, upd. 2026-10-28).
- Android 16: no new types; background jobs started while a FGS runs now adhere to JobScheduler runtime quotas (affects the *implementation* pattern if Baluard schedules jobs from the service); Local Network Permission begins opt-in rollout 25Q2 (behavior-changes-16, upd. 2026-10-28).
- Android 17: no FGS-type changes; `ACCESS_LOCAL_NETWORK` runtime permission becomes **mandatory** for targetSdk 37 apps (only matters if Baluard ever talks directly to LAN devices, e.g. local-discovery mode — the relay path is unaffected) (behavior-changes-17, upd. 2026-11-11).
- Note: Baluard's build currently targets API 36, so Android 17 rules apply only if `targetSdk` is raised; the Samsung S25 Ultra test device already runs Android 17 (SDK 37).

### 2.3 What Play review will demand regardless of type

Per the Device and Network Abuse "Permissions for Foreground Services (FGS)" section, the use must: run only as long as necessary; not be safely deferrable; be stoppable by the user; be user-initiated or user-perceptible; and serve core functionality (answer/9888379). Play Console declaration additionally requires, for **each type**: a functional description, an explanation of user impact if deferred/interrupted, a video of the user triggering the feature, and the chosen use case (answer/13392821).

**Design consequences for Baluard (policy-shaped):**
1. Start the FGS from an explicit user action ("Enable remote unlock"), not from BOOT_COMPLETED.
2. Persistent, honest notification ("Unlock authority active — tap to stop"), i.e. `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_CONNECTED_DEVICE` + `POST_NOTIFICATIONS` flow.
3. Offer a one-tap stop in-app and accept that Task Manager Stop will kill it.
4. Consider an "active session" model as plan B: FGS only while the desktop extension has a pending request window, rather than 24/7 — this is the strongest answer to "runs only as long as necessary."

---

## 3. Question 2 — Practical limits

| Constraint | Behavior | Source (URL + date) |
|---|---|---|
| Notification dismissal (13+) | FGS notifications are **user-dismissible by default** (dismissing does not stop the service); the Task Manager "Stop" button in the drawer **removes the whole app from memory**, removes the back stack, kills the notification, and sends **no callback** to the app (recoverable reason via `ApplicationExitInfo.REASON_USER_REQUESTED`). | developer.android.com/develop/background-work/services/fgs/handle-user-stopping (accessed 2026-11-19); developer.android.com/about/versions/13/behavior-changes-all, "Dismissible foreground service notifications" (upd. 2026-10-28) |
| POST_NOTIFICATIONS denied | Service keeps running; FGS notices don't appear in the drawer, but the Task Manager entry remains visible. | developer.android.com/about/versions/13/behavior-changes-13 (accessed 2026-11-19) |
| Doze / screen-off | Both lightweight and deep Doze **suspend app network access** (and ignore wake locks); FGS grants **no exemption**. Battery-optimization-whitelisted apps are partially exempt (network + partial wake locks). Empirically reproduced on the S25 Ultra (see §5.4): under forced deep idle the WSS handshake could not complete at all. | source.android.com/docs/core/power/platform_mgmt (accessed 2026-11-19); developer.android.com/training/monitoring-device-state/doze-standby (upd. 2026-10-22) |
| Battery-optimization exemption policy | Apps may invoke `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` only when Doze/standby breaks core function. The published acceptable-use table lists "Peripheral device companion app — maintaining a persistent connection with the peripheral device" as **acceptable** — Baluard's use case reads directly into that row. | developer.android.com/training/monitoring-device-state/doze-standby (upd. 2026-10-22) |
| OEM task killers | Samsung: since One UI 6.0 Samsung publicly committed that "foreground services of apps targeting Android 14 will be guaranteed to work as intended" per the Google collaboration statement (July 2024), but non-standard sleeping-app lists and per-app restrictions persist and can re-restrict after firmware updates. Xiaomi/MIUI: non-standard background limits with no API; per-app "Autostart" permission and app locking required; documented as the second-worst vendor on dontkillmyapp. | dontkillmyapp.com/samsung and dontkillmyapp.com/xiaomi (accessed 2026-11-19; Samsung statement dated 07/2024) |
| Android 16 | Background jobs launched from a FGS must now respect JobScheduler runtime quotas (affects any WorkManager use *from* the service); no FGS-type changes. | developer.android.com/develop/background-work/services/fgs/changes (upd. 2026-10-28); /about/versions/16/behavior-changes-all (accessed 2026-11-19) |
| Play vitals | "Excessive mobile network usage in background" flags apps at > 50 MB/day **only in `PROCESS_STATE_BACKGROUND`/`CACHED`** — an app with a running FGS is not in those states, so a well-behaved keepalive won't trip this metric. | developer.android.com/google/play/vitals/bg-network-usage (accessed 2026-11-19) |
| Play Data safety | "Collect = transmitting data off device"; SDK/library transmissions count. The secret-transfer channel to the relay must be declared (data types + purpose "App functionality", "encrypted in transit", retention/deletion posture). The connection mechanics themselves are not declared, only the data. | support.google.com/googleplay/android-developer/answer/10787469 (accessed 2026-11-19) |
| Overrun/timeout UX | If a time-limited type (dataSync/mediaProcessing) overruns, the system crashes the app and **the user sees an "app has stopped" dialog**. | developer.android.com/develop/background-work/services/fgs/troubleshooting (upd. 2026-11-16) |

---

## 4. Question 3 — Latency and battery

### 4.1 WiFi (measured on-device, see §5)

- Full HTTPS round trip (fresh TCP + TLS 1.3 + HTTP exchange, device→LAN host, 5 GHz 802.11ax, RSSI −47): **16.2–24.9 ms** (avg ≈ 19 ms); TCP connect ≈ 3.5–5.1 ms, TLS handshake complete ≈ 10.5–20.6 ms. An established WSS connection that only ships ping/pong frames rides the bare-RTT path, so expect **single-digit ms typical** on WiFi.
- ICMP RTT: 3.2–7.3 ms in clean samples, but averages inflated to ~20 ms with **spikes up to 122 ms** — the phone's WiFi power-save wake adds jitter when the screen is off. Design the unlock-authority latency budget around ~10–150 ms on WiFi, not the ~5 ms ideal case.
- Battery attribution (25 s WSS ping/pong for ≈ 11.6 min, screen off, on battery):
  - App-attributed (uid 2000 segment): **0.119 mAh** ≈ 0.012 %/h ≈ **0.29 %/day extrapolated**.
  - Idle wireless-ADB baseline run of the same window: 0.048 mAh/10 min → net keepalive-attributable ≈ **0.15 %/day**.
  - **Call it: well under 0.5 %/day on WiFi.** WiFi radio slept 99.6 % of wall time (Rx 2.48 s + Tx 0.15 s in 11.6 min).
- Data volume: ~165 KB/11.6 min measured (this includes idle wireless-ADB tunnel noise of ~100 KB/10 min); a pure WS ping/pong exchange is ~150–300 bytes wire each way → roughly **1–6 MB/day**. Irrelevant for data plans.

### 4.2 Cellular (from primary literature + real-world dogfood reports; not measured — device SIM not touched)

The physics that makes 25 s keepalive expensive on cellular is the RRC state machine: every exchange promotes the radio to a high-power state and a *network-controlled inactivity timer* holds it there long after the ping is done.

| Network | State | Measured power | Tail/inactivity | Source |
|---|---|---|---|---|
| 3G/UMTS (US carrier) | CELL_DCH (high) | 600 mW | DCH→FACH idle 5 s | Qian et al., "Periodic Transfers in Mobile Applications," WWW 2012 — feng-qian.github.io/paper/periodic_www12.pdf |
| 3G/UMTS | CELL_FACH (low) | 450 mW | FACH→IDLE idle 12 s | same |
| 3G/UMTS | IDLE | < 10 mW | promotion delay up to 3 s | same |
| LTE (large US carrier) | RRC_CONNECTED→IDLE | CONNECTED 1000–3500 mW while transmitting/waiting (AT&T) | **inactivity timer measured 11.6 s** | Qian WWW 2012; AT&T Developer "Comparing LTE and 3G Energy Consumption" |
| WiFi | data | ~300 mW | tail ~250 ms | Qian WWW 2012 |

Consequence: a 25 s period sits **inside the tail** on LTE (11.6 s tail + ramp ≈ 13–15 s of elevated power per 25 s cycle → ~50–60 % radio duty at high power). The same paper quantifies the class of harm: periodic transfers were **1.7 % of Facebook's traffic volume but 30 % of its handset radio energy**; even app-wide, periodic transfers contributed 8 % of radio energy from 0.4 % of bytes.

Real-world confirmation (independent, app-side): ntfy (WSS-in-FGS push app) on 4G drained **~5 %/h** on a Xiaomi Mi9 SE, "not the case for WiFi," with the reporter observing the same for Signal's permanent-WSS FGS (3–5× worse than ntfy) — github.com/binwiederhier/ntfy/issues/687 (filed 2023-03-27, last substantive update 2025-02-19). 5 %/h ≈ 100+ mW continuous radio power — consistent with the RRC numbers above.

**Estimate for a fixed 25 s keepalive on cellular: ≈ 5–25 %/day device battery depending on device/modem/network** (5 %/h worst case observed → modern devices with fast dormancy land lower; WiFi is ~50× cheaper).

### 4.3 Doze interaction (why "adaptive" is mandatory, not optional)

When the phone is stationary, unplugged, screen-off for long enough, Doze suspends app network access — **including FGS apps** — with only sparse maintenance windows (source.android.com/docs/core/power/platform_mgmt). Overnight the WSS will silently die at the relay/NAT/server timeout; the phone cannot notice until a maintenance window or user interaction. Therefore:
- On WiFi: keep 25 s while user-active/screen-on; relax to 60–120 s in background (well above every NAT/firewall idle timeout in practice? — verify relay's own idle timeout; typical TCP NAT ≈ 5–30 min, so 60–120 s is safe and cuts Doze-window losses).
- On cellular: 25 s is the expensive regime; 60–300 s still beats every realistic NAT timeout and cuts radio duty cycle ~10× (Qian's headline optimization).
- Doze-awareness: on entering/exiting Doze, expect disconnect → reconnect at next window; surface "authority offline" state honestly in the UI. Optionally pair with FCM for wake-ups (Google's own recommendation for persistent connections; doze-standby page) — though an unlock *authority* over a custom relay can't fully delegate to FCM.
- If the feature is user-visible enough, request battery-optimization exemption via the sanctioned flow ("peripheral device companion app" row) rather than fighting Doze silently.

---

## 5. Empirical results (measured 2026-11-19/20, ~22:09–22:35 −03)

### 5.1 Environment
- Devices found via `adb devices`: **Samsung SM-S938B** (Galaxy S25 Ultra, **Android 17 / SDK 37**, wireless ADB) and an x86_64 emulator (Android 15, no tooling; used only for sanity checks).
- Test: no Baluard build, no app install. Server: minimal stdlib WSS echo server (handshake + frame echo + ping/pong) on the host (192.168.10.100:8443, self-signed cert, TLS 1.3). Client: the device's stock `/system/bin/curl` 8.16.0-DEV (protocols include `ws wss`; verified: WSS 101 handshake, automatic PONG to server PING).
- Traffic path: device WiFi → LAN → host (real radio path; host firewall port opened for the test, then left open — flagging as an environment change outside the repo).
- Device conditions: screen off (`mWakefulness=Dozing`), on battery (status 3, level 44), Samsung Android 17.

### 5.2 Latency (WiFi)
| Metric | Result |
|---|---|
| ICMP RTT (device→host) | 3.2–7.3 ms clean; avg 20.2 ms incl. power-save spikes; max 122 ms (20 pings, screen partially off) |
| HTTPS round trip, fresh TCP+TLS each (15 samples) | total 16.2–24.9 ms (avg ≈ 19 ms); TCP 3.5–5.1 ms; TLS done 10.5–20.6 ms |
| WSS handshake (persistent conn) | 101 Switching Protocols verified from device |

### 5.3 Battery (25 s WSS ping/pong, ~11.6 min, screen off, `dumpsys batterystats --reset` before / `--charged` after)
| Item | Keepalive run | Idle baseline (10 min, no traffic) |
|---|---|---|
| UID-attributed (adb-shell uid 2000, which ran the client) | **0.119 mAh** (cpu 0.044 + wifi 0.075) | 0.048 mAh (cpu 0.021 + wifi 0.028) |
| → rate | 0.61 mAh/h ≈ 0.012 %/h ≈ **0.29 %/day** | 0.29 mAh/h ≈ 0.006 %/h ≈ 0.14 %/day |
| **Net keepalive-attributable** | **≈ 0.32 mAh/h ≈ 0.15 %/day** | — |
| WiFi radio duty (uid 2000) | Rx 2 s 480 ms + Tx 154 ms of 11 m 36 s = **0.38 %**; sleep 99.6 % | Rx 1 s 717 ms + Tx 300 ms of 9 m 19 s = 0.36 % |
| Bytes (uid 2000 incl. ADB-tunnel noise) | 92.4 KB rx / 72.9 KB tx | 57.5 KB rx / 43.9 KB tx |
| curl CPU (whole window) | 20 ms user + 30 ms kernel | — |

Interpretation: 24 keepalive exchanges over ~11.6 min cost, net of baseline, ~0.07 mAh — **< 0.5 %/day on WiFi**, radio asleep 99 %+ of the time. This matches the theoretical WiFi profile (Qian 2012: ~300 mW during brief wakes, ~250 ms tail).

### 5.4 Forced-Doze probe (demonstration, not a full study)
`dumpsys deviceidle force-idle` → deep idle → device-side `curl wss://…` for 10 s: **no TCP/TLS/WS handshake ever reached the server** (server log empty for the window; curl exited rc=28 timeout). Confirms Doze network suspension applies to even shell-uid traffic on this device. Device restored (`unforce` + stepped to ACTIVE; post-doze HTTPS ping 200 OK, 20.6 ms).

### 5.5 Caveats
- Traffic/battery attribution is to **uid 2000 (adb shell)**, not a normal app uid; the wireless-ADB session adds ~100 KB/10 min of tunnel noise to both runs (cancels in the net delta).
- The keepalive used server-initiated WS PING frames with libcurl auto-PONG (verified pongs in server log). A client-initiated ping has the identical radio profile (small uplink + small downlink per interval).
- Cellular battery was **not measured** (intentionally — did not want to disable the personal device's WiFi/SIM). Protocol below.
- No Doze-vs-FGS-reconnect timing study (full Doze cycle needs 30+ min unattended).

### 5.6 Measurement protocol for later dogfooding (cellular + Doze + real app)
1. **Cellular battery:** disable WiFi (`svc wifi disable`), leave mobile data on; `dumpsys batterystats --reset`; run the WSS-keepalive client (25 s interval) for 60–120 min screen-off on battery; `dumpsys batterystats --charged > bs-cellular.txt`; record uid-attributed mAh (cpu + mobile_radio), "Mobile radio active" time and per-uid "Mobile network" bytes; repeat with 60 s and 300 s intervals; acceptance: attributed drain ≤ 1 %/h at the adopted interval; alert if ≥ 5 %/h (the ntfy-class pathology).
2. **Doze survival:** unplug; `adb shell dumpsys deviceidle force-idle`; run keepalive 30 min; record ping/pong cadence in the relay log (expect long gaps/maintenance-window-only delivery); then `unforce` and measure reconnect latency (time from wake to first pong). Acceptance: reconnect ≤ 10 s after Doze exit; UI surfaces "offline" within one ping interval of silence.
3. **OEM killer reality:** on the Samsung (One UI 8/Android 17): enable the FGS, screen off, 24 h; check `dumpsys activity processes` for the service each morning with default settings vs "Unrestricted" battery + added to "Apps that won't be put to sleep." On a MIUI/HyperOS device: test with Autostart off vs on.
4. **Latency percentile budget:** from the persistent WSS connection, log per-ping RTT for 24 h (WiFi + cellular); acceptance: p50 ≤ 50 ms WiFi / ≤ 250 ms cellular; p99 ≤ 500 ms; the extension's unlock UX should tolerate p99, not p50.

---

## 6. RECOMMENDATION

**Declare `connectedDevice` as the foreground service type for Baluard's unlock-authority service** (both flavors; `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_CONNECTED_DEVICE` permissions, and satisfy the platform prerequisite by declaring `CHANGE_WIFI_STATE` or `CHANGE_WIFI_MULTICAST_STATE` in the manifest). It is the only candidate that (a) explicitly covers "interaction with an external device over a network connection" in the platform docs, (b) has **no runtime time limit** (the 6 h cap hits only `dataSync`/`mediaProcessing`), (c) maps to an existing Play Console use case ("Continuous Data Transfer to an External Device") with a video script Baluard can actually produce (the pairing flow), and (d) has direct precedent — KDE Connect ships exactly this type for its phone↔desktop connection on both Play and F-Droid. Keep the service honest against the FGS policy criteria: user-initiated start, persistent clear notification, one-tap stop.

**Fallbacks if Play rejects `connectedDevice`:** (1) resubmit with the "active session" framing — the FGS runs only while the extension pairing is enabled/connected and the notification says so; (2) `specialUse` with a concrete `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` string ("password manager maintains a user-enabled secure channel to the user's paired desktop browser extension to serve unlock requests; connection cannot be deferred without breaking the feature"), knowing specialUse is subject to case-by-case review with no published approval statistics and anecdotal pushback on deferrable designs; (3) last resort for Play: `dataSync` with a reconnect-on-timeout design (service stops itself at `onTimeout` before the crash, FCM or user foreground-visit resets the 6 h budget) — acceptable for the F-Droid flavor's simplicity but a poor always-on UX for Play users.

**Keepalive: 25 s fixed is acceptable on WiFi only, and should be adaptive overall.** On WiFi the measured cost is ≈ 0.3 %/day attributed (≈ 0.15 %/day net) with 99.6 % radio sleep — effectively free — while RTTs of 16–25 ms (fresh TLS) and 3–7 ms (established path) mean unlock latency is dominated by relay routing, not the phone. On cellular, 25 s sits inside the LTE RRC tail (inactivity ≈ 11.6 s), giving ~50 %+ high-power radio duty; measured reality for exactly this pattern (permanent WSS in an FGS on 4G) is ≈ 5 %/h on affected devices. Ship: 25 s on WiFi/screen-on; 60–120 s background on WiFi; 60–300 s on cellular; treat Doze as a disconnect event (reconnect at the next maintenance window or on wake, show "authority offline"), and offer the user the battery-optimization exemption ("peripheral device companion app" use case) for users who want overnight availability. Confirm the relay's server-side idle timeout is comfortably above the longest adopted interval before raising it. Add an idle-timeout test: hold a WSS connection idle for 300 s through Tailscale Funnel and through Caddy and record whether the intermediary drops it; if it does, cap the cellular keepalive below the measured idle timeout (the 60-300 s cellular intervals have not been tested through any proxy).

---

## 7. Source list (all accessed 2026-11-19/20 unless dated inline)

Primary (developer.android.com / source.android.com — each page footer states its last-update date):
- FGS types: https://developer.android.com/develop/background-work/services/fgs/service-types (upd. 2026-10-28)
- FGS timeouts: https://developer.android.com/develop/background-work/services/fgs/timeout (upd. 2026-10-28)
- FGS changes by version: https://developer.android.com/develop/background-work/services/fgs/changes (upd. 2026-10-28)
- FGS troubleshooting (crash dialog on overrun; prerequisites): https://developer.android.com/develop/background-work/services/fgs/troubleshooting (upd. 2026-11-16)
- User stopping FGS (Task Manager): https://developer.android.com/develop/background-work/services/fgs/handle-user-stopping (accessed 2026-11-19)
- Android 13 behavior changes (dismissible FGS notifications; Task Manager; restricted bucket): https://developer.android.com/about/versions/13/behavior-changes-all, /behavior-changes-13 (upd. 2026-10-28)
- Android 15 behavior changes (dataSync timeout; BOOT_COMPLETED): https://developer.android.com/about/versions/15/behavior-changes-15 (upd. 2026-10-28)
- Android 16 behavior changes (job quotas; Local Network Permission opt-in): https://developer.android.com/about/versions/16/behavior-changes-16 and /behavior-changes-all (upd. 2026-10-28)
- Android 17 behavior changes (ACCESS_LOCAL_NETWORK mandatory; background audio hardening): https://developer.android.com/about/versions/17/behavior-changes-17 (upd. 2026-11-11)
- Doze (AOSP): https://source.android.com/docs/core/power/platform_mgmt (accessed 2026-11-19)
- Doze + exemptions + acceptable use for battery-optimization requests: https://developer.android.com/training/monitoring-device-state/doze-standby (upd. 2026-10-22)

Play policy:
- FGS/FSI declaration process + per-type use cases + video requirements: https://support.google.com/googleplay/android-developer/answer/13392821
- Device and Network Abuse (FGS criteria; exemptions list): https://support.google.com/googleplay/android-developer/answer/9888379
- Data safety form guidance ("collect = transmit off device"): https://support.google.com/googleplay/android-developer/answer/10787469
- Android vitals background network: https://developer.android.com/google/play/vitals/bg-network-usage

Community/anecdotal (labeled as such):
- dontkillmyapp.com/samsung (Samsung One UI ≥6.0 statement dated 07/2024) and /xiaomi (accessed 2026-11-19)
- F-Droid forum on `systemExempted` misuse: https://forum.f-droid.org/t/misuse-of-foreground-service-with-systemexempt-permissions-background-workaround-v-31-0/34514
- KDE Connect manifest (connectedDevice precedent): https://github.com/KDE/kdeconnect-android, master, src/main/AndroidManifest.xml (inspected 2026-11-19 via gh api)
- bond-bunny PR #115 (connectedDevice→dataSync precedent): https://github.com/dimadesu/bond-bunny/pull/115
- ntfy #687 (4G WSS keepalive ≈ 5 %/h, WiFi fine; Signal similar): https://github.com/binwiederhier/ntfy/issues/687 (2023-03-27, updated 2025-02-19)
- StackOverflow specialUse violation anecdote: https://stackoverflow.com/questions/77778015 (2024)

Academic:
- Qian et al., "Periodic Transfers in Mobile Applications," WWW 2012 — https://feng-qian.github.io/paper/periodic_www12.pdf (RRC powers/timers; LTE inactivity 11.6 s; Facebook 1.7 %→30 %)
- Huang et al., "A Close Examination of Performance and Power Characteristics of a 4G LTE Network," MobiSys 2012 — https://feng-qian.github.io/paper/lte_mobisys12.pdf / dl.acm.org/doi/10.1145/2307636.2307658 (DRX parameters)
- Balasubramanian et al., "Energy Consumption in Mobile Phones: A Measurement Study…", MobiSys 2009 — https://people.cs.umass.edu/~arun/papers/TailEnder.pdf (tail energy share)
- Haverinen et al., "Energy Consumption of Always-On Applications in WCDMA Networks," VTC 2007 — http://www.pasieronen.com/publications/haverinen_siren_eronen_vtc2007.pdf (keepalive-specific WCDMA energy)
