# WebKitGTK Frontend Constraints

> Layout rules for the Tauri desktop frontend so the UI renders identically from the WebKitGTK 2.44 floor (Ubuntu 24.04) to current rolling-release engines, plus the incident record and the probe rig that keeps the floor honest. Born from the Arch Linux search-bar misalignment report of 2026-11-11.

---

## The rules

- **Never hang critical layout on absolute positioning.** Flex children cannot fall out of place on any engine; absolutely positioned overlays can. Absolute positioning is reserved for true overlays (modals, dropdowns, backdrops) where a failure degrades visibly but not destructively.
- **Never build abspos placement on logical inset shorthands.** Tailwind v4 emits `inset-y-0` as `inset-block: calc(var(--spacing) * 0)`, `inset-x-0` as `inset-inline`, `inset-0` as `inset`. WebKitGTK has mis-laid abspos elements whose offsets resolve through those shorthands. Physical longhands (`top-0 bottom-0 left-0 right-0`) are the safe spelling where abspos stays.
- **Ancestors with `scale`, `filter`, `transform`, or `will-change` are containing blocks** for every abspos descendant below them. The vault columns carry `scale-100` / `filter-none` at steady state for the vault-switch animation. Overlay math that assumes a nearer positioned ancestor breaks silently when coordinate spaces differ.
- **The engine floor is WebKitGTK 2.44** (Ubuntu 24.04 as shipped). Feature support verified on that floor: cascade layers, `@property`, `color-mix()`, `oklch()`, logical property longhands and shorthands, `translate`/`scale` properties. The floor is not the risk; the GPU and Wayland compositor paths above it are (see incident below).
- **The global `*:focus-visible` outline uses `!important`** (app.css) and cannot be suppressed per element. A focus ring on a composite field is drawn with `focus-within:` on the wrapper; the inner input still draws its own outline inside it.
- **Tailwind v4 utilities assume browsers at Safari 16.4+ / Chrome 111+ / Firefox 128+.** WebKitGTK 2.44 meets that bar. Upgrading Tailwind or adding plugins re-raises the emitted-CSS floor; re-run the probe rig (below) before shipping.

---

## Incident record: search bar icons displaced (2026-11-11)

- **Symptom:** On Arch Linux, the vault search bar rendered with the magnifier pinned to the input's bottom edge and the clear button in flow on the line below, left-aligned. macOS, Windows, and other Linux machines were unaffected.
- **Diagnosis:** The clear button rendered at its static in-flow position: both its abspos offsets resolved to `auto`, so the overlay lost its placement while `position: absolute` itself applied. The icon kept `left` and `bottom` but lost `top`. Same stylesheet, per-element divergence, only in the real app.
- **Eliminated causes:** Not a feature gap. The shipped CSS renders correctly on WebKitGTK 2.42.2, 2.44.0, 2.52.6, and 2.54.2 in plain-webview probes, at device scale 1 and 2, and in the real app under Xvfb on Fedora. The failing variable is the real-app GPU/Wayland compositor path (report machine ran fractional scaling, ~150%).
- **Fix:** The search bar (`VaultView.jsx`) no longer uses abspos at all. A `flex items-center` wrapper owns border, background, rounding, and `focus-within:border-primary`; the icon is a `shrink-0` flex child, the input is `flex-1 min-w-0`, the clear button is a static `pr-3 shrink-0` child that mounts and unmounts without layout risk.
- **Guard:** `e2e/desktop/search-align.mjs` unlocks the seeded vault, types a query, and asserts both icons are static flex children, aligned to the row, and inside the bar. Run it with `e2e/desktop/run-e2e-desktop.sh search-align.mjs`. It fails if anyone reintroduces overlay positioning there.

---

## The probe rig

Plain-webview geometry probes catch engine-feature gaps deterministically; they do not reproduce compositor-specific faults. Use them to answer "does this CSS construct work on engine X", not "does this app render right on every GPU".

```bash
# Floor engine: WebKitGTK 2.44.0 exactly as Ubuntu 24.04 shipped it.
docker run -d --name webkit-noble ubuntu:noble sleep infinity
docker exec webkit-noble apt-get update -qq
docker exec webkit-noble apt-get install -y --no-install-recommends \
  libwebkit2gtk-4.1-0=2.44.0-2 libjavascriptcoregtk-4.1-0=2.44.0-2 \
  gir1.2-webkit2-4.1=2.44.0-2 gir1.2-javascriptcoregtk-4.1=2.44.0-2 \
  xvfb xauth dbus-x11 python3-gi ca-certificates fonts-dejavu-core
# Older still: Debian 12 as shipped (2.42.x) via snapshot.debian.org.
echo "deb [trusted=yes] http://snapshot.debian.org/archive/debian/20240101T000000Z/ bookworm main" \
  > /etc/apt/sources.list.d/snapshot.list   # inside the container
# Then: copy a static HTML replica + the built stylesheet in, and measure
# element rects from python3-gi after load (WebKit2.run_javascript).
# Sandbox note: WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 is required in containers.
```

- The real-app check is the e2e harness: `run-e2e-desktop.sh` seeds a sandbox vault, serves the frontend with vite, and drives the actual WebKitGTK webview through tauri-driver under Xvfb. It rebuilds the daemon, CLI, and desktop binary before each run; if the desktop build fails, build it by hand with `cargo build --manifest-path desktop/src-tauri/Cargo.toml`.
