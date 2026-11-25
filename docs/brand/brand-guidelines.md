# Baluard Brand

> Central reference for visual identity: colors, tokens, and design rules.

**Machine-readable tokens:** [design-language-tokens.json](design-language-tokens.json)
**CSS source of truth:** `desktop/src/app.css`

---

## Colors

Do not introduce ad-hoc colors. Extend tokens here first, then reference the CSS variable.

## Dark Mode: Deep Forest Teal / Soft Lavender / Lime Accent

| Token | Hex | Swatch | Role |
|---|---|---|---|
| `--color-bg` | `#091315` | 🟩 | Page background |
| `--color-sidebar` | `#0f2022` | 🟩 | Sidebar surface |
| `--color-list` | `#14292c` | 🟩 | Cipher list pane |
| `--color-detail` | `#193236` | 🟩 | Detail/editor pane |
| `--color-card` | `#0b1517` | 🟩 | Cards within surfaces |
| `--color-surface` | `#193236` | 🟩 | Raised surfaces (derived: detail elevation) |
| `--color-border` | `#1d3a3d` | 🟩 | Default borders |
| `--color-border-focus` | `#b3e55c` | 🟩 | Focus ring / active border |
| `--color-text` | `#f3f4f6` | ⬜ | Primary text |
| `--color-text-secondary` | `#d3ddde` | 🟩 | Secondary text (derived: between text and muted) |
| `--color-text-muted` / `--color-muted` | `#a2b7ba` | 🟩 | Secondary/placeholder text (derived) |
| `--color-primary` | `#b3e55c` | 🟩 | Primary action (lime green) |
| `--color-primary-text` | `#102427` | 🟩 | Text on primary |
| `--color-primary-hover` | `#c5f279` | 🟩 | Primary hover state |
| `--color-accent` | `#cfc6f9` | 🟩 | Accent/highlight (lavender) |
| `--color-warning` | `#fcd34d` | 🟨 | Warning states (derived: dark warning tone) |
| `--color-danger` | `#ef4444` | 🟥 | Destructive actions |
| `--color-danger-strong` | `#f87171` | 🟥 | Danger text/icons on tinted surfaces |
| `--color-success` | `#10b981` | 🟩 | Success states |
| `--color-primary-strong` | `#b3e55c` | 🟩 | Primary text/icons on tinted surfaces |
| `--color-accent-strong` | `#cfc6f9` | 🟩 | Accent text/icons on tinted surfaces |

Dark aliases the base tones for the `strong` variants; they already clear 4.5:1 everywhere. The four tokens the legacy terminal palette never declared (`surface`, `text-secondary`, `text-muted`/`muted`, `warning`) are derived in-family.

## Light Mode: Catppuccin Latte / Green Accent (WCAG 2.2 AA)

| Token | Hex | Swatch | Role |
|---|---|---|---|
| `--color-bg` | `#eff1f5` | ⬜ | Page background (Latte Base) |
| `--color-sidebar` | `#e6e9ef` | ⬜ | Sidebar surface (Mantle) |
| `--color-list` | `#dce0e8` | ⬜ | Cipher list pane (Crust) |
| `--color-detail` | `#ccd0da` | ⬜ | Detail/editor pane (Surface0) |
| `--color-card` | `#e6e9ef` | ⬜ | Cards within surfaces (Mantle) |
| `--color-surface` | `#ccd0da` | ⬜ | Raised surfaces (Surface0) |
| `--color-border` | `#bcc0cc` | ⬜ | Default borders (Surface1) |
| `--color-border-focus` | `#256015` | 🟩 | Focus ring / active border (green, >= 3:1 on all surfaces) |
| `--color-text` | `#4c4f69` | 🟩 | Primary text (Latte Text) |
| `--color-text-secondary` | `#5c5f77` | 🟩 | Secondary text (Subtext1) |
| `--color-text-muted` / `--color-muted` | `#55586a` | 🟩 | Muted text (darkened Subtext0: 4.5:1 on every surface) |
| `--color-primary` | `#40a02b` | 🟩 | Primary action (Latte green; FILL token for buttons/fills) |
| `--color-primary-text` | `#102427` | 🟩 | Text on primary (dark text on green fills) |
| `--color-primary-hover` | `#55b83b` | 🟩 | Primary hover state (green tint) |
| `--color-accent` | `#66bf4f` | 🟩 | Accent/highlight (soft green companion; FILL token, totp bar) |
| `--color-warning` | `#7c4d0d` | 🟨 | Warning states (yellow darkened to 4.5:1 on all surfaces) |
| `--color-danger` | `#b70f2a` | 🟥 | Destructive actions (red darkened: text >= 4.5:1, white on fill 6.7:1) |
| `--color-danger-strong` | `#a90e26` | 🟥 | Danger text/icons (4.9:1 even on detail) |
| `--color-success` | `#40a02b` | 🟩 | Success states (green) |
| `--color-primary-strong` | `#256015` | 🟩 | Primary text/icons (4.9-6.7:1 on all four surfaces) |
| `--color-accent-strong` | `#256015` | 🟩 | Accent text/icons on tinted surfaces |

Light darkens the green family for `strong` variants so text on tinted surfaces passes WCAG 1.4.3. `desktop/src/app.css` is the runtime source of truth; [design-language-tokens.json](design-language-tokens.json) mirrors it.

## Semantic Tokens (shared across themes)

| Token | Purpose |
|---|---|
| `--color-danger` | Error states, delete actions, validation failures |
| `--color-success` | Confirmations, health score improvements, saved indicators |

## Rules

1. **No hardcoded hex in components.** Always use `var(--color-*)`.
2. **New token?** Add it to both palettes here and in `app.css` simultaneously.
3. **Contrast check.** Any new foreground/background pair must pass WCAG AA (4.5:1 for normal text, 3:1 for large text).
4. **Dark-first design.** Dark mode is the default (`:root`). Light mode overrides via `.light-theme`.
5. **Semantic over decorative.** Use `--color-primary` for actions, not because you like the shade.

## Extending the Palette

When adding a token, follow this checklist:

- [ ] Name describes semantic role, not the color value (`--color-warning`, not `--color-amber`)
- [ ] Added to both `:root` (dark) and `.light-theme` blocks in `app.css`
- [ ] Documented in the tables above
- [ ] Contrast ratio verified against the surface it sits on

## Animation Guidelines

Keep animations subtle, micro, and composited (relying on `opacity` and `transform`). Avoid layout-shifts and heavy JS runtimes.

### Standard Conventions

1. **Shared Motion Components**
   - Use the `motion-*` classes and `--motion-*` timing tokens defined in `desktop/src/app.css`.
   - `.motion-dropdown` covers menus and inline disclosures, `.motion-modal` covers dialog entrances, `.motion-fade` covers content changes, and `.motion-fade-up` covers initial screens.
   - Use `.motion-window-morph` for container resizing and `.motion-vault-switch` for vault pane transitions.
2. **Screen/Page Transitions**
   - Use `<Transition name="fade" mode="out-in">` with the `.fade-*` classes in `desktop/src/app.css`.
3. **Details & Editor Panes**
   - Use `<Transition name="slide" mode="out-in">` to keep side panel context changes smooth without jarring state jumps.
4. **Modal/Dialog Overlays**
   - Use `<Transition name="fade">` to smoothly dim the screen backing and `.motion-modal` for the dialog container.
5. **Grow and Shrink Reveals**
   - Use `<Transition name="reveal-grow">` for expandable content such as recovery codes.
   - All shared motion components include reduced-motion behavior.
