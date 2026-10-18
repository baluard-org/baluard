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
| `--color-border` | `#1d3a3d` | 🟩 | Default borders |
| `--color-border-focus` | `#b3e55c` | 🟩 | Focus ring / active border |
| `--color-text` | `#f3f4f6` | ⬜ | Primary text |
| `--color-muted` | `#8fa3a6` | 🟩 | Secondary/placeholder text |
| `--color-primary` | `#b3e55c` | 🟩 | Primary action (lime green) |
| `--color-primary-text` | `#102427` | 🟩 | Text on primary |
| `--color-primary-hover` | `#c5f279` | 🟩 | Primary hover state |
| `--color-accent` | `#cfc6f9` | 🟩 | Accent/highlight (lavender) |
| `--color-danger` | `#ef4444` | 🟥 | Destructive actions |
| `--color-success` | `#10b981` | 🟩 | Success states |

## Light Mode: Catppuccin Latte / Green Accent

| Token | Hex | Swatch | Role |
|---|---|---|---|
| `--color-bg` | `#eff1f5` | ⬜ | Page background (Latte Base) |
| `--color-sidebar` | `#e6e9ef` | ⬜ | Sidebar surface (Mantle) |
| `--color-list` | `#dce0e8` | ⬜ | Cipher list pane (Crust) |
| `--color-detail` | `#ccd0da` | ⬜ | Detail/editor pane (Surface0) |
| `--color-card` | `#e6e9ef` | ⬜ | Cards within surfaces (Mantle) |
| `--color-border` | `#bcc0cc` | ⬜ | Default borders (Surface1) |
| `--color-border-focus` | `#40a02b` | 🟩 | Focus ring / active border (green) |
| `--color-text` | `#4c4f69` | 🟩 | Primary text (Latte Text) |
| `--color-muted` | `#6c6f85` | 🟩 | Secondary/placeholder text (Subtext0) |
| `--color-primary` | `#40a02b` | 🟩 | Primary action (Latte green) |
| `--color-primary-text` | `#eff1f5` | ⬜ | Text on primary (Base; green fills) |
| `--color-primary-hover` | `#55b83b` | 🟩 | Primary hover state (green tint) |
| `--color-accent` | `#66bf4f` | 🟩 | Accent/highlight (soft green) |
| `--color-danger` | `#d20f39` | 🟥 | Destructive actions (Latte red) |
| `--color-success` | `#40a02b` | 🟩 | Success states (green) |
| `--color-surface` | `#ccd0da` | ⬜ | Raised surfaces (Surface0) |
| `--color-text-secondary` | `#5c5f77` | 🟩 | Secondary text (Subtext1) |
| `--color-text-muted` | `#6c6f85` | 🟩 | Muted text (Subtext0) |
| `--color-warning` | `#df8e1d` | 🟨 | Warning states (Latte yellow) |
| `--color-surface` | `#193236` | 🟩 | Raised surfaces (derived: detail elevation) |
| `--color-text-secondary` | `#d3ddde` | 🟩 | Secondary text (derived) |
| `--color-text-muted` | `#a2b7ba` | 🟩 | Muted text (derived) |
| `--color-warning` | `#fcd34d` | 🟨 | Warning states (derived) |

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

1. **Screen/Page Transitions**
   - Use `<Transition name="fade" mode="out-in">` (200ms cubic-bezier).
   - Class triggers defined in `desktop/src/app.css` under `.fade-*`.
2. **Details & Editor Panes**
   - Use `<Transition name="slide" mode="out-in">` (150ms cubic-bezier).
   - Keeps side panel context changes smooth without jarring state jumps.
3. **Modal/Dialog Overlays**
   - Use `<Transition name="fade">` to smoothly dim screen backing and pop container.
4. **Entrance/Welcome Animations**
   - Use `.animate-fade-in-up` (450ms cubic-bezier(0.16, 1, 0.3, 1)) for initial screens like `LoginScreen`.

