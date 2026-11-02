# ADR 0015. Modal Accessibility

> Status: Accepted (completed 2026-06-09)

## Context

Modal interactions require keyboard and focus behavior that supports assistive technology and users who navigate without a pointer. Without a shared mechanism, each modal reimplemented, or omitted, focus containment and Escape handling.

## Decision

All modals use the reusable `<FocusTrap containerRef={ref} onEscape={fn} />` component, and every modal must satisfy the following contract:

- The modal container carries `role="dialog"`, `aria-modal="true"`, `aria-labelledby`, and where a description exists `aria-describedby`.
- Tab and Shift+Tab are trapped within the container.
- Escape dismisses the modal through the required `onEscape` callback.
- The first interactive element receives focus on mount.
- Focus returns to the element that had it before the modal opened when the modal unmounts.

The original design described `FocusTrap` as providing the dialog and ARIA attributes. In the implementation, `FocusTrap` is a renderless component that provides only the keyboard and focus behavior (trap, Escape, initial focus, focus restore); the dialog and ARIA attributes are written on each modal's container markup, and shared wrappers (`ConfirmModal`, `ConsolePanel`) write them once for the modals built on them. `containerRef` accepts either an element or a getter, because some containers can be located only after render.

The component was first applied to the DeleteConfirm, ArchiveConfirm, Reprompt, Generator, Settings, and EmptyTrash modals. It has since been extended to the setup screen (ADR 0020), the tag-deletion modal (ADR 0018), and later dialogs such as the vault switch unlock, detach, sharing, legacy contact, and conflict resolution surfaces.

## Consequences

Modal keyboard focus is contained while the modal is open and returns to the invoking control when it closes. Adding a modal means rendering `FocusTrap` and writing the ARIA attributes on the container; a modal that skips either is non-compliant. Because the trap queries only visible, enabled focusable elements, a modal with no focusable element is not trapped.

## References

- `<FocusTrap>` in `desktop/src/components/FocusTrap.jsx`
- ADR 0093 for the conflict panel, which uses the same component.
