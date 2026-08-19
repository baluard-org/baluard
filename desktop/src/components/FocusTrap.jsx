import { onSettled, onCleanup } from "solid-js";

/**
 * Trap keyboard focus inside a modal dialog.
 *
 * Usage (inside a <Show when={open}>):
 *   <div ref={containerRef} ...>
 *     <FocusTrap />
 *     ...modal content...
 *   </div>
 *
 * Provides:
 * - Tab/Shift+Tab trapped within the container
 * - Escape closes via props.onEscape (required)
 * - Auto-focuses the first focusable element on mount
 */
export default function FocusTrap(props) {
  let previouslyFocused = null;

  function getFocusable(container) {
    if (!container) return [];
    const sel = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    return [...container.querySelectorAll(sel)].filter(el => el.offsetParent !== null);
  }

  function handleKeyDown(e) {
    const container = e.currentTarget;

    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      props.onEscape?.();
      return;
    }

    if (e.key === "Tab") {
      const focusable = getFocusable(container);
      if (!focusable.length) { e.preventDefault(); return; }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }
  }

  onSettled(() => {
    previouslyFocused = document.activeElement;
    const container = props.containerRef;
    if (!container) return;

    container.addEventListener("keydown", handleKeyDown);

    // Auto-focus first focusable element
    const focusable = getFocusable(container);
    if (focusable.length) {
      // If there's a primary action (last button in the button group), focus that
      // Otherwise focus the first focusable element
      focusable[0].focus();
    }
  });

  onCleanup(() => {
    const container = props.containerRef;
    if (container) container.removeEventListener("keydown", handleKeyDown);
    // Restore focus to whatever had it before the modal opened
    if (previouslyFocused && typeof previouslyFocused.focus === "function") {
      previouslyFocused.focus();
    }
  });

  return null;
}
