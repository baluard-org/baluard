// Global pointer down listener for Material-style tactile ripple feedback.
// Runs on the capture phase to animate instantly before state re-renders.
// Purely CSS-driven (transform and opacity) for optimal performance.

export function initRipple() {
  document.addEventListener("pointerdown", (e) => {
    // Only trigger on main mouse button or touch/pen
    if (e.button !== 0 && e.pointerType === "mouse") return;

    const target = e.target.closest("button, [role='button'], .cursor-pointer, [data-ripple]");
    if (!target || target.disabled || target.getAttribute("aria-disabled") === "true") return;

    // Skip inputs that aren't buttons
    if (target.tagName === "INPUT" && !["button", "submit", "reset"].includes(target.type)) return;

    if (!target.hasAttribute("data-ripple")) {
      target.setAttribute("data-ripple", "");
    }

    // The ripple span is absolutely positioned and needs the target as its
    // containing block. Only give UNPOSITIONED targets one — overriding a
    // fixed or absolute button demotes it to relative and its insets become
    // relative shifts (the theme toggle lost its corner on first press).
    if (getComputedStyle(target).position === "static") {
      target.style.position = "relative";
    }

    const rect = target.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = e.clientX - rect.left - size / 2;
    const y = e.clientY - rect.top - size / 2;

    const ripple = document.createElement("span");
    ripple.className = "ripple-element";
    ripple.style.width = `${size}px`;
    ripple.style.height = `${size}px`;
    ripple.style.left = `${x}px`;
    ripple.style.top = `${y}px`;

    // Ensure ripple is painted on top if the element uses isolated stacking
    ripple.style.zIndex = "0";

    target.appendChild(ripple);

    setTimeout(() => {
      ripple.remove();
    }, 550);
  }, { passive: true, capture: true });
}
