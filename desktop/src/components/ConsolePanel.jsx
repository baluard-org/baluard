import { Show } from "solid-js";
import { Portal } from "solid-js/web";
import FocusTrap from "./FocusTrap.jsx";

/**
 * A reusable sliding top-down console panel (Quake 3 console feel).
 * Used for forced actions and high-priority prompts.
 *
 * Props:
 * - show (boolean, required): Whether to show the panel
 * - accentClass (string): Tailwind border color class for bottom accent line (default: "border-amber-500")
 * - minHeightClass (string): Tailwind min-height class (default: "min-h-[24rem]")
 * - onEscape (function): Optional escape key handler
 * - role (string): ARIA role (default: "dialog")
 * - ariaLabelledby (string): ARIA label element ID
 * - ariaDescribedby (string): ARIA description element ID
 * - children (JSX): Content to render inside the panel
 */
export default function ConsolePanel(props) {
  let panelRef;

  const accentClass = () => props.accentClass ?? "border-amber-500";
  const minHeightClass = () => props.minHeightClass ?? "min-h-[24rem]";
  const role = () => props.role ?? "dialog";

  return (
    <Show when={props.show}>
      <Portal>
        <div class="fixed inset-0 z-50">
          {/* Backdrop: blocks interaction */}
          <div class="absolute inset-0 bg-black/60 backdrop-blur-[2px]" />

          {/* Panel body: slides down from the very top */}
          <div
            ref={panelRef}
            class={`animate-console-panel absolute top-0 left-0 right-0 w-full ${minHeightClass()} bg-[var(--color-sidebar)]/95 border-b-4 ${accentClass()} shadow-[0_20px_50px_rgba(0,0,0,0.6)] z-50 overflow-hidden text-[var(--color-text)]`}
            role={role()}
            aria-modal="true"
            aria-labelledby={props.ariaLabelledby}
            aria-describedby={props.ariaDescribedby}
          >
            <FocusTrap
              containerRef={panelRef}
              onEscape={() => props.onEscape?.()}
            />
            
            <div class="w-full flex justify-center pt-12 pb-6 px-6 md:px-12">
              <div class="w-full max-w-5xl relative z-10">
                {props.children}
              </div>
            </div>
          </div>
        </div>
      </Portal>
    </Show>
  );
}
