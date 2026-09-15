import { Show } from "solid-js";

/**
 * Primitive components to standardize accessibility, styling, and interactivity.
 */

export function Button(props) {
  return (
    <button
      type={props.type || "button"}
      onClick={props.onClick}
      disabled={props.disabled}
      class={`px-4 py-2 rounded-xl text-sm font-semibold transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)] active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed ${
        props.variant === "primary"
          ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] hover:bg-[var(--color-primary-hover)]"
          : props.variant === "danger"
          ? "bg-[var(--color-danger)] text-white hover:opacity-90"
          : "bg-[var(--color-sidebar)] text-[var(--color-text)] border border-[var(--color-border)] hover:border-[var(--color-text)]"
      } ${props.class || ""}`}
      aria-label={props["aria-label"]}
      title={props.title}
    >
      {props.children}
    </button>
  );
}

export function Input(props) {
  return (
    <input
      type={props.type || "text"}
      id={props.id}
      name={props.name}
      value={props.value}
      onInput={props.onInput}
      onBlur={props.onBlur}
      placeholder={props.placeholder}
      class={`w-full px-3 py-2 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-sm text-[var(--color-text)] placeholder-[var(--color-muted)] outline-none focus:border-[var(--color-primary)] focus-visible:ring-2 focus-visible:ring-[var(--color-primary)] ${props.class || ""}`}
      autocomplete={props.autocomplete}
      disabled={props.disabled}
      aria-label={props["aria-label"]}
      aria-describedby={props["aria-describedby"]}
      aria-invalid={props["aria-invalid"]}
    />
  );
}
