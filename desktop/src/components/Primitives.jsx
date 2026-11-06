import { Show } from "solid-js";

/**
 * Primitive components to standardize accessibility, styling, and interactivity.
 */

export function Button(props) {
  return (
    <button
      type={props.type || "button"}
      data-testid={props["data-testid"]}
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
      data-testid={props["data-testid"]}
    />
  );
}

export function Toggle(props) {
  let inputRef;
  const isChecked = () => (typeof props.checked === "function" ? props.checked() : !!props.checked);

  return (
    <label
      class={`inline-flex items-center justify-between gap-3 cursor-pointer select-none group ${
        props.disabled ? "opacity-50 cursor-not-allowed pointer-events-none" : ""
      } ${props.class || ""}`}
    >
      <Show when={props.label || props.description}>
        <div class="flex flex-col flex-1 pr-2">
          <Show when={props.label}>
            <span class="text-xs font-semibold text-[var(--color-text)] leading-tight">
              {props.label}
            </span>
          </Show>
          <Show when={props.description}>
            <span class="text-[11px] text-[var(--color-muted)] mt-0.5 leading-normal">
              {props.description}
            </span>
          </Show>
        </div>
      </Show>
      <span class="relative inline-flex items-center shrink-0">
        <input
          ref={inputRef}
          type="checkbox"
          id={props.id}
          name={props.name}
          data-testid={props["data-testid"]}
          checked={isChecked()}
          disabled={props.disabled}
          onChange={props.onChange}
          class="sr-only peer"
          role="switch"
          aria-checked={isChecked() ? "true" : "false"}
          aria-label={props["aria-label"] || (typeof props.label === "string" ? props.label : undefined)}
        />
        <div
          class={`relative inline-flex items-center h-6 w-11 shrink-0 rounded-full transition-colors duration-200 ease-in-out border border-transparent peer-focus-visible:ring-2 peer-focus-visible:ring-[var(--color-primary)] peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-[var(--color-bg)] ${
            isChecked()
              ? props.variant === "danger"
                ? "bg-[var(--color-danger)]"
                : "bg-[var(--color-primary)]"
              : "bg-[var(--color-sidebar)] border-[var(--color-border)] group-hover:border-[var(--color-muted)]/50"
          }`}
        >
          <span
            class={`pointer-events-none inline-block h-4 w-4 rounded-full shadow-md transform transition-transform duration-200 ease-out ${
              isChecked()
                ? "translate-x-6 " + (props.variant === "danger" ? "bg-white" : "bg-[var(--color-primary-text)]")
                : "translate-x-1 bg-[var(--color-muted)] group-hover:bg-[var(--color-text)]"
            }`}
          />
        </div>
      </span>
    </label>
  );
}

export { Toggle as Switch };
