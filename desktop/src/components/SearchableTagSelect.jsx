import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import { IconX } from "./Icon.jsx";

export default function SearchableTagSelect(props) {
  let inputRef;
  const [query, setQuery] = createSignal("");
  const [open, setOpen] = createSignal(false);
  const [activeIndex, setActiveIndex] = createSignal(0);
  const values = () => props.values || [];
  const selected = createMemo(() => values()
    .map((value) => props.options.find((option) => option.value === value))
    .filter(Boolean));
  const results = createMemo(() => {
    const needle = query().trim().toLocaleLowerCase();
    if (!needle) return [];
    return props.options
      .filter((option) => !values().includes(option.value))
      .filter((option) => `${option.label} ${option.description || ""}`.toLocaleLowerCase().includes(needle))
      .slice(0, 8);
  });

  createEffect(
    () => [props.options, values(), props.onChange],
    ([options, current, onChange]) => {
      const available = new Set(options.map((option) => option.value));
      const next = current.filter((value) => available.has(value));
      if (next.length !== current.length) onChange(next);
    },
  );

  function select(option) {
    props.onChange([...values(), option.value]);
    setQuery("");
    setActiveIndex(0);
    setOpen(false);
    inputRef?.focus();
  }

  function remove(value) {
    props.onChange(values().filter((item) => item !== value));
    inputRef?.focus();
  }

  function onKeyDown(event) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (!query().trim() || results().length === 0) return;
      const direction = event.key === "ArrowDown" ? 1 : -1;
      if (!open()) {
        setOpen(true);
        setActiveIndex(direction === 1 ? 0 : results().length - 1);
        return;
      }
      setOpen(true);
      setActiveIndex((index) => (index + direction + results().length) % results().length);
      return;
    }
    if (event.key === "Enter" && open() && results().length > 0) {
      event.preventDefault();
      select(results()[activeIndex()] || results()[0]);
      return;
    }
    if (event.key === "Escape") {
      setOpen(false);
      return;
    }
    if (event.key === "Backspace" && !query() && values().length > 0) {
      remove(values()[values().length - 1]);
    }
  }

  return (
    <div
      class="relative"
      onFocusOut={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <div class="flex flex-wrap items-center gap-1.5 px-2.5 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] focus-within:border-[var(--color-primary)] transition-colors">
        <For each={selected()}>
          {(option) => (
            <span class="inline-flex items-center gap-1 max-w-full px-2 py-1 rounded-md bg-[var(--color-sidebar)] text-[11px] text-[var(--color-text)]">
              <span class="truncate">{option.label}</span>
              <button
                type="button"
                class="shrink-0 p-0.5 rounded text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
                aria-label={`${props.removeLabel} ${option.label}`}
                disabled={props.disabled}
                onClick={() => remove(option.value)}
              >
                <IconX class="w-3 h-3" />
              </button>
            </span>
          )}
        </For>
        <input
          ref={inputRef}
          id={props.id}
          type="text"
          role="combobox"
          aria-expanded={open() && query().trim().length > 0}
          aria-controls={`${props.id}-results`}
          aria-autocomplete="list"
          aria-activedescendant={open() && results().length > 0 ? `${props.id}-option-${activeIndex()}` : undefined}
          autocomplete="off"
          class="flex-1 min-w-[120px] px-1 py-0.5 bg-transparent text-xs text-[var(--color-text)] placeholder:text-[var(--color-muted)] outline-none"
          placeholder={props.placeholder}
          value={query()}
          disabled={props.disabled}
          onFocus={() => setOpen(true)}
          onInput={(event) => {
            setQuery(event.currentTarget.value);
            setActiveIndex(0);
            setOpen(true);
          }}
          onKeyDown={onKeyDown}
        />
      </div>
      <Show when={open() && query().trim().length > 0}>
        <div
          id={`${props.id}-results`}
          role="listbox"
          aria-label={props.resultsLabel}
          aria-multiselectable="true"
          class="motion-dropdown absolute left-0 right-0 top-full mt-1.5 z-50 max-h-56 overflow-y-auto rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] shadow-xl p-1.5"
        >
          <Show
            when={results().length > 0}
            fallback={<p class="px-3 py-2.5 text-xs text-[var(--color-muted)]">{props.noResultsLabel}</p>}
          >
            <For each={results()}>
              {(option, index) => (
                <button
                  id={`${props.id}-option-${index()}`}
                  type="button"
                  role="option"
                  aria-selected="false"
                  tabindex="-1"
                  class={`w-full px-3 py-2.5 rounded-lg text-left cursor-pointer transition-colors ${
                    activeIndex() === index()
                      ? "bg-[var(--color-sidebar)] text-[var(--color-text)]"
                      : "text-[var(--color-text)] hover:bg-[var(--color-sidebar)]"
                  }`}
                  onMouseDown={(event) => event.preventDefault()}
                  onMouseEnter={() => setActiveIndex(index())}
                  onClick={() => select(option)}
                >
                  <span class="block text-xs font-medium">{option.label}</span>
                  <Show when={option.description}>
                    <span class="block text-[10px] text-[var(--color-muted)] mt-0.5 truncate">{option.description}</span>
                  </Show>
                </button>
              )}
            </For>
          </Show>
        </div>
      </Show>
    </div>
  );
}
