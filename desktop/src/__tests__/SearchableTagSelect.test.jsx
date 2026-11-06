import { createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, waitFor } from "@solidjs/testing-library";
import SearchableTagSelect from "../components/SearchableTagSelect.jsx";

const options = [
  { value: "alpha", label: "Alpha login" },
  { value: "beta", label: "Beta card" },
  { value: "gamma", label: "Gamma note" },
];

function props(overrides = {}) {
  return {
    id: "entries",
    options,
    values: [],
    onChange: vi.fn(),
    placeholder: "Search entries",
    noResultsLabel: "No matches",
    removeLabel: "Remove",
    resultsLabel: "Entries",
    ...overrides,
  };
}

describe("SearchableTagSelect", () => {
  it("shows only matching results after the user types", async () => {
    const rendered = render(() => <SearchableTagSelect {...props()} />);
    const input = rendered.getByRole("combobox");
    fireEvent.focus(input);
    expect(rendered.queryByRole("option")).toBeNull();
    fireEvent.input(input, { target: { value: "beta" } });
    await waitFor(() => expect(rendered.getAllByRole("option")).toHaveLength(1));
    expect(rendered.getByRole("option").textContent).toContain("Beta card");
    expect(rendered.getByRole("option").getAttribute("tabindex")).toBe("-1");
    expect(rendered.getByRole("listbox", { name: "Entries" })).toBeTruthy();
  });

  it("selects multiple results as removable tags", async () => {
    const onChange = vi.fn();
    const rendered = render(() => <SearchableTagSelect {...props({ values: ["alpha"], onChange })} />);
    fireEvent.click(rendered.getByRole("button", { name: "Remove Alpha login" }));
    expect(onChange).toHaveBeenCalledWith([]);
    const input = rendered.getByRole("combobox");
    fireEvent.input(input, { target: { value: "beta" } });
    await waitFor(() => expect(rendered.getByRole("option")).toBeTruthy());
    fireEvent.click(rendered.getByRole("option"));
    expect(onChange).toHaveBeenCalledWith(["alpha", "beta"]);
  });

  it("keeps tag order aligned with selection order", () => {
    const rendered = render(() => <SearchableTagSelect {...props({ values: ["gamma", "alpha"] })} />);
    const tags = rendered.getAllByRole("button", { name: /^Remove / });
    expect(tags[0].getAttribute("aria-label")).toBe("Remove Gamma note");
    expect(tags[1].getAttribute("aria-label")).toBe("Remove Alpha login");
  });

  it("prunes values that are no longer available", async () => {
    const onChange = vi.fn();
    const [values, setValues] = createSignal(["missing"]);
    render(() => (
      <SearchableTagSelect
        {...props({
          values: values(),
          onChange: (next) => {
            onChange(next);
            setValues(next);
          },
        })}
      />
    ));
    await waitFor(() => expect(onChange).toHaveBeenCalledWith([]));
  });

  it("opens a closed result list at the first option", async () => {
    const onChange = vi.fn();
    const rendered = render(() => <SearchableTagSelect {...props({ onChange })} />);
    const input = rendered.getByRole("combobox");
    fireEvent.input(input, { target: { value: "alpha" } });
    await waitFor(() => expect(rendered.getByRole("option")).toBeTruthy());
    fireEvent.keyDown(input, { key: "Escape" });
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(["alpha"]));
  });

  it("disables selected-tag removal while busy", () => {
    const rendered = render(() => <SearchableTagSelect {...props({ values: ["alpha"], disabled: true })} />);
    expect(rendered.getByRole("button", { name: "Remove Alpha login" }).disabled).toBe(true);
  });

  it("supports keyboard result selection", async () => {
    const onChange = vi.fn();
    const rendered = render(() => <SearchableTagSelect {...props({ onChange })} />);
    const input = rendered.getByRole("combobox");
    fireEvent.input(input, { target: { value: "a" } });
    await waitFor(() => expect(rendered.getAllByRole("option").length).toBeGreaterThan(1));
    fireEvent.keyDown(input, { key: "ArrowDown" });
    await waitFor(() => expect(input.getAttribute("aria-activedescendant")).toBe("entries-option-1"));
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(["beta"]));
  });
});
