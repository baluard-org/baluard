// Regression tests for the schema-driven Add/Edit form sections
// (identity, bank account, driver license, passport, signing key).
// Solid 2's <For> recreates every row when `each` yields fresh item
// identities; layoutRows() built new arrays per call and tracked the
// whole-object newCipher signal, so one keystroke destroyed the focused
// input. flush() is required after each simulated keystroke — Solid 2
// defers signal writes.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { createSignal, flush } from "solid-js";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k) => k, locale: () => "en", setLocale: vi.fn() }),
  I18nProvider: (props) => props.children,
}));

const daemonMock = vi.fn();
vi.mock("../lib/daemon.js", () => ({ daemon: (...args) => daemonMock(...args) }));

import AddEditCipherForm from "../components/AddEditCipherForm.jsx";

function inputForLabel(container, labelText) {
  const label = Array.from(container.querySelectorAll("label")).find(
    (l) => l.textContent === labelText
  );
  expect(label, `label ${labelText} not found`).toBeTruthy();
  // The label sits in a header sub-div; climb to the field wrapper that
  // owns the input.
  let scope = label.parentElement;
  while (scope && !scope.querySelector("input, textarea")) scope = scope.parentElement;
  return scope?.querySelector("input, textarea") || null;
}

describe("AddEditCipherForm schema-field focus retention", () => {
  beforeEach(() => {
    daemonMock.mockReset();
    daemonMock.mockImplementation((action) => {
      if (action === "settings.get") return Promise.resolve("{}");
      return Promise.resolve("{}");
    });
  });

  function setup(cipherType) {
    const [cipher, setCipher] = createSignal({ cipherType, name: "" });
    const props = {
      newCipher: cipher,
      setNewCipher: (v) => setCipher(v),
      isEdit: false,
      folders: [],
      tags: [],
      onSave: vi.fn(),
      onCancel: vi.fn(),
    };
    return { ...render(() => <AddEditCipherForm {...props} />), setCipher };
  }

  it("identity text input keeps the same DOM node across keystrokes", () => {
    const { container, unmount } = setup("identity");
    const input = inputForLabel(container, "fields.firstName");
    input.focus();
    expect(document.activeElement).toBe(input);

    let typed = "";
    for (const ch of ["a", "b", "c"]) {
      typed += ch;
      fireEvent.input(input, { target: { value: typed } });
      flush();
      expect(document.activeElement, `focus lost after '${ch}'`).toBe(input);
      // activeElement alone could pass if a recreated node got refocused;
      // prove the original node survived.
      expect(inputForLabel(container, "fields.firstName"), `node replaced after '${ch}'`).toBe(input);
      expect(input.value).toBe(typed);
    }
    unmount();
    cleanup();
  });

  it("identity TITLE input keeps focus while other fields are typed", () => {
    const { container, unmount } = setup("identity");
    const title = inputForLabel(container, "fields.title");
    const first = inputForLabel(container, "fields.firstName");
    title.focus();
    fireEvent.input(title, { target: { value: "Mr" } });
    flush();
    expect(document.activeElement, "TITLE lost focus").toBe(title);
    expect(title.value).toBe("Mr");

    first.focus();
    fireEvent.input(first, { target: { value: "John" } });
    flush();
    expect(document.activeElement, "firstName lost focus").toBe(first);
    expect(inputForLabel(container, "fields.title"), "TITLE node replaced").toBe(title);
    // TITLE's node must survive typing into a sibling field.
    expect(container.contains(title)).toBe(true);
    expect(title.value).toBe("Mr");
    unmount();
    cleanup();
  });

  it("bank account text input keeps the same DOM node across keystrokes", () => {
    const { container, unmount } = setup("bankAccount");
    const input = inputForLabel(container, "fields.bankName");
    input.focus();
    fireEvent.input(input, { target: { value: "B" } });
    flush();
    expect(document.activeElement).toBe(input);
    expect(inputForLabel(container, "fields.bankName"), "node replaced").toBe(input);
    expect(input.value).toBe("B");
    unmount();
    cleanup();
  });

  it("login static inputs still keep focus (control)", () => {
    const { container, unmount } = setup("login");
    const input = container.querySelector('[data-testid="form-username"]');
    input.focus();
    fireEvent.input(input, { target: { value: "u" } });
    flush();
    expect(document.activeElement).toBe(input);
    unmount();
    cleanup();
  });

  it("switching cipher type still re-renders the schema fields", () => {
    const { container, unmount, setCipher } = setup("identity");
    const identityInput = inputForLabel(container, "fields.firstName");
    identityInput.focus();
    setCipher({ cipherType: "bankAccount", name: "" });
    flush();
    // Old rows must be disposed, not kept alongside the new ones.
    const leftoverLabels = Array.from(container.querySelectorAll("label")).filter(
      (l) => l.textContent === "fields.firstName"
    );
    expect(leftoverLabels.length, "identity rows still present after type switch").toBe(0);
    expect(identityInput.isConnected, "identity input still attached after type switch").toBe(false);
    const bank = inputForLabel(container, "fields.bankName");
    expect(bank).toBeTruthy();
    unmount();
    cleanup();
  });

  it("signing key textarea keeps the same DOM node across keystrokes", () => {
    const { container, unmount } = setup("sshKey");
    const input = inputForLabel(container, "fields.publicKey");
    input.focus();
    let typed = "";
    for (const ch of ["a", "b"]) {
      typed += ch;
      fireEvent.input(input, { target: { value: typed } });
      flush();
      expect(document.activeElement, `focus lost after '${ch}'`).toBe(input);
      expect(inputForLabel(container, "fields.publicKey"), `node replaced after '${ch}'`).toBe(input);
      expect(input.value).toBe(typed);
    }
    unmount();
    cleanup();
  });
});
