// ToastContainer render tests: each concurrent toast carries its own icon.
// Regression: module-scope ICONS values share one DOM node across For rows,
// so every toast older than the newest rendered iconless.
//
// Solid 2 defers dynamic JSX insertions to the microtask queue; asserts
// wait one macrotask so the rows are actually in the DOM.

import { describe, expect, it, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";

import ToastContainer from "../components/ToastContainer.jsx";
import { toast, dismiss, toasts } from "../context/toastSignal.js";

async function flushInsertions() {
  await new Promise((r) => setTimeout(r, 0));
}

describe("ToastContainer", () => {
  beforeEach(() => {
    for (const t of toasts()) dismiss(t.id);
  });

  it("renders one icon per toast when several are live", async () => {
    const { container } = render(() => <ToastContainer />);
    toast("success", "first");
    toast("success", "second");
    toast("error", "third");
    await flushInsertions();

    const rows = container.querySelectorAll(".toast-container__toast");
    const icons = container.querySelectorAll(".toast-container__toast-icon svg");
    expect(rows.length).toBe(3);
    expect(icons.length).toBe(3);
  });
});
