import { describe, it, expect, vi, afterEach } from "vitest";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";

const toggleSpy = vi.fn();
const themeMock = { current: "dark" };

vi.mock("../context/themeSignal.js", () => ({
  theme: () => themeMock.current,
  setTheme: (t) => { themeMock.current = t; },
  resolvedTheme: () => (themeMock.current === "system" ? "dark" : themeMock.current),
  toggleTheme: (...a) => toggleSpy(...a),
}));

vi.mock("../components/Icon.jsx", () => ({
  IconSun: (props) => <svg data-icon="sun" class={props.class} />,
  IconMoon: (props) => <svg data-icon="moon" class={props.class} />,
}));

vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k) => k }),
}));

import ThemeToggleFloating from "../components/ThemeToggleFloating.jsx";

describe("ThemeToggleFloating", () => {
  afterEach(() => {
    cleanup();
    toggleSpy.mockClear();
  });

  it("dark resolved: shows the sun and offers switching to light", () => {
    themeMock.current = "dark";
    const { container, getByTitle } = render(() => <ThemeToggleFloating />);
    expect(container.querySelector('[data-icon="sun"]')).toBeTruthy();
    expect(getByTitle("settings.switchToLight")).toBeTruthy();
  });

  it("light resolved: shows the moon and offers switching to dark", () => {
    themeMock.current = "light";
    const { container, getByTitle } = render(() => <ThemeToggleFloating />);
    expect(container.querySelector('[data-icon="moon"]')).toBeTruthy();
    expect(getByTitle("settings.switchToDark")).toBeTruthy();
  });

  it("clicking calls the two-state toggle", async () => {
    themeMock.current = "dark";
    const { container } = render(() => <ThemeToggleFloating />);
    fireEvent.click(container.querySelector(".theme-toggle-floating"));
    await Promise.resolve();
    expect(toggleSpy).toHaveBeenCalledTimes(1);
  });

  // Regression (2026-11-11 Mac): a real pointerdown stamped data-ripple on
  // this button and the unlayered [data-ripple] CSS rule demoted it from
  // fixed to relative, so its insets became relative shifts and the button
  // landed half-clipped on the left edge. Two guards pin the fix.
  it("ripple styling never carries a position rule for [data-ripple]", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    // vitest transforms import.meta.url, so anchor on the process cwd
    // (tests run from desktop/) instead.
    const css = fs.readFileSync(
      path.resolve(process.cwd(), "src/app.css"),
      "utf8",
    );
    const start = css.indexOf("[data-ripple] {");
    expect(start).toBeGreaterThanOrEqual(0);
    const end = css.indexOf("}", start);
    const block = css.slice(start, end);
    expect(block).not.toMatch(/position\s*:/);
  });

  it("a real pointerdown leaves a positioned button positioned", async () => {
    const { initRipple } = await import("../lib/ripple.js");
    initRipple();
    themeMock.current = "dark";
    const { container } = render(() => <ThemeToggleFloating />);
    const btn = container.querySelector(".theme-toggle-floating");
    // Stand in for the stylesheet's fixed utility: the guard in ripple.js
    // keys on the computed position, so a positioned target must be left
    // alone entirely.
    btn.style.position = "fixed";
    btn.dispatchEvent(
      new PointerEvent("pointerdown", { bubbles: true, button: 0 }),
    );
    expect(btn.hasAttribute("data-ripple")).toBe(true);
    expect(btn.style.position).toBe("fixed");
    // A static button still gets a positioning context for the ripple span.
    // It must be in the document: the capture listener lives there.
    const plain = document.createElement("button");
    document.body.appendChild(plain);
    plain.dispatchEvent(
      new PointerEvent("pointerdown", { bubbles: true, button: 0 }),
    );
    expect(plain.style.position).toBe("relative");
    plain.remove();
  });
});
