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
  IconMonitor: (props) => <svg data-icon="monitor" class={props.class} />,
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
});
