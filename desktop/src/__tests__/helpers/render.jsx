// Shared render helper for SolidJS component tests.
//
// Wraps the component in a minimal provider tree (i18n + toast context)
// with all Tauri + daemon calls pre-mocked via `vi.mock`. Each test file
// imports `render` and `mockI18n` from here and uses vi.mock'd modules
// for daemon/invoke/etc. — vi.mock is hoisted, so a top-level call
// before the import is enough.
//
// Usage:
//   import { render, screen, fireEvent } from "@solidjs/testing-library";
//   import { vi } from "vitest";
//   vi.mock("../lib/daemon.js", () => ({ daemon: vi.fn() }));
//   import { daemon } from "../lib/daemon.js";
//   import MyComponent from "../components/MyComponent.jsx";
//
//   it("renders", () => {
//     const { getByText } = render(() => <MyComponent />);
//     getByText("Hello");
//   });

import { vi } from "vitest";

// Default i18n mock. Most components call useI18n() and destructure `t`.
// The mock returns a t() that echoes the key back (good enough for
// asserting the key was looked up; for assertion on localized text, pass
// a custom `t` factory in mockI18n({ t: (k) => `Localised ${k}` }).
vi.mock("../i18n/index.jsx", () => ({
  useI18n: () => ({ t: (k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k), locale: () => "en", setLocale: vi.fn() }),
  I18nProvider: (props) => props.children,
}));

// Default toast mock. The toastSignal module is a singleton with module-
// level createSignal, which Solid can't re-create between tests, so we
// stub the exported functions instead. Components import the named
// exports, not the signal, so this is safe.
vi.mock("../context/toastSignal.js", () => ({
  toast: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  toastWarning: vi.fn(),
  toastInfo: vi.fn(),
  dismiss: vi.fn(),
  toasts: { length: 0 },
}));

export function mockI18n({ t } = {}) {
  return {
    useI18n: () => ({
      t: t ?? ((k, vars) => (vars ? `${k}(${JSON.stringify(vars)})` : k)),
      locale: () => "en",
      setLocale: vi.fn(),
    }),
  };
}

// Re-export commonly used testing-library pieces so test files have a
// single import path.
export {
  render,
  screen,
  fireEvent,
  cleanup,
  waitFor,
} from "@solidjs/testing-library";