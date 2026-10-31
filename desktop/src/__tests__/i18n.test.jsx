import { describe, it, expect, beforeEach } from "vitest";
import { render, waitFor, fireEvent, cleanup } from "@solidjs/testing-library";

import { I18nProvider, useI18n } from "../i18n/index.jsx";

function Probe() {
  const { t, locale, setLocale } = useI18n();
  return (
    <div>
      <span data-testid="probe-locale">{locale()}</span>
      <span data-testid="probe-cancel">{t("common.cancel")}</span>
      <button data-testid="probe-es" onClick={() => setLocale("es")} />
      <button data-testid="probe-pt" onClick={() => setLocale("pt")} />
    </div>
  );
}

function renderProvider() {
  const utils = render(
    <I18nProvider>
      <Probe />
    </I18nProvider>,
  );
  return utils;
}

describe("i18n provider", () => {
  beforeEach(() => {
    cleanup();
    // The vitest node env has no localStorage; the i18n module reads the
    // global at call time, so a stub drives both boot and persistence.
    const store = new Map();
    globalThis.localStorage = {
      getItem: (k) => store.get(k) ?? null,
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
      clear: () => store.clear(),
    };
  });

  it("boots in the stored locale, not English", async () => {
    localStorage.setItem("baluard-locale", "es");
    const utils = renderProvider();
    expect(utils.getByTestId("probe-cancel").textContent).toBe("Cancel");
    await waitFor(() => {
      expect(utils.getByTestId("probe-cancel").textContent).toBe("Cancelar");
    });
    expect(utils.getByTestId("probe-locale").textContent).toBe("es");
  });

  it("applies a first-time switch away from English", async () => {
    localStorage.setItem("baluard-locale", "en");
    const utils = renderProvider();
    fireEvent.click(utils.getByTestId("probe-es"));
    await waitFor(() => {
      expect(utils.getByTestId("probe-cancel").textContent).toBe("Cancelar");
    });
    expect(utils.getByTestId("probe-locale").textContent).toBe("es");
    expect(localStorage.getItem("baluard-locale")).toBe("es");
  });

  it("lets a later request supersede one still importing", async () => {
    localStorage.setItem("baluard-locale", "en");
    const utils = renderProvider();
    fireEvent.click(utils.getByTestId("probe-es"));
    fireEvent.click(utils.getByTestId("probe-pt"));
    await waitFor(() => {
      expect(utils.getByTestId("probe-locale").textContent).toBe("pt");
    });
    expect(localStorage.getItem("baluard-locale")).toBe("pt");
  });
});
