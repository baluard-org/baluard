/**
 * Lightweight i18n for SolidJS.
 *
 * - JSON locale files in ./locales/
 * - t("key.path") for simple strings
 * - t("key", { count: 5 }) for interpolation / plurals
 * - setLocale("es") to switch at runtime
 * - Persists choice to localStorage
 */

import { createSignal, createContext, useContext } from "solid-js";

import en from "./locales/en.json";

/** Flatten nested JSON into dot-path keys: { a: { b: "hi" } } -> { "a.b": "hi" } */
function flatten(obj, prefix = "") {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "object" && v !== null && !Array.isArray(v)) {
      Object.assign(out, flatten(v, path));
    } else if (typeof v === "string") {
      out[path] = v;
    }
  }
  return out;
}

/** Replace {key} placeholders and pick _plural variant when count > 1 */
function interpolate(template, vars) {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, key) => String(vars[key] ?? ""));
}

function pickPlural(dict, key, count) {
  if (count !== undefined && count !== 1) {
    const plural = dict[`${key}_plural`];
    if (plural) return plural;
  }
  return dict[key] ?? key;
}

const STORAGE_KEY = "idtty-locale";

function getStoredLocale() {
  try {
    return localStorage.getItem(STORAGE_KEY) || "en";
  } catch {
    return "en";
  }
}

// ── Public API ──

const I18nContext = createContext();

export function I18nProvider(props) {
  const [locale, setLocaleSignal] = createSignal(getStoredLocale());
  const [dict, setDict] = createSignal(flatten(en));

  const loaded = new Map([["en", flatten(en)]]);

  async function setLocale(l) {
    if (l === "en") {
      setDict(loaded.get("en"));
      setLocaleSignal(l);
      try { localStorage.setItem(STORAGE_KEY, l); } catch { /* noop */ }
      return;
    }
    if (!loaded.has(l)) {
      try {
        const mod = await import(`./locales/${l}.json`);
        const flat = flatten(mod.default ?? mod);
        loaded.set(l, flat);
        setDict(flat);
      } catch {
        console.warn(`Locale "${l}" not found, keeping current`);
        return;
      }
    } else {
      setDict(loaded.get(l));
    }
    setLocaleSignal(l);
    try { localStorage.setItem(STORAGE_KEY, l); } catch { /* noop */ }
  }

  function t(key, vars) {
    const count = typeof vars?.count === "number" ? vars.count : undefined;
    const template = pickPlural(dict(), key, count);
    return interpolate(template, vars);
  }

  function availableLocales() {
    return Array.from(loaded.keys());
  }

  return (
    <I18nContext.Provider value={{ t, locale, setLocale, availableLocales }}>
      {props.children}
    </I18nContext.Provider>
  );
}

export function useI18n() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}
