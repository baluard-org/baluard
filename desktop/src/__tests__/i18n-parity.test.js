// i18n locale key-parity guard (C-14).
//
// Every user-facing string must exist in BOTH en.json and es.json. A drift
// here used to ship silently and Spanish users hit English fallbacks for the
// missing keys (the clone flow + two common buttons were the original gap).
// This test flattens both files with the same helper the runtime uses and
// asserts the dot-path key sets are identical, so a missing translation
// fails CI at the PR that introduced it.

import { describe, it, expect } from "vitest";
import en from "../i18n/locales/en.json";
import es from "../i18n/locales/es.json";
import pt from "../i18n/locales/pt.json";

// Mirror of flatten() in i18n/index.jsx. Kept local (not imported) so a test
// failure points at the data, not at a runtime import path.
function flatten(obj, prefix = "") {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k.startsWith("_")) continue; // skip _comment etc.
    const path = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      Object.assign(out, flatten(v, path));
    } else if (typeof v === "string") {
      out[path] = v;
    }
  }
  return out;
}

describe("i18n locale parity", () => {
  it("en.json and es.json expose the same dot-path key set", () => {
    const enKeys = new Set(Object.keys(flatten(en)));
    const esKeys = new Set(Object.keys(flatten(es)));
    const missingInEs = [...enKeys].filter((k) => !esKeys.has(k));
    const missingInEn = [...esKeys].filter((k) => !enKeys.has(k));
    expect(missingInEs, `keys missing in es.json: ${missingInEs.join(", ")}`).toEqual([]);
    expect(missingInEn, `keys missing in en.json: ${missingInEn.join(", ")}`).toEqual([]);
  });

  it("en.json and pt.json expose the same dot-path key set", () => {
    const enKeys = new Set(Object.keys(flatten(en)));
    const ptKeys = new Set(Object.keys(flatten(pt)));
    const missingInPt = [...enKeys].filter((k) => !ptKeys.has(k));
    const missingInEn = [...ptKeys].filter((k) => !enKeys.has(k));
    expect(missingInPt, `keys missing in pt.json: ${missingInPt.join(", ")}`).toEqual([]);
    expect(missingInEn, `keys missing in en.json: ${missingInEn.join(", ")}`).toEqual([]);
  });
});
