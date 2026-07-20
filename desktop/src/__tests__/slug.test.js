// Tests for desktop/src/lib/slug.js — pure helpers for vault slug
// generation + validation. Must stay in sync with
// crates/baluard-core/src/vault/slug.rs.

import { describe, it, expect } from "vitest";
import { suggestSlug, validateSlug, cleanSlug } from "../lib/slug.js";

describe("suggestSlug", () => {
  it("lowercases and replaces non-alphanumerics with hyphens", () => {
    expect(suggestSlug("My Personal Vault")).toBe("baluard-my-personal-vault");
  });

  it("collapses consecutive non-alphanumerics into a single hyphen", () => {
    expect(suggestSlug("hello   world!!!")).toBe("baluard-hello-world");
  });

  it("strips leading and trailing hyphens", () => {
    expect(suggestSlug("---foo---")).toBe("baluard-foo");
  });

  it("returns baluard-vault for empty input", () => {
    expect(suggestSlug("")).toBe("baluard-vault");
  });

  it("returns baluard-vault for input with no alphanumerics", () => {
    expect(suggestSlug("!!!@@@###")).toBe("baluard-vault");
  });

  it("does not double-prefix baluard-", () => {
    expect(suggestSlug("baluard-already")).toBe("baluard-already");
  });

  it("truncates at 63 chars and strips trailing hyphens", () => {
    const longName = "a".repeat(100);
    const result = suggestSlug(longName);
    expect(result.length).toBeLessThanOrEqual(63);
    expect(result.endsWith("-")).toBe(false);
  });
});

describe("validateSlug", () => {
  it("returns null for a valid slug", () => {
    expect(validateSlug("my-personal-vault")).toBeNull();
  });

  it("rejects empty slug", () => {
    expect(validateSlug("")).toMatch(/cannot be empty/);
  });

  it("rejects slug shorter than 4 chars", () => {
    expect(validateSlug("abc")).toMatch(/minimum is 4/);
  });

  it("rejects slug longer than 63 chars", () => {
    expect(validateSlug("a".repeat(64))).toMatch(/maximum is 63/);
  });

  it("rejects slug with leading hyphen", () => {
    expect(validateSlug("-foo")).toMatch(/cannot start or end/);
  });

  it("rejects slug with trailing hyphen", () => {
    expect(validateSlug("foo-")).toMatch(/cannot start or end/);
  });

  it("rejects slug with uppercase", () => {
    expect(validateSlug("MySlug")).toMatch(/lowercase/);
  });

  it("rejects slug with consecutive hyphens", () => {
    expect(validateSlug("foo--bar")).toMatch(/consecutive hyphens/);
  });

  it("rejects slug with non-alphanumeric characters", () => {
    expect(validateSlug("foo_bar")).toMatch(/lowercase letters/);
  });
});

describe("cleanSlug", () => {
  it("lowercases", () => {
    expect(cleanSlug("MySlug")).toBe("myslug");
  });

  it("replaces non-alphanumerics with hyphens", () => {
    expect(cleanSlug("my slug!")).toBe("my-slug");
  });

  it("collapses consecutive non-alphanumerics", () => {
    expect(cleanSlug("foo   bar")).toBe("foo-bar");
  });

  it("strips leading and trailing hyphens", () => {
    expect(cleanSlug("---foo---")).toBe("foo");
  });

  it("returns empty string for input with no alphanumerics", () => {
    expect(cleanSlug("!!!")).toBe("");
  });
});