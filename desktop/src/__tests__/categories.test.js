import { describe, expect, it } from "vitest";
import {
  CATEGORIES_COLLAPSED_KEY,
  categoriesCollapsed,
  setCategoriesCollapsed,
  visibleCategories,
} from "../lib/categories.js";

function storage(initial = null) {
  const values = new Map(initial === null ? [] : [[CATEGORIES_COLLAPSED_KEY, initial]]);
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    value: () => values.get(CATEGORIES_COLLAPSED_KEY),
  };
}

const categories = [
  { id: "allItems" },
  { id: "favorites" },
  { id: "login" },
  { id: "archive" },
];

describe("Categories sidebar preference", () => {
  it("defaults to expanded and reads the stored choice", () => {
    expect(categoriesCollapsed(storage())).toBe(false);
    expect(categoriesCollapsed(storage("true"))).toBe(true);
    expect(categoriesCollapsed(storage("false"))).toBe(false);
    expect(categoriesCollapsed(storage("invalid"))).toBe(false);
  });

  it("persists the collapsed choice locally", () => {
    const store = storage();
    setCategoriesCollapsed(true, store);
    expect(store.value()).toBe("true");
    setCategoriesCollapsed(false, store);
    expect(store.value()).toBe("false");
  });

  it("fails open when storage is unavailable", () => {
    const broken = {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
    };
    expect(categoriesCollapsed(broken)).toBe(false);
    expect(() => setCategoriesCollapsed(true, broken)).not.toThrow();
  });

  it("keeps All Items and Favorites visible while collapsed", () => {
    expect(visibleCategories(categories, true).map((category) => category.id)).toEqual(["allItems", "favorites"]);
    expect(visibleCategories(categories, false)).toBe(categories);
  });
});
