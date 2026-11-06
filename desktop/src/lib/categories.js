export const CATEGORIES_COLLAPSED_KEY = "baluard-categories-collapsed";

export function categoriesCollapsed(store) {
  try {
    return (store || globalThis.localStorage).getItem(CATEGORIES_COLLAPSED_KEY) === "true";
  } catch {
    return false;
  }
}

export function setCategoriesCollapsed(collapsed, store) {
  try {
    (store || globalThis.localStorage).setItem(CATEGORIES_COLLAPSED_KEY, String(collapsed));
  } catch {
    // The in-memory preference still applies when storage is blocked.
  }
}

export function visibleCategories(categories, collapsed) {
  if (!collapsed) return categories;
  return categories.filter((category) => category.id === "allItems" || category.id === "favorites");
}
