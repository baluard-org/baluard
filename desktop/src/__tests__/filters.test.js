import { describe, it, expect } from "vitest";
import {
  CATEGORY_TYPE_MAP,
  cipherCollectionId,
  filterByCollection,
  selectSource,
  filterByCategory,
  filterByFolder,
  searchCiphers,
} from "../lib/filters.js";

const makeCipher = (overrides = {}) => ({
  id: "1",
  name: "Test",
  type: "login",
  username: "",
  notes: "",
  uris: [],
  ...overrides,
});

describe("selectSource", () => {
  const active = [makeCipher({ name: "A" })];
  const trash = [makeCipher({ name: "T" })];
  const archived = [makeCipher({ name: "R" })];

  it("returns trash for Trash category", () => {
    expect(selectSource("Trash", active, trash, archived)).toEqual(trash);
  });

  it("returns archived for Archive category", () => {
    expect(selectSource("Archive", active, trash, archived)).toEqual(archived);
  });

  it("returns active for any other category", () => {
    expect(selectSource("All items", active, trash, archived)).toEqual(active);
    expect(selectSource("Login", active, trash, archived)).toEqual(active);
  });

  it("handles null sources", () => {
    expect(selectSource("Trash", null, null, null)).toEqual([]);
  });
});

describe("filterByCategory", () => {
  const ciphers = [
    makeCipher({ type: "login", favorite: false }),
    makeCipher({ type: "card", favorite: true }),
    makeCipher({ type: "login", favorite: true }),
    makeCipher({ type: "sshKey", favorite: false }),
  ];

  it("passes through for All items", () => {
    expect(filterByCategory(ciphers, "All items")).toHaveLength(4);
  });

  it("filters by type", () => {
    expect(filterByCategory(ciphers, "Login")).toHaveLength(2);
    expect(filterByCategory(ciphers, "Card")).toHaveLength(1);
    expect(filterByCategory(ciphers, "SSH key")).toHaveLength(1);
  });

  it("filters favorites", () => {
    expect(filterByCategory(ciphers, "Favorites")).toHaveLength(2);
  });

  it("returns all for unknown category", () => {
    expect(filterByCategory(ciphers, "Unknown")).toHaveLength(4);
  });
});

describe("filterByFolder", () => {
  const ciphers = [
    makeCipher({ folder_id: "f1" }),
    makeCipher({ folder_id: "f2" }),
    makeCipher({ folder_id: "f3" }),
    makeCipher({ folder_id: null }),
  ];
  const folders = [
    { id: "f1", parent_id: null },
    { id: "f2", parent_id: "f1" },
    { id: "f3", parent_id: "f2" },
  ];

  it("returns all when no folder selected", () => {
    expect(filterByFolder(ciphers, folders, null)).toHaveLength(4);
  });

  it("includes direct folder and descendants via BFS", () => {
    // f1 has ciphers in f1, f2 (child), f3 (grandchild) — all are descendants
    const result = filterByFolder(ciphers, folders, "f1");
    expect(result).toHaveLength(3);
  });

  it("leaf folder with no children", () => {
    expect(filterByFolder(ciphers, folders, "f3")).toHaveLength(1);
  });
});

describe("searchCiphers", () => {
  const ciphers = [
    makeCipher({ name: "GitHub", username: "dev", notes: "work account", uris: [{ uri: "https://github.com" }] }),
    makeCipher({ name: "AWS Console", username: "admin", notes: "production", uris: [] }),
    makeCipher({ name: "Personal", username: "me", notes: "stuff", uris: [{ uri: "https://example.com" }] }),
  ];

  it("returns all when no query", () => {
    expect(searchCiphers(ciphers, "")).toHaveLength(3);
    expect(searchCiphers(ciphers, null)).toHaveLength(3);
  });

  it("searches by name", () => {
    expect(searchCiphers(ciphers, "github")).toHaveLength(1);
  });

  it("searches by username", () => {
    expect(searchCiphers(ciphers, "admin")).toHaveLength(1);
  });

  it("searches by notes", () => {
    expect(searchCiphers(ciphers, "production")).toHaveLength(1);
  });

  it("searches by URI", () => {
    expect(searchCiphers(ciphers, "example")).toHaveLength(1);
  });

  it("case insensitive", () => {
    expect(searchCiphers(ciphers, "GITHUB")).toHaveLength(1);
  });
});

describe("CATEGORY_TYPE_MAP", () => {
  it("maps all 9 cipher types", () => {
    const types = Object.values(CATEGORY_TYPE_MAP);
    expect(types).toContain("login");
    expect(types).toContain("card");
    expect(types).toContain("identity");
    expect(types).toContain("secureNote");
    expect(types).toContain("sshKey");
    expect(types).toContain("bankAccount");
    expect(types).toContain("driversLicense");
    expect(types).toContain("passport");
    expect(types).toContain("signingKey");
    expect(Object.keys(CATEGORY_TYPE_MAP)).toHaveLength(9);
  });
});

describe("cipherCollectionId", () => {
  it("prefers top-level then _meta then null", () => {
    expect(cipherCollectionId({ collection_id: "a" })).toBe("a");
    expect(cipherCollectionId({ _meta: { collection_id: "b" } })).toBe("b");
    expect(cipherCollectionId({})).toBeNull();
  });
});

describe("filterByCollection", () => {
  const rows = [
    { id: "1", _meta: { collection_id: "c1" } },
    { id: "2", collection_id: "c2" },
    { id: "3" },
  ];
  it("filters by either surface and passes everything through when unset", () => {
    expect(filterByCollection(rows, "c1").map((r) => r.id)).toEqual(["1"]);
    expect(filterByCollection(rows, "c2").map((r) => r.id)).toEqual(["2"]);
    expect(filterByCollection(rows, null)).toHaveLength(3);
  });
});
