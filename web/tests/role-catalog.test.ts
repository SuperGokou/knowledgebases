import { describe, expect, it } from "vitest";

import {
  mergeRoleCatalogItems,
  missingSelectedRoleCount,
  roleCatalogPagePath,
  roleOptionsForSelection,
  splitRoleCatalogPage,
} from "../src/lib/role-catalog";

type Item = { id: string; name: string };

describe("role catalog", () => {
  it("builds a bounded 50+1 request with an encoded q search", () => {
    expect(roleCatalogPagePath({ offset: 100, query: " 财务 %_ ", assignable: true })).toBe(
      "/api/v1/roles?limit=51&offset=100&assignable=true&q=%E8%B4%A2%E5%8A%A1+%25_",
    );
  });

  it("splits the lookahead item from the visible page", () => {
    const page = splitRoleCatalogPage(
      Array.from({ length: 51 }, (_, index) => ({ id: String(index), name: String(index) })),
    );
    expect(page.items).toHaveLength(50);
    expect(page.hasMore).toBe(true);
  });

  it("appends pages without duplicates and replaces results for a new search", () => {
    const first = [{ id: "1", name: "One" }, { id: "2", name: "Old two" }];
    const appended = mergeRoleCatalogItems(first, [
      { id: "2", name: "New two" },
      { id: "3", name: "Three" },
    ], false);
    expect(appended).toEqual([
      { id: "1", name: "One" },
      { id: "2", name: "New two" },
      { id: "3", name: "Three" },
    ]);
    expect(mergeRoleCatalogItems(appended, [{ id: "4", name: "Four" }], true)).toEqual([
      { id: "4", name: "Four" },
    ]);
  });

  it("pins previously loaded selections across searches without leaking unrelated cached roles", () => {
    const known: Item[] = [
      { id: "selected", name: "Selected" },
      { id: "unrelated", name: "Unrelated" },
      { id: "result", name: "Result" },
    ];
    const candidates = [{ id: "result", name: "Result" }];
    expect(roleOptionsForSelection(candidates, known, ["selected"])).toEqual([
      { id: "selected", name: "Selected" },
      { id: "result", name: "Result" },
    ]);
    expect(missingSelectedRoleCount(known, ["selected", "never-loaded"])).toBe(1);
  });
});
