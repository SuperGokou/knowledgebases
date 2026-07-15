import { describe, expect, it } from "vitest";

import {
  ADMIN_LIST_PAGE_SIZE,
  buildOffsetListPath,
  offsetPageNumber,
  previousOffset,
  splitOffsetPage,
} from "../src/lib/offset-pagination";

describe("offset pagination", () => {
  it("requests one look-ahead row and safely encodes server-side search", () => {
    const path = buildOffsetListPath("/api/v1/users", {
      offset: 100,
      search: " 第 101 位%_成员 ",
    });
    const url = new URL(path, "https://example.test");

    expect(url.pathname).toBe("/api/v1/users");
    expect(url.searchParams.get("limit")).toBe(String(ADMIN_LIST_PAGE_SIZE + 1));
    expect(url.searchParams.get("offset")).toBe("100");
    expect(url.searchParams.get("search")).toBe("第 101 位%_成员");
  });

  it("uses the look-ahead row only to decide whether the next page exists", () => {
    const rows = Array.from({ length: ADMIN_LIST_PAGE_SIZE + 1 }, (_, index) => index);

    expect(splitOffsetPage(rows)).toEqual({
      items: rows.slice(0, ADMIN_LIST_PAGE_SIZE),
      hasNext: true,
    });
    expect(splitOffsetPage(rows.slice(0, ADMIN_LIST_PAGE_SIZE))).toEqual({
      items: rows.slice(0, ADMIN_LIST_PAGE_SIZE),
      hasNext: false,
    });
  });

  it("moves between deterministic offset pages without going negative", () => {
    expect(offsetPageNumber(0)).toBe(1);
    expect(offsetPageNumber(50)).toBe(2);
    expect(offsetPageNumber(100)).toBe(3);
    expect(previousOffset(100)).toBe(50);
    expect(previousOffset(0)).toBe(0);
  });

  it.each([
    { offset: -1, pageSize: 50 },
    { offset: 0.5, pageSize: 50 },
    { offset: 0, pageSize: 0 },
    { offset: 0, pageSize: 100 },
  ])("rejects an invalid page request: $offset/$pageSize", ({ offset, pageSize }) => {
    expect(() => buildOffsetListPath("/api/v1/files", { offset, pageSize })).toThrow();
  });
});
