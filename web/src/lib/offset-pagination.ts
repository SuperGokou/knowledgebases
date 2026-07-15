export const ADMIN_LIST_PAGE_SIZE = 50;

export type OffsetPage<T> = {
  items: T[];
  hasNext: boolean;
};

export function buildOffsetListPath(
  basePath: string,
  {
    offset,
    search,
    pageSize = ADMIN_LIST_PAGE_SIZE,
  }: { offset: number; search?: string; pageSize?: number },
): string {
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new Error("offset must be a non-negative integer");
  }
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize >= 100) {
    throw new Error("pageSize must be between 1 and 99");
  }
  const params = new URLSearchParams({
    limit: String(pageSize + 1),
    offset: String(offset),
  });
  const term = search?.trim();
  if (term) params.set("search", term);
  return `${basePath}?${params.toString()}`;
}

export function splitOffsetPage<T>(items: readonly T[], pageSize = ADMIN_LIST_PAGE_SIZE): OffsetPage<T> {
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize >= 100) {
    throw new Error("pageSize must be between 1 and 99");
  }
  return {
    items: items.slice(0, pageSize),
    hasNext: items.length > pageSize,
  };
}

export function previousOffset(offset: number, pageSize = ADMIN_LIST_PAGE_SIZE): number {
  return Math.max(0, offset - pageSize);
}

export function offsetPageNumber(offset: number, pageSize = ADMIN_LIST_PAGE_SIZE): number {
  return Math.floor(offset / pageSize) + 1;
}
