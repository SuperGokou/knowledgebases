export const ADMIN_PAGE_SIZE = 50;
const ADMIN_PAGE_FETCH_SIZE = ADMIN_PAGE_SIZE + 1;

export type AdminPage<T> = {
  items: T[];
  hasMore: boolean;
};

export function splitAdminPage<T>(items: T[]): AdminPage<T> {
  return {
    items: items.slice(0, ADMIN_PAGE_SIZE),
    hasMore: items.length > ADMIN_PAGE_SIZE,
  };
}

export function mergeAdminPage<T extends { id: string }>(
  current: T[],
  incoming: T[],
  replace: boolean,
): T[] {
  if (replace) return incoming;
  const merged = new Map(current.map((item) => [item.id, item]));
  for (const item of incoming) merged.set(item.id, item);
  return [...merged.values()];
}

function pagePath(path: string, offset: number, query?: string): string {
  const parameters = new URLSearchParams({
    limit: String(ADMIN_PAGE_FETCH_SIZE),
    offset: String(offset),
  });
  const normalizedQuery = query?.trim();
  if (normalizedQuery) parameters.set("q", normalizedQuery);
  return `${path}?${parameters.toString()}`;
}

export function apiKeyPagePath(offset: number): string {
  return pagePath("/api/v1/api-keys", offset);
}

export function knowledgeBasePagePath({
  offset,
  query,
}: {
  offset: number;
  query: string;
}): string {
  return pagePath("/api/v1/knowledge-bases", offset, query);
}

export function replaceRotatedApiKey<T extends { id: string }>(
  current: T[],
  previousId: string,
  replacement: T,
): T[] {
  return [
    replacement,
    ...current.filter((item) => item.id !== previousId && item.id !== replacement.id),
  ];
}
