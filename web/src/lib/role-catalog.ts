export const ROLE_CATALOG_PAGE_SIZE = 50;
const ROLE_CATALOG_FETCH_SIZE = ROLE_CATALOG_PAGE_SIZE + 1;

export type RoleCatalogPage<T> = {
  items: T[];
  hasMore: boolean;
};

export function roleCatalogPagePath({
  offset,
  query,
  assignable = false,
}: {
  offset: number;
  query: string;
  assignable?: boolean;
}): string {
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new Error("offset must be a non-negative integer");
  }
  const parameters = new URLSearchParams({
    limit: String(ROLE_CATALOG_FETCH_SIZE),
    offset: String(offset),
  });
  if (assignable) parameters.set("assignable", "true");
  const normalizedQuery = query.trim();
  if (normalizedQuery) parameters.set("q", normalizedQuery);
  return `/api/v1/roles?${parameters.toString()}`;
}

export function splitRoleCatalogPage<T>(items: readonly T[]): RoleCatalogPage<T> {
  return {
    items: items.slice(0, ROLE_CATALOG_PAGE_SIZE),
    hasMore: items.length > ROLE_CATALOG_PAGE_SIZE,
  };
}

export function mergeRoleCatalogItems<T extends { id: string }>(
  current: readonly T[],
  incoming: readonly T[],
  replace: boolean,
): T[] {
  if (replace) return [...incoming];
  const merged = new Map(current.map((item) => [item.id, item]));
  for (const item of incoming) merged.set(item.id, item);
  return [...merged.values()];
}

export function roleOptionsForSelection<T extends { id: string }>(
  candidates: readonly T[],
  knownRoles: readonly T[],
  selectedIds: readonly string[],
): T[] {
  const candidateIds = new Set(candidates.map((item) => item.id));
  const knownById = new Map(knownRoles.map((item) => [item.id, item]));
  const retainedSelections = selectedIds.flatMap((id) => {
    const role = knownById.get(id);
    return role && !candidateIds.has(id) ? [role] : [];
  });
  return [...retainedSelections, ...candidates];
}

export function missingSelectedRoleCount<T extends { id: string }>(
  knownRoles: readonly T[],
  selectedIds: readonly string[],
): number {
  const knownIds = new Set(knownRoles.map((item) => item.id));
  return selectedIds.filter((id) => !knownIds.has(id)).length;
}
