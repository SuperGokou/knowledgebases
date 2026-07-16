import type { KnowledgeAccessLevel, KnowledgeBase } from "@/lib/types";

export const KNOWLEDGE_CANDIDATE_PAGE_SIZE = 50;
const KNOWLEDGE_CANDIDATE_FETCH_SIZE = KNOWLEDGE_CANDIDATE_PAGE_SIZE + 1;

export type KnowledgeCandidatePage = {
  items: KnowledgeBase[];
  hasMore: boolean;
};

export function knowledgeCandidatePagePath({
  offset,
  query,
  minimumAccessLevel,
}: {
  offset: number;
  query: string;
  minimumAccessLevel: KnowledgeAccessLevel;
}): string {
  const parameters = new URLSearchParams({
    limit: String(KNOWLEDGE_CANDIDATE_FETCH_SIZE),
    offset: String(offset),
    minimum_access_level: minimumAccessLevel,
  });
  const normalizedQuery = query.trim();
  if (normalizedQuery) parameters.set("q", normalizedQuery);
  return `/api/v1/knowledge-bases?${parameters.toString()}`;
}

export function splitKnowledgeCandidatePage(items: KnowledgeBase[]): KnowledgeCandidatePage {
  return {
    items: items.slice(0, KNOWLEDGE_CANDIDATE_PAGE_SIZE),
    hasMore: items.length > KNOWLEDGE_CANDIDATE_PAGE_SIZE,
  };
}

export function mergeKnowledgeCandidates(
  current: KnowledgeBase[],
  incoming: KnowledgeBase[],
  replace: boolean,
): KnowledgeBase[] {
  if (replace) return incoming;
  const merged = new Map(current.map((item) => [item.id, item]));
  for (const item of incoming) merged.set(item.id, item);
  return [...merged.values()];
}

export function candidatesWithSelection(
  candidates: KnowledgeBase[],
  selected: KnowledgeBase | null,
): KnowledgeBase[] {
  if (!selected || candidates.some((candidate) => candidate.id === selected.id)) return candidates;
  return [selected, ...candidates];
}
