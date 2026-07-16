import { describe, expect, it, vi } from "vitest";

import { ApiClientError } from "../src/lib/api-client";
import {
  openKnowledgeGrantEditor,
  saveKnowledgeGrantAssignment,
  STALE_KNOWLEDGE_GRANTS_MESSAGE,
} from "../src/lib/knowledge-grant-assignment";
import type { KnowledgeBase, KnowledgeBaseRoleGrant } from "../src/lib/types";

const knowledgeBase: KnowledgeBase = {
  id: "00000000-0000-4000-8000-000000000301",
  owner_id: "00000000-0000-4000-8000-000000000101",
  name: "企业知识库",
  description: null,
  custom_metadata: {},
  external_llm_processing_enabled: false,
  access_level: "manager",
  role_grant_version: 7,
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:00:00Z",
};

const grants: KnowledgeBaseRoleGrant[] = [
  {
    id: "00000000-0000-4000-8000-000000000401",
    role_id: "00000000-0000-4000-8000-000000000201",
    access_level: "reader",
    granted_by: knowledgeBase.owner_id,
    created_at: "2026-07-14T00:00:00Z",
    updated_at: "2026-07-14T00:00:00Z",
  },
];

describe("knowledge grant CAS", () => {
  it("rejects an invalid catalog snapshot version before editing", () => {
    expect(() => openKnowledgeGrantEditor({
      ...knowledgeBase,
      role_grant_version: 0,
    })).toThrow("知识库授权版本无效");
  });

  it("sends the selected knowledge-base snapshot version with the full grant set", async () => {
    const request = vi.fn().mockResolvedValue(grants);
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    const result = await saveKnowledgeGrantAssignment(
      openKnowledgeGrantEditor(knowledgeBase),
      grants.map(({ role_id, access_level }) => ({ role_id, access_level })),
      { request, reloadLatest },
    );

    expect(result).toEqual({ status: "saved", grants });
    expect(request).toHaveBeenCalledWith(
      `/api/v1/knowledge-bases/${knowledgeBase.id}/role-grants`,
      {
        method: "PUT",
        body: JSON.stringify({
          grants: [{ role_id: grants[0].role_id, access_level: "reader" }],
          expected_version: 7,
        }),
      },
    );
    expect(reloadLatest).toHaveBeenCalledWith("saved");
  });

  it("refreshes once and never retries an obsolete full grant set after a stale conflict", async () => {
    const request = vi.fn().mockRejectedValue(new ApiClientError(
      "stale",
      409,
      "stale_knowledge_grants",
    ));
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    const result = await saveKnowledgeGrantAssignment(
      openKnowledgeGrantEditor(knowledgeBase),
      [],
      { request, reloadLatest },
    );

    expect(result).toEqual({ status: "stale" });
    expect(request).toHaveBeenCalledTimes(1);
    expect(reloadLatest).toHaveBeenCalledTimes(1);
    expect(reloadLatest).toHaveBeenCalledWith("stale");
    expect(STALE_KNOWLEDGE_GRANTS_MESSAGE).toContain("已被其他管理员更新");
    expect(STALE_KNOWLEDGE_GRANTS_MESSAGE).toContain("旧草稿已关闭");
  });

  it("does not disguise an unrelated conflict as a stale grant snapshot", async () => {
    const conflict = new ApiClientError("different conflict", 409, "other_conflict");
    const reloadLatest = vi.fn().mockResolvedValue(undefined);

    await expect(saveKnowledgeGrantAssignment(
      openKnowledgeGrantEditor(knowledgeBase),
      [],
      { request: vi.fn().mockRejectedValue(conflict), reloadLatest },
    )).rejects.toBe(conflict);
    expect(reloadLatest).not.toHaveBeenCalled();
  });
});
