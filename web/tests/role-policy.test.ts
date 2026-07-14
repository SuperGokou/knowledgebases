import { describe, expect, it } from "vitest";

import {
  displayLimit,
  generateRoleCode,
  isValidRoleCode,
  limitCopy,
  limitMode,
  normalizeRoleCode,
  permissionCopy,
  roleCopy,
} from "../src/lib/role-policy";
import type { LimitDefinition, Permission } from "../src/lib/types";

const permission = (code: string, name = "English name", description = "English copy"): Permission => ({
  id: code,
  code,
  name,
  description,
});

const definition = (key: string): LimitDefinition => ({
  id: key,
  key,
  name: "English name",
  description: "English copy",
  unit: "bytes",
  window: "day",
});

describe("角色权限中文文案", () => {
  it("覆盖服务端当前的全部权限代码", () => {
    const codes = [
      "file:read",
      "file:read:any",
      "file:upload",
      "file:approve",
      "file:approve:any",
      "file:delete",
      "user:manage",
      "role:read",
      "role:manage",
      "role:assign",
      "quota:manage",
      "audit:read",
      "knowledge:create",
      "knowledge:read",
      "knowledge:update",
      "knowledge:grant",
      "chat:query",
      "api-key:manage",
      "llm:manage",
    ];

    for (const code of codes) {
      const copy = permissionCopy(permission(code));
      expect(copy.name).toMatch(/[\u3400-\u9fff]/u);
      expect(copy.description).toMatch(/[\u3400-\u9fff]/u);
      expect(copy.name).not.toBe("English name");
    }
  });

  it("未知权限也不会回退为英文能力名称", () => {
    expect(permissionCopy(permission("report:export"))).toEqual({
      name: "操作系统资源",
      description: "该权限由服务端目录定义，请联系系统管理员确认具体用途。",
    });
  });
});

describe("角色中文文案", () => {
  it("数据库目录尚为英文时也会显示中文系统管理员", () => {
    expect(roleCopy({
      code: "system_admin",
      name: "System Administrator",
      description: "Bootstrap role with every catalog permission and unlimited quotas",
    })).toEqual({
      name: "系统管理员",
      description: "拥有全部系统权限，角色额度不设上限；仍受平台安全硬上限、恶意软件扫描上限及磁盘水位策略约束。",
    });
  });

  it("保留自定义角色文案并提供空说明兜底", () => {
    expect(roleCopy({ code: "editor", name: "知识编辑", description: null })).toEqual({
      name: "知识编辑",
      description: "暂无角色说明。",
    });
  });
});

describe("角色限额说明", () => {
  it("明确区分未设置、有限制和无限制", () => {
    expect(limitMode(undefined)).toBe("unset");
    expect(limitMode("")).toBe("unset");
    expect(limitMode("100")).toBe("limited");
    expect(limitMode("unlimited")).toBe("unlimited");
  });

  it("为所有现有限额提供中文计算口径", () => {
    for (const key of ["requests_per_minute", "max_upload_bytes", "daily_upload_bytes", "storage_bytes", "daily_downloads"]) {
      const copy = limitCopy(definition(key));
      expect(copy.name).toMatch(/[\u3400-\u9fff]/u);
      expect(copy.description).toMatch(/[\u3400-\u9fff]/u);
      expect(copy.window).toMatch(/[\u3400-\u9fff]/u);
    }
    expect(limitCopy(definition("storage_bytes")).description).toContain("删除文件不会返还");
    expect(limitCopy(definition("max_upload_bytes")).description).toContain("平台安全硬上限");
  });

  it("使用中文状态并格式化容量", () => {
    const uploadLimit = definition("max_upload_bytes");
    expect(displayLimit(uploadLimit, undefined)).toBe("未设置");
    expect(displayLimit(uploadLimit, null)).toBe("无限制");
    expect(displayLimit(uploadLimit, 1024 * 1024)).toBe("1.0 MB");
    expect(displayLimit(definition("daily_downloads"), 20)).toBe("20 次");
  });
});

describe("角色创建输入", () => {
  it("自动规范化常见的英文角色标识", () => {
    expect(normalizeRoleCode(" Knowledge Editor ")).toBe("knowledge_editor");
    expect(normalizeRoleCode("123 编辑者")).toBe("role_123");
    expect(normalizeRoleCode("知识编辑")).toBe("");
  });

  it("留空时生成后端可接受的稳定格式", () => {
    const code = generateRoleCode("M123-ABC");
    expect(code).toBe("role_m123abc");
    expect(isValidRoleCode(code)).toBe(true);
  });
});
