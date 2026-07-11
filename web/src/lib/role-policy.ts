import type { LimitDefinition, Permission, Role } from "@/lib/types";

type PermissionCopy = {
  name: string;
  description: string;
};

type LimitCopy = {
  name: string;
  description: string;
  unit: string;
  window: string;
};

type RoleCopy = {
  name: string;
  description: string;
};

export type LimitMode = "unset" | "limited" | "unlimited";

const ROLE_CODE_PATTERN = /^[a-z][a-z0-9_-]{1,99}$/;

const SYSTEM_ROLE_COPY: Record<string, RoleCopy> = {
  system_admin: {
    name: "系统管理员",
    description: "拥有全部系统权限且所有资源限额均为无限制的系统角色。",
  },
};

const PERMISSION_COPY: Record<string, PermissionCopy> = {
  "file:read": {
    name: "查看本人文件",
    description: "查看本人拥有的文件列表、详情并获取下载链接。",
  },
  "file:read:any": {
    name: "查看全部文件",
    description: "查看所有用户拥有的文件，不受文件所有者限制。",
  },
  "file:upload": {
    name: "上传文件",
    description: "创建并完成文件直传任务，将资料加入知识库。",
  },
  "file:approve": {
    name: "审核文件",
    description: "批准已完成安全扫描或人工复核的文件。",
  },
  "file:approve:any": {
    name: "审核未归属文件",
    description: "审核尚未绑定到具体知识库的文件。",
  },
  "file:delete": {
    name: "删除文件",
    description: "从知识库中软删除文件，并保留必要的审计记录。",
  },
  "user:manage": {
    name: "管理账号",
    description: "创建、更新、禁用或恢复后台登录账号。",
  },
  "role:read": {
    name: "查看角色",
    description: "查看角色列表、权限能力和资源访问限额。",
  },
  "role:manage": {
    name: "管理角色",
    description: "创建角色，并修改允许授权的角色策略。",
  },
  "role:assign": {
    name: "分配角色",
    description: "为用户分配或调整允许授予的角色。",
  },
  "quota:manage": {
    name: "管理资源额度",
    description: "管理限额定义以及用户级别的额度覆盖规则。",
  },
  "audit:read": {
    name: "查看审计日志",
    description: "查看安全事件和后台管理操作的审计记录。",
  },
  "knowledge:create": {
    name: "创建知识库",
    description: "创建由当前用户负责管理的企业知识库。",
  },
  "knowledge:read": {
    name: "查看知识库",
    description: "查看已获授权的知识库、条目和相关资料。",
  },
  "knowledge:update": {
    name: "编辑知识库",
    description: "更新已获授权的知识库设置和知识条目。",
  },
  "knowledge:grant": {
    name: "管理知识库授权",
    description: "配置角色对知识库的阅读、编辑或管理等级。",
  },
  "chat:query": {
    name: "使用知识问答",
    description: "在已获授权的知识库中发起带来源引用的问答。",
  },
  "api-key:manage": {
    name: "管理 API 密钥",
    description: "签发、查看和吊销限定范围的 API 访问密钥。",
  },
  "llm:manage": {
    name: "管理大模型配置",
    description: "配置并切换系统允许使用的大模型服务商。",
  },
};

const LIMIT_COPY: Record<string, LimitCopy> = {
  requests_per_minute: {
    name: "每分钟请求次数",
    description: "每个固定分钟窗口内允许调用受保护接口的次数；超出后返回限流提示。",
    unit: "次请求",
    window: "每分钟",
  },
  max_upload_bytes: {
    name: "单个文件大小上限",
    description: "一次上传任务允许声明的最大文件大小。",
    unit: "文件大小",
    window: "每次上传",
  },
  daily_upload_bytes: {
    name: "每日上传总量",
    description: "每个 UTC 自然日可发起上传的文件总字节数。",
    unit: "上传流量",
    window: "每日（UTC）",
  },
  storage_bytes: {
    name: "累计存储写入量",
    description: "生命周期内累计成功上传的字节数；当前版本删除文件不会返还该额度。",
    unit: "累计字节数",
    window: "生命周期累计",
  },
  daily_downloads: {
    name: "每日下载授权次数",
    description: "每个 UTC 自然日可签发短期文件下载链接的次数。",
    unit: "次下载授权",
    window: "每日（UTC）",
  },
};

const RESOURCE_LABELS: Record<string, string> = {
  file: "文件",
  user: "账号",
  role: "角色",
  quota: "额度",
  audit: "审计日志",
  knowledge: "知识库",
  chat: "知识问答",
  "api-key": "API 密钥",
  llm: "大模型",
};

const ACTION_LABELS: Record<string, string> = {
  read: "查看",
  create: "创建",
  update: "编辑",
  upload: "上传",
  approve: "审核",
  delete: "删除",
  manage: "管理",
  assign: "分配",
  grant: "授权",
  query: "使用",
};

function containsChinese(value: string | null | undefined): value is string {
  return Boolean(value && /[\u3400-\u9fff]/u.test(value));
}

export function roleCopy(role: Pick<Role, "code" | "name" | "description">): RoleCopy {
  return SYSTEM_ROLE_COPY[role.code] ?? {
    name: role.name,
    description: role.description || "暂无角色说明。",
  };
}

export function permissionCopy(permission: Permission): PermissionCopy {
  const known = PERMISSION_COPY[permission.code];
  if (known) return known;
  if (containsChinese(permission.name)) {
    return {
      name: permission.name,
      description: containsChinese(permission.description)
        ? permission.description
        : "该权限由服务端目录定义，请联系系统管理员确认具体用途。",
    };
  }

  const [resource = "", action = ""] = permission.code.split(":");
  return {
    name: `${ACTION_LABELS[action] ?? "操作"}${RESOURCE_LABELS[resource] ?? "系统资源"}`,
    description: "该权限由服务端目录定义，请联系系统管理员确认具体用途。",
  };
}

export function limitCopy(definition: LimitDefinition): LimitCopy {
  const known = LIMIT_COPY[definition.key];
  if (known) return known;
  return {
    name: containsChinese(definition.name) ? definition.name : "自定义资源限额",
    description: containsChinese(definition.description)
      ? definition.description
      : "该限额由服务端目录定义，请联系系统管理员确认计算口径。",
    unit: "服务端定义单位",
    window: "服务端定义周期",
  };
}

export function limitMode(value: string | undefined): LimitMode {
  if (!value?.trim()) return "unset";
  return value.trim().toLowerCase() === "unlimited" ? "unlimited" : "limited";
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const digits = index === 0 ? 0 : 1;
  return `${(bytes / 1024 ** index).toFixed(digits)} ${units[index]}`;
}

export function displayLimit(definition: LimitDefinition, value: number | null | undefined): string {
  if (value === undefined) return "未设置";
  if (value === null) return "无限制";
  if (definition.key.includes("bytes")) return formatBytes(value);
  return `${new Intl.NumberFormat("zh-CN").format(value)} 次`;
}

export function normalizeRoleCode(value: string): string {
  let normalized = value
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9_-]/g, "")
    .replace(/^[_-]+|[_-]+$/g, "");
  if (!normalized) return "";
  if (!/^[a-z]/.test(normalized)) normalized = `role_${normalized}`;
  if (normalized.length === 1) normalized = `${normalized}_role`;
  return normalized.slice(0, 100).replace(/[_-]+$/g, "");
}

export function generateRoleCode(seed: string): string {
  const suffix = seed.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 24) || "custom";
  return `role_${suffix}`;
}

export function isValidRoleCode(value: string): boolean {
  return ROLE_CODE_PATTERN.test(value);
}
