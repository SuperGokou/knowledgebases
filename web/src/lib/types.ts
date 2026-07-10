export type ApiProblem = {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
  request_id?: string | null;
  message?: string;
};

export type SessionView = {
  authenticated: boolean;
  email?: string;
};

export type AuthMe = {
  id: string;
  email: string;
  display_name: string | null;
  status: UserStatus;
  is_superuser: boolean;
  permission_codes: string[];
  role_ids: string[];
  limits: Record<string, number | null>;
};

export type UserStatus = "active" | "disabled" | "locked";

export type User = {
  id: string;
  email: string;
  display_name: string | null;
  status: UserStatus;
  is_superuser: boolean;
  created_at: string;
  updated_at: string;
  role_ids: string[];
};

export type Role = {
  id: string;
  code: string;
  name: string;
  description: string | null;
  priority: number;
  is_system: boolean;
  created_at: string;
  updated_at: string;
  permission_codes: string[];
  limits: Record<string, number | null>;
};

export type Permission = {
  id: string;
  code: string;
  name: string;
  description: string | null;
};

export type LimitDefinition = {
  id: string;
  key: string;
  name: string;
  description: string | null;
  unit: string;
  window: string;
};

export type FileRecord = {
  id: string;
  owner_id: string;
  knowledge_base_id: string | null;
  original_name: string;
  extension: string;
  content_type: string;
  size_bytes: number;
  checksum_algorithm: string | null;
  checksum_value: string | null;
  status:
    | "pending"
    | "uploading"
    | "processing"
    | "available"
    | "quarantined"
    | "failed"
    | "deleted";
  custom_metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  available_at: string | null;
};

export type UploadPlan = {
  upload_session_id: string;
  file_id: string;
  mode: "single" | "multipart";
  expires_at: string;
  part_size_bytes: number;
  part_count: number;
  upload_url: string | null;
  required_headers: Record<string, string>;
};

export type PartUrlResponse = {
  parts: Array<{ part_number: number; url: string; size_bytes: number }>;
  expires_in: number;
};

export type KnowledgeBase = {
  id: string;
  owner_id: string;
  name: string;
  description: string | null;
  custom_metadata: Record<string, unknown>;
  access_level: "reader" | "editor" | "manager";
  created_at: string;
  updated_at: string;
};

export type KnowledgeAccessLevel = "reader" | "editor" | "manager";

export type KnowledgeBaseRoleGrant = {
  id: string;
  role_id: string;
  access_level: KnowledgeAccessLevel;
  granted_by: string | null;
  created_at: string;
  updated_at: string;
};

export type ChatCitation = {
  entry_id: string;
  source_file_id: string | null;
  title: string;
  excerpt: string;
  source_path: string | null;
  format_version: string | null;
};

export type ChatReply = {
  knowledge_base_id: string;
  answer: string;
  mode: string;
  citations: ChatCitation[];
};

export type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
  pending?: boolean;
  failed?: boolean;
};
