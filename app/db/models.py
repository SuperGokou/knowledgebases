from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"


class FileStatus(StrEnum):
    PENDING = "pending"
    UPLOADING = "uploading"
    PROCESSING = "processing"
    AVAILABLE = "available"
    QUARANTINED = "quarantined"
    FAILED = "failed"
    DELETED = "deleted"


class UploadSessionStatus(StrEnum):
    INITIATED = "initiated"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"
    EXPIRED = "expired"


class ReservationStatus(StrEnum):
    HELD = "held"
    CONSUMED = "consumed"
    RELEASED = "released"
    EXPIRED = "expired"


class KnowledgeBaseAccessLevel(StrEnum):
    READER = "reader"
    EDITOR = "editor"
    MANAGER = "manager"


class OkfConversionStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    RETRY_WAIT = "retry_wait"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class KnowledgeIngestionStatus(StrEnum):
    NOT_REQUESTED = "not_requested"
    PENDING = "pending"
    DRAFT_READY = "draft_ready"
    INDEXED = "indexed"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class KnowledgeEntryPublicationStatus(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status"), default=UserStatus.ACTIVE, nullable=False
    )
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Role(TimestampMixin, Base):
    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_roles_pair"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), index=True, nullable=False
    )
    assigned_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_pair"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), index=True, nullable=False
    )
    permission_id: Mapped[UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), index=True, nullable=False
    )


class LimitDefinition(Base):
    __tablename__ = "limit_definitions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    unit: Mapped[str] = mapped_column(String(50), nullable=False)
    window: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RoleLimit(Base):
    __tablename__ = "role_limits"
    __table_args__ = (
        UniqueConstraint("role_id", "limit_definition_id", name="uq_role_limits_pair"),
        CheckConstraint("value IS NULL OR value >= 0", name="non_negative_value"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), index=True, nullable=False
    )
    limit_definition_id: Mapped[UUID] = mapped_column(
        ForeignKey("limit_definitions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    value: Mapped[int | None] = mapped_column(BigInteger)


class UserLimitOverride(Base):
    __tablename__ = "user_limit_overrides"
    __table_args__ = (
        UniqueConstraint("user_id", "limit_definition_id", name="uq_user_limit_overrides_pair"),
        CheckConstraint("value IS NULL OR value >= 0", name="non_negative_value"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    limit_definition_id: Mapped[UUID] = mapped_column(
        ForeignKey("limit_definitions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    value: Mapped[int | None] = mapped_column(BigInteger)


class KnowledgeBase(TimestampMixin, Base):
    __tablename__ = "knowledge_bases"
    __table_args__ = (Index("ix_knowledge_bases_owner_updated", "owner_id", "updated_at"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    owner_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    external_llm_processing_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    custom_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class KnowledgeBaseRoleGrant(TimestampMixin, Base):
    __tablename__ = "knowledge_base_role_grants"
    __table_args__ = (
        UniqueConstraint(
            "knowledge_base_id",
            "role_id",
            name="uq_knowledge_base_role_grants_pair",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    knowledge_base_id: Mapped[UUID] = mapped_column(
        ForeignKey("knowledge_bases.id", ondelete="CASCADE"), index=True, nullable=False
    )
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), index=True, nullable=False
    )
    access_level: Mapped[KnowledgeBaseAccessLevel] = mapped_column(
        Enum(KnowledgeBaseAccessLevel, name="knowledge_base_access_level"),
        nullable=False,
    )
    granted_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )


class File(TimestampMixin, Base):
    __tablename__ = "files"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    owner_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    knowledge_base_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("knowledge_bases.id", ondelete="SET NULL"), index=True
    )
    bucket: Mapped[str] = mapped_column(String(255), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False)
    original_name: Mapped[str] = mapped_column(String(500), nullable=False)
    extension: Mapped[str] = mapped_column(String(20), nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    checksum_algorithm: Mapped[str | None] = mapped_column(String(50))
    checksum_value: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[FileStatus] = mapped_column(
        Enum(FileStatus, name="file_status"), default=FileStatus.PENDING, nullable=False
    )
    knowledge_status: Mapped[KnowledgeIngestionStatus] = mapped_column(
        Enum(KnowledgeIngestionStatus, name="knowledge_ingestion_status"),
        default=KnowledgeIngestionStatus.NOT_REQUESTED,
        nullable=False,
    )
    knowledge_error_code: Mapped[str | None] = mapped_column(String(100))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    custom_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class KnowledgeEntry(TimestampMixin, Base):
    __tablename__ = "knowledge_entries"
    __table_args__ = (
        Index("ix_knowledge_entries_kb_updated", "knowledge_base_id", "updated_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    knowledge_base_id: Mapped[UUID] = mapped_column(
        ForeignKey("knowledge_bases.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_file_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), index=True
    )
    entry_type: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_path: Mapped[str | None] = mapped_column(String(1000))
    format_version: Mapped[str | None] = mapped_column(String(50))
    publication_status: Mapped[KnowledgeEntryPublicationStatus] = mapped_column(
        Enum(KnowledgeEntryPublicationStatus, name="knowledge_entry_publication_status"),
        default=KnowledgeEntryPublicationStatus.PUBLISHED,
        nullable=False,
    )
    custom_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OkfConversionJob(TimestampMixin, Base):
    """Durable, idempotent hand-off from immutable source files to OKF entries."""

    __tablename__ = "okf_conversion_jobs"
    __table_args__ = (
        UniqueConstraint("file_id", "file_version", name="uq_okf_conversion_file_version"),
        Index("ix_okf_conversion_claim", "status", "next_attempt_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    file_id: Mapped[UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), index=True, nullable=False
    )
    knowledge_base_id: Mapped[UUID] = mapped_column(
        ForeignKey("knowledge_bases.id", ondelete="CASCADE"), index=True, nullable=False
    )
    file_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[OkfConversionStatus] = mapped_column(
        Enum(OkfConversionStatus, name="okf_conversion_status"),
        default=OkfConversionStatus.PENDING,
        nullable=False,
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    model: Mapped[str | None] = mapped_column(String(100))
    prompt_version: Mapped[str] = mapped_column(String(50), nullable=False)
    output_entry_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("knowledge_entries.id", ondelete="SET NULL"), unique=True
    )
    error_code: Mapped[str | None] = mapped_column(String(100))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    lease_id: Mapped[UUID | None] = mapped_column(Uuid, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UploadSession(Base):
    __tablename__ = "upload_sessions"
    __table_args__ = (
        UniqueConstraint("user_id", "idempotency_key", name="uq_upload_sessions_idempotency"),
        Index("ix_upload_sessions_status_expires_at", "status", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    file_id: Mapped[UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    storage_upload_id: Mapped[str | None] = mapped_column(Text)
    part_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    part_count: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[UploadSessionStatus] = mapped_column(
        Enum(UploadSessionStatus, name="upload_session_status"),
        default=UploadSessionStatus.INITIATED,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class QuotaCounter(Base):
    __tablename__ = "quota_counters"
    __table_args__ = (
        UniqueConstraint("user_id", "limit_key", "window_start", name="uq_quota_counter_window"),
        CheckConstraint("used_value >= 0", name="non_negative_used"),
        CheckConstraint("reserved_value >= 0", name="non_negative_reserved"),
        Index("ix_quota_counters_lookup", "user_id", "limit_key", "window_start"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    limit_key: Mapped[str] = mapped_column(String(100), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_value: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    reserved_value: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class QuotaReservation(Base):
    __tablename__ = "quota_reservations"
    __table_args__ = (
        UniqueConstraint("upload_session_id", "limit_key", name="uq_quota_reservation_metric"),
        CheckConstraint("amount >= 0", name="non_negative_amount"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    upload_session_id: Mapped[UUID] = mapped_column(
        ForeignKey("upload_sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    limit_key: Mapped[str] = mapped_column(String(100), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    amount: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[ReservationStatus] = mapped_column(
        Enum(ReservationStatus, name="reservation_status"),
        default=ReservationStatus.HELD,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    family_id: Mapped[UUID] = mapped_column(Uuid, default=uuid4, index=True, nullable=False)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    parent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"), index=True
    )
    replaced_by_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"), unique=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reuse_detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_resource", "resource_type", "resource_id"),)

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    actor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(150), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(255))
    request_id: Mapped[str | None] = mapped_column(String(100), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True, nullable=False
    )


class ApiKey(Base):
    """A revocable service credential whose cleartext is never persisted."""

    __tablename__ = "api_keys"
    __table_args__ = (
        CheckConstraint(
            "requests_per_minute >= 1 AND requests_per_minute <= 10000",
            name="api_key_rpm_range",
        ),
        Index("ix_api_keys_user_created", "user_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(24), index=True, nullable=False)
    permission_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    knowledge_base_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    requests_per_minute: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class LlmProviderConfig(TimestampMixin, Base):
    """Runtime provider selection and encrypted server-side credentials."""

    __tablename__ = "llm_provider_configs"
    __table_args__ = (
        CheckConstraint(
            "provider IN ('deepseek', 'qwen', 'minimax')",
            name="supported_llm_provider",
        ),
        Index(
            "uq_llm_provider_configs_default",
            "is_default",
            unique=True,
            postgresql_where=text("is_default"),
            sqlite_where=text("is_default = 1"),
        ),
    )

    provider: Mapped[str] = mapped_column(String(30), primary_key=True)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    api_key_ciphertext: Mapped[str | None] = mapped_column(Text)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    updated_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
