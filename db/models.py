"""SQLAlchemy 2.0 models — AuthScope core schema (ISS-004)."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class ScanStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    WAF_BLOCKED = "waf_blocked"


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    api_keys: Mapped[list[ApiKey]] = relationship(back_populates="user")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sha256 hex
    label: Mapped[str | None] = mapped_column(Text, nullable=True)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=60)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship(back_populates="api_keys")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_url_created", "normalized_url", "created_at"),
        Index("ix_scans_status", "status"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    url: Mapped[str] = mapped_column(Text)
    normalized_url: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default=ScanStatus.QUEUED.value)
    difficulty_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    security_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    options: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    auth_finding: Mapped[AuthFinding | None] = relationship(
        back_populates="scan", uselist=False
    )
    security_finding: Mapped[SecurityFinding | None] = relationship(
        back_populates="scan", uselist=False
    )
    antibot_finding: Mapped[AntibotFinding | None] = relationship(
        back_populates="scan", uselist=False
    )
    artifacts: Mapped[Artifacts | None] = relationship(back_populates="scan", uselist=False)


class AuthFinding(Base):
    __tablename__ = "auth_findings"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), unique=True
    )
    provider: Mapped[str] = mapped_column(String(50))
    flow: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="auth_finding")


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), primary_key=True
    )
    has_csrf: Mapped[bool] = mapped_column(Boolean, default=False)
    has_hsts: Mapped[bool] = mapped_column(Boolean, default=False)
    has_csp: Mapped[bool] = mapped_column(Boolean, default=False)
    cookie_flags: Mapped[dict] = mapped_column(JSONB, default=dict)
    mfa_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_headers: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="security_finding")


class AntibotFinding(Base):
    __tablename__ = "antibot_findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), primary_key=True
    )
    captcha_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    captcha_visible: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    waf_providers: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    fingerprinting_signals: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    cookies_detected: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    difficulty_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="antibot_finding")


class Artifacts(Base):
    __tablename__ = "artifacts"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id"), primary_key=True
    )
    har_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    screenshot_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    dom_snapshot_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    trace_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="artifacts")


class Signature(Base):
    __tablename__ = "signatures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    category: Mapped[str] = mapped_column(Text)  # auth | antibot | captcha | fingerprinting
    name: Mapped[str] = mapped_column(Text)
    yaml_definition: Mapped[dict] = mapped_column(JSONB)
    version: Mapped[int] = mapped_column(Integer, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    url: Mapped[str] = mapped_column(Text)
    secret: Mapped[str] = mapped_column(Text)  # for HMAC signing
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Feedback(Base):
    """False-positive / confirmation feedback loop input."""

    __tablename__ = "feedback"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    finding_kind: Mapped[str] = mapped_column(Text)  # auth|security|antibot|captcha...
    signature_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    verdict: Mapped[str] = mapped_column(Text)  # correct | false_positive
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
