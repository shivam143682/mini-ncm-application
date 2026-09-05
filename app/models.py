"""
SQLAlchemy ORM Models
=====================
Two tables:
  device_configs      — raw config text + parsed JSON snapshot
  compliance_reports  — compliance result linked to a device config
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DeviceConfig(Base):
    """Stores a submitted Cisco IOS configuration."""
    __tablename__ = "device_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    device_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True,
    )
    raw_config: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    raw_lines: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False,
    )

    # Relationship
    report: Mapped["ComplianceReport"] = relationship(
        "ComplianceReport",
        back_populates="device_config",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<DeviceConfig id={self.id} device={self.device_name}>"


class ComplianceReport(Base):
    """Compliance evaluation result for a DeviceConfig."""
    __tablename__ = "compliance_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    device_config_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("device_configs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total_rules: Mapped[int] = mapped_column(Integer, default=0)
    passed_rules: Mapped[int] = mapped_column(Integer, default=0)
    failed_rules: Mapped[int] = mapped_column(Integer, default=0)
    is_compliant: Mapped[bool] = mapped_column(Boolean, default=False)
    result_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )

    # Relationship back
    device_config: Mapped["DeviceConfig"] = relationship(
        "DeviceConfig", back_populates="report",
    )

    def __repr__(self) -> str:
        return f"<ComplianceReport id={self.id} score={self.score}>"
