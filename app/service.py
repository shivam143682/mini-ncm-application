"""
Service Layer
=============
Orchestrates:  Parser → Compliance Engine → PostgreSQL persistence.
All functions are async and accept an AsyncSession from the DI system.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.compliance.engine import ComplianceEngine
from app.models import ComplianceReport, DeviceConfig
from app.parser.ios_parser import CiscoIOSParser


_engine = ComplianceEngine()


# ── Parse & Store ────────────────────────────────────────────────────────────

async def parse_and_store(
    config_text: str,
    device_name: str | None,
    db: AsyncSession,
) -> tuple[DeviceConfig, ComplianceReport]:
    """
    1. Parse raw config text with CiscoIOSParser
    2. Run ComplianceEngine on the parsed result
    3. Persist both to PostgreSQL
    4. Return (DeviceConfig, ComplianceReport)
    """
    # Step 1: Parse
    parser = CiscoIOSParser(config_text)
    parsed = parser.parse()
    parsed_dict = parsed.to_dict()

    # Use parsed hostname as device_name if not supplied
    resolved_name = device_name or parsed.hostname or "Unknown Device"

    # Step 2: Compliance
    compliance = _engine.evaluate(parsed)
    compliance_dict = compliance.to_dict()

    # Step 3: Persist DeviceConfig
    db_config = DeviceConfig(
        device_name=resolved_name,
        raw_config=config_text,
        parsed_data=parsed_dict,
        raw_lines=parsed.raw_lines,
    )
    db.add(db_config)
    await db.flush()

    # Step 4: Persist ComplianceReport
    db_report = ComplianceReport(
        device_config_id=db_config.id,
        score=compliance.score,
        total_rules=compliance.total,
        passed_rules=compliance.passed,
        failed_rules=compliance.failed,
        is_compliant=compliance.score >= 80.0,
        result_data=compliance_dict,
    )
    db.add(db_report)
    await db.commit()
    await db.refresh(db_config)
    await db.refresh(db_report)

    return db_config, db_report


# ── Retrieval helpers ────────────────────────────────────────────────────────

async def list_configs(
    db: AsyncSession, skip: int = 0, limit: int = 50,
) -> list[DeviceConfig]:
    result = await db.execute(
        select(DeviceConfig)
        .options(selectinload(DeviceConfig.report))
        .order_by(DeviceConfig.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return list(result.scalars().all())


async def get_config_by_id(
    config_id: uuid.UUID, db: AsyncSession,
) -> DeviceConfig | None:
    result = await db.execute(
        select(DeviceConfig)
        .where(DeviceConfig.id == config_id)
        .options(selectinload(DeviceConfig.report))
    )
    return result.scalar_one_or_none()


async def delete_config(
    config_id: uuid.UUID, db: AsyncSession,
) -> bool:
    cfg = await get_config_by_id(config_id, db)
    if not cfg:
        return False
    await db.delete(cfg)
    await db.commit()
    return True


async def list_reports(
    db: AsyncSession, skip: int = 0, limit: int = 50,
) -> list[ComplianceReport]:
    result = await db.execute(
        select(ComplianceReport)
        .order_by(ComplianceReport.evaluated_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return list(result.scalars().all())


async def get_report_by_id(
    report_id: uuid.UUID, db: AsyncSession,
) -> ComplianceReport | None:
    result = await db.execute(
        select(ComplianceReport).where(ComplianceReport.id == report_id)
    )
    return result.scalar_one_or_none()


async def get_report_by_config_id(
    config_id: uuid.UUID, db: AsyncSession,
) -> ComplianceReport | None:
    result = await db.execute(
        select(ComplianceReport).where(
            ComplianceReport.device_config_id == config_id
        )
    )
    return result.scalar_one_or_none()
