"""
API Router
==========
All REST endpoints grouped under ``/api/v1``.

Endpoints
---------
  POST   /api/v1/parse                        → parse + compliance + store
  GET    /api/v1/configs                       → list stored device configs
  GET    /api/v1/configs/{config_id}           → get config detail
  DELETE /api/v1/configs/{config_id}           → delete config (cascades)
  GET    /api/v1/reports                       → list compliance reports
  GET    /api/v1/reports/{report_id}           → get specific report
  GET    /api/v1/reports/by-config/{config_id} → report for a config
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app import service
from app.database import get_db
from app.schemas import (
    ComplianceReportSchema,
    ConfigDetailSchema,
    ConfigListItem,
    ConfigParseRequest,
    ParseResponse,
    ReportListItem,
)

router = APIRouter(prefix="/api/v1", tags=["Cisco IOS Compliance"])


# ── Parse ────────────────────────────────────────────────────────────────────

@router.post(
    "/parse",
    response_model=ParseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Parse Cisco IOS config and run compliance check",
    description=(
        "Submit raw Cisco IOS configuration text. The API will:\n"
        "1. Parse the config (hostname, interfaces, routes, ACLs, SNMP, AAA, NTP…)\n"
        "2. Run 8 security compliance rules (SEC-001 → SEC-008)\n"
        "3. Store the device config + compliance report in PostgreSQL\n"
        "4. Return the full result including parsed data and per-rule verdict"
    ),
)
async def parse_config(
    request: ConfigParseRequest,
    db: AsyncSession = Depends(get_db),
) -> ParseResponse:
    db_config, db_report = await service.parse_and_store(
        config_text=request.config_text,
        device_name=request.device_name,
        db=db,
    )
    return ParseResponse(
        config=db_config,
        report=db_report,
        parsed_data=db_config.parsed_data,
    )


# ── Configs ──────────────────────────────────────────────────────────────────

@router.get(
    "/configs",
    response_model=list[ConfigListItem],
    summary="List all stored device configurations",
)
async def list_configs(
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    db: AsyncSession = Depends(get_db),
) -> list[ConfigListItem]:
    configs = await service.list_configs(db, skip=skip, limit=limit)
    return [
        ConfigListItem(
            id=c.id,
            device_name=c.device_name,
            raw_lines=c.raw_lines,
            created_at=c.created_at,
            has_report=c.report is not None,
        )
        for c in configs
    ]


@router.get(
    "/configs/{config_id}",
    response_model=ConfigDetailSchema,
    summary="Get a specific device config with full parsed data",
)
async def get_config(
    config_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ConfigDetailSchema:
    cfg = await service.get_config_by_id(config_id, db)
    if not cfg:
        raise HTTPException(status_code=404, detail="Device config not found")
    return cfg


@router.delete(
    "/configs/{config_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a device config and its compliance report",
    response_class=Response,
)
async def delete_config(
    config_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    deleted = await service.delete_config(config_id, db)
    if not deleted:
        raise HTTPException(status_code=404, detail="Device config not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Reports ──────────────────────────────────────────────────────────────────

@router.get(
    "/reports",
    response_model=list[ReportListItem],
    summary="List all compliance reports",
)
async def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> list[ReportListItem]:
    return await service.list_reports(db, skip=skip, limit=limit)


@router.get(
    "/reports/{report_id}",
    response_model=ComplianceReportSchema,
    summary="Get a specific compliance report by ID",
)
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ComplianceReportSchema:
    report = await service.get_report_by_id(report_id, db)
    if not report:
        raise HTTPException(status_code=404, detail="Compliance report not found")
    return report


@router.get(
    "/reports/by-config/{config_id}",
    response_model=ComplianceReportSchema,
    summary="Get the compliance report for a given device config",
)
async def get_report_by_config(
    config_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ComplianceReportSchema:
    report = await service.get_report_by_config_id(config_id, db)
    if not report:
        raise HTTPException(
            status_code=404,
            detail="No compliance report found for this config",
        )
    return report
