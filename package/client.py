"""
Cisco IOS Compliance — Python SDK Client
=========================================
A synchronous Python client that wraps the FastAPI REST endpoints,
making it easy to interact with the Cisco IOS Compliance Platform
from any Python script or notebook.

Usage::

    from sdk import CiscoComplianceClient

    client = CiscoComplianceClient(base_url="http://localhost:8000")

    # Check health
    print(client.health_check())

    # Parse a config and get compliance results
    result = client.parse_config(
        config_text=open("router.cfg").read(),
        device_name="Core-Router-01",
    )
    print(f"Score: {result['report']['score']}")
    print(f"Compliant: {result['report']['is_compliant']}")
"""

from __future__ import annotations

from typing import Any

import requests


class CiscoComplianceClient:
    """
    Synchronous Python SDK client for the Cisco IOS Compliance API.

    Parameters
    ----------
    base_url : str
        Root URL of the running FastAPI service (e.g. ``http://localhost:8000``).
    timeout : int
        Request timeout in seconds (default: 30).
    """

    def __init__(self, base_url: str = "http://localhost:8000", timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    # ── Internal helpers ─────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _get(self, path: str, params: dict | None = None) -> Any:
        resp = self._session.get(self._url(path), params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, json_body: dict) -> Any:
        resp = self._session.post(self._url(path), json=json_body, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def _delete(self, path: str) -> bool:
        resp = self._session.delete(self._url(path), timeout=self.timeout)
        return resp.status_code == 204

    # ── Public API ───────────────────────────────────────────────────────

    def health_check(self) -> dict[str, Any]:
        """Check API and database health."""
        return self._get("/health")

    def parse_config(
        self,
        config_text: str,
        device_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Submit a raw Cisco IOS config for parsing and compliance evaluation.

        Returns the full result including parsed data and compliance report.
        """
        body: dict[str, Any] = {"config_text": config_text}
        if device_name:
            body["device_name"] = device_name
        return self._post("/api/v1/parse", body)

    def list_configs(
        self, skip: int = 0, limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List all stored device configurations."""
        return self._get("/api/v1/configs", params={"skip": skip, "limit": limit})

    def get_config(self, config_id: str) -> dict[str, Any]:
        """Get a specific device configuration by ID."""
        return self._get(f"/api/v1/configs/{config_id}")

    def delete_config(self, config_id: str) -> bool:
        """Delete a device configuration and its compliance report."""
        return self._delete(f"/api/v1/configs/{config_id}")

    def list_reports(
        self, skip: int = 0, limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List all compliance reports."""
        return self._get("/api/v1/reports", params={"skip": skip, "limit": limit})

    def get_report(self, report_id: str) -> dict[str, Any]:
        """Get a specific compliance report by ID."""
        return self._get(f"/api/v1/reports/{report_id}")

    def get_report_by_config(self, config_id: str) -> dict[str, Any]:
        """Get the compliance report for a given device config."""
        return self._get(f"/api/v1/reports/by-config/{config_id}")
