"""
Compliance Engine
=================
Evaluates a ParsedConfig against Cisco IOS security best-practice rules
and returns a ComplianceResult with per-rule verdicts and an overall score.

Rules
-----
SEC-001  service password-encryption must be enabled             HIGH
SEC-002  No SNMP community 'public' or 'private'                HIGH
SEC-003  SSH must be enabled; telnet should not be allowed       HIGH
SEC-004  NTP server must be configured                          MEDIUM
SEC-005  Loopback0 interface must exist                          LOW
SEC-006  All interfaces must have a description                  LOW
SEC-007  Banner MOTD must be present                            MEDIUM
SEC-008  AAA new-model must be configured                       HIGH
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from app.parser.ios_parser import ParsedConfig


class Severity(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class RuleResult:
    """Outcome of a single compliance rule."""
    rule_id: str
    description: str
    severity: Severity
    status: Status
    detail: str = ""


@dataclass
class ComplianceResult:
    """Aggregated compliance evaluation across all rules."""
    rules: list[RuleResult] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Weighted compliance score (0 – 100)."""
        if not self.rules:
            return 0.0
        weights = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
        total = sum(weights[r.severity] for r in self.rules)
        passed = sum(weights[r.severity] for r in self.rules if r.status == Status.PASS)
        return round((passed / total) * 100, 2) if total else 0.0

    @property
    def passed(self) -> int:
        return sum(1 for r in self.rules if r.status == Status.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.rules if r.status == Status.FAIL)

    @property
    def total(self) -> int:
        return len(self.rules)

    def to_dict(self) -> dict:
        """Serialise for JSON storage."""
        return {
            "score": self.score,
            "passed": self.passed,
            "failed": self.failed,
            "total": self.total,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "description": r.description,
                    "severity": r.severity.value,
                    "status": r.status.value,
                    "detail": r.detail,
                }
                for r in self.rules
            ],
        }


# ── Rule implementations ─────────────────────────────────────────────────────

def _check_sec001(cfg: ParsedConfig) -> RuleResult:
    ok = cfg.service_password_encryption
    return RuleResult(
        rule_id="SEC-001",
        description="service password-encryption must be enabled",
        severity=Severity.HIGH,
        status=Status.PASS if ok else Status.FAIL,
        detail=(
            "Found 'service password-encryption'"
            if ok
            else "Missing 'service password-encryption' — passwords stored in cleartext"
        ),
    )


def _check_sec002(cfg: ParsedConfig) -> RuleResult:
    weak = {"public", "private"}
    bad = [
        c.community_string
        for c in cfg.snmp_communities
        if c.community_string.lower() in weak
    ]
    ok = not bad
    return RuleResult(
        rule_id="SEC-002",
        description="No SNMP community 'public' or 'private' allowed",
        severity=Severity.HIGH,
        status=Status.PASS if ok else Status.FAIL,
        detail=(
            "All SNMP communities use strong strings"
            if ok
            else f"Weak SNMP community strings found: {', '.join(bad)}"
        ),
    )


def _check_sec003(cfg: ParsedConfig) -> RuleResult:
    ssh_version = cfg.ip_ssh_version is not None
    telnet_found = False
    ssh_on_vty = False
    for lc in cfg.line_configs:
        if lc.line_type == "vty":
            ti = [t.lower() for t in lc.transport_input]
            if "telnet" in ti:
                telnet_found = True
            if "ssh" in ti:
                ssh_on_vty = True

    ok = ssh_version and ssh_on_vty and not telnet_found
    details: list[str] = []
    if not ssh_version:
        details.append("ip ssh version not configured")
    if not ssh_on_vty:
        details.append("SSH not set as transport input on VTY lines")
    if telnet_found:
        details.append("Telnet allowed on VTY lines (insecure)")
    return RuleResult(
        rule_id="SEC-003",
        description="SSH must be enabled; telnet must not be allowed on VTY",
        severity=Severity.HIGH,
        status=Status.PASS if ok else Status.FAIL,
        detail="SSH properly configured on VTY lines" if ok else "; ".join(details),
    )


def _check_sec004(cfg: ParsedConfig) -> RuleResult:
    ok = len(cfg.ntp_servers) > 0
    return RuleResult(
        rule_id="SEC-004",
        description="At least one NTP server must be configured",
        severity=Severity.MEDIUM,
        status=Status.PASS if ok else Status.FAIL,
        detail=(
            f"NTP servers: {', '.join(n.address for n in cfg.ntp_servers)}"
            if ok
            else "No NTP server configured — clock synchronisation absent"
        ),
    )


def _check_sec005(cfg: ParsedConfig) -> RuleResult:
    lo = [i for i in cfg.interfaces if i.name.lower().startswith("loopback0")]
    ok = bool(lo)
    return RuleResult(
        rule_id="SEC-005",
        description="Loopback0 interface must be present",
        severity=Severity.LOW,
        status=Status.PASS if ok else Status.FAIL,
        detail=(
            "Loopback0 found"
            if ok
            else "No Loopback0 interface — required for stable router-id"
        ),
    )


def _check_sec006(cfg: ParsedConfig) -> RuleResult:
    missing = [
        i.name
        for i in cfg.interfaces
        if not i.shutdown and not i.description
    ]
    ok = not missing
    return RuleResult(
        rule_id="SEC-006",
        description="All active interfaces must have a description",
        severity=Severity.LOW,
        status=Status.PASS if ok else Status.FAIL,
        detail=(
            "All active interfaces have descriptions"
            if ok
            else f"Interfaces missing description: {', '.join(missing)}"
        ),
    )


def _check_sec007(cfg: ParsedConfig) -> RuleResult:
    ok = bool(cfg.banner_motd and cfg.banner_motd.strip())
    return RuleResult(
        rule_id="SEC-007",
        description="Banner MOTD must be configured",
        severity=Severity.MEDIUM,
        status=Status.PASS if ok else Status.FAIL,
        detail=(
            "Banner MOTD present"
            if ok
            else "No banner MOTD — unauthorised access warning missing"
        ),
    )


def _check_sec008(cfg: ParsedConfig) -> RuleResult:
    ok = cfg.aaa_new_model
    return RuleResult(
        rule_id="SEC-008",
        description="AAA new-model must be configured",
        severity=Severity.HIGH,
        status=Status.PASS if ok else Status.FAIL,
        detail=(
            "aaa new-model enabled"
            if ok
            else "aaa new-model not configured — centralised auth unavailable"
        ),
    )


# ── Rule registry ────────────────────────────────────────────────────────────

_RULES: list[Callable[[ParsedConfig], RuleResult]] = [
    _check_sec001,
    _check_sec002,
    _check_sec003,
    _check_sec004,
    _check_sec005,
    _check_sec006,
    _check_sec007,
    _check_sec008,
]


class ComplianceEngine:
    """Run all compliance rules against a ParsedConfig."""

    def __init__(
        self,
        rules: list[Callable[[ParsedConfig], RuleResult]] | None = None,
    ) -> None:
        self._rules = rules or _RULES

    def evaluate(self, cfg: ParsedConfig) -> ComplianceResult:
        """Evaluate all rules and return a :class:`ComplianceResult`."""
        result = ComplianceResult()
        for rule_fn in self._rules:
            try:
                result.rules.append(rule_fn(cfg))
            except Exception as exc:
                result.rules.append(RuleResult(
                    rule_id=getattr(rule_fn, '__name__', 'UNKNOWN'),
                    description="Rule evaluation error",
                    severity=Severity.HIGH,
                    status=Status.WARN,
                    detail=str(exc),
                ))
        return result
