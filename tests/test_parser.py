"""
Unit Tests — Cisco IOS Parser & Compliance Engine
==================================================
Run with:  python -m pytest tests/ -v

These tests validate the parser and compliance engine in isolation
(no database or Docker required).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is importable
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from app.parser.ios_parser import CiscoIOSParser
from app.compliance.engine import ComplianceEngine, Status


# ── Sample config used across tests ──────────────────────────────────────────

SAMPLE_CONFIG = """
hostname TestRouter
service password-encryption
enable secret 5 $1$abc$hash
ip domain-name test.local
ip ssh version 2
aaa new-model
aaa authentication login default local
!
interface Loopback0
 description Router-ID
 ip address 10.255.0.1 255.255.255.255
!
interface GigabitEthernet0/0
 description WAN Uplink
 ip address 192.168.1.1 255.255.255.0
!
interface GigabitEthernet0/1
 description LAN
 ip address 10.1.0.1 255.255.255.0
!
interface GigabitEthernet0/2
 shutdown
!
ip route 0.0.0.0 0.0.0.0 192.168.1.254
ip route 172.16.0.0 255.240.0.0 10.1.0.254 100
!
access-list 10 permit 10.1.0.0 0.0.0.255
access-list 10 deny any
!
snmp-server community MyStr0ngStr RO
!
ntp server 10.0.0.1 prefer
ntp server 10.0.0.2
!
banner motd ^Authorised access only^
!
line con 0
 login local
 exec-timeout 5 0
!
line vty 0 4
 login local
 transport input ssh
 exec-timeout 10 0
!
end
"""


def _parse() -> "ParsedConfig":
    return CiscoIOSParser(SAMPLE_CONFIG).parse()


# ── Parser Tests ─────────────────────────────────────────────────────────────

class TestCiscoIOSParser:
    def test_hostname(self):
        cfg = _parse()
        assert cfg.hostname == "TestRouter"

    def test_domain_name(self):
        cfg = _parse()
        assert cfg.domain_name == "test.local"

    def test_enable_secret(self):
        cfg = _parse()
        assert cfg.enable_secret is True

    def test_password_encryption(self):
        cfg = _parse()
        assert cfg.service_password_encryption is True

    def test_ssh_version(self):
        cfg = _parse()
        assert cfg.ip_ssh_version == "2"

    def test_aaa_new_model(self):
        cfg = _parse()
        assert cfg.aaa_new_model is True

    def test_aaa_authentication(self):
        cfg = _parse()
        assert len(cfg.aaa_authentication) >= 1
        assert "login" in cfg.aaa_authentication[0]

    def test_banner_motd(self):
        cfg = _parse()
        assert cfg.banner_motd is not None
        assert "Authorised" in cfg.banner_motd

    def test_interfaces_count(self):
        cfg = _parse()
        # Loopback0, Gi0/0, Gi0/1, Gi0/2
        assert len(cfg.interfaces) == 4

    def test_interface_ip(self):
        cfg = _parse()
        lo = [i for i in cfg.interfaces if "Loopback" in i.name]
        assert len(lo) == 1
        assert lo[0].ip_address == "10.255.0.1"

    def test_interface_shutdown(self):
        cfg = _parse()
        gi2 = [i for i in cfg.interfaces if "0/2" in i.name]
        assert len(gi2) == 1
        assert gi2[0].shutdown is True

    def test_interface_description(self):
        cfg = _parse()
        gi0 = [i for i in cfg.interfaces if "0/0" in i.name]
        assert gi0[0].description == "WAN Uplink"

    def test_static_routes(self):
        cfg = _parse()
        assert len(cfg.static_routes) == 2
        default = [r for r in cfg.static_routes if r.network == "0.0.0.0"]
        assert len(default) == 1
        assert default[0].next_hop == "192.168.1.254"

    def test_static_route_admin_distance(self):
        cfg = _parse()
        r172 = [r for r in cfg.static_routes if r.network == "172.16.0.0"]
        assert r172[0].admin_distance == 100

    def test_access_lists(self):
        cfg = _parse()
        assert len(cfg.access_lists) >= 1
        acl10 = [a for a in cfg.access_lists if a.name_or_number == "10"]
        assert len(acl10) == 1
        assert len(acl10[0].entries) == 2

    def test_snmp_communities(self):
        cfg = _parse()
        assert len(cfg.snmp_communities) == 1
        assert cfg.snmp_communities[0].community_string == "MyStr0ngStr"
        assert cfg.snmp_communities[0].access_type == "RO"

    def test_ntp_servers(self):
        cfg = _parse()
        assert len(cfg.ntp_servers) == 2
        preferred = [n for n in cfg.ntp_servers if n.prefer]
        assert len(preferred) == 1
        assert preferred[0].address == "10.0.0.1"

    def test_line_configs(self):
        cfg = _parse()
        # con 0, vty 0 4
        assert len(cfg.line_configs) >= 2
        vty = [l for l in cfg.line_configs if l.line_type == "vty"]
        assert len(vty) >= 1
        assert "ssh" in vty[0].transport_input

    def test_to_dict(self):
        cfg = _parse()
        d = cfg.to_dict()
        assert isinstance(d, dict)
        assert d["hostname"] == "TestRouter"
        assert isinstance(d["interfaces"], list)

    def test_raw_lines(self):
        cfg = _parse()
        assert cfg.raw_lines > 0


# ── Compliance Engine Tests ──────────────────────────────────────────────────

class TestComplianceEngine:
    def test_full_compliance(self):
        """The sample config should pass all 8 rules."""
        cfg = _parse()
        engine = ComplianceEngine()
        result = engine.evaluate(cfg)
        assert result.total == 8
        assert result.score == 100.0
        assert result.passed == 8
        assert result.failed == 0

    def test_fail_no_password_encryption(self):
        """Config without 'service password-encryption' should fail SEC-001."""
        text = "hostname Bare\ninterface Loopback0\n ip address 1.1.1.1 255.255.255.255"
        cfg = CiscoIOSParser(text).parse()
        engine = ComplianceEngine()
        result = engine.evaluate(cfg)
        sec001 = [r for r in result.rules if r.rule_id == "SEC-001"]
        assert sec001[0].status == Status.FAIL

    def test_fail_weak_snmp(self):
        """Config with snmp community 'public' should fail SEC-002."""
        text = "hostname Weak\nsnmp-server community public RO"
        cfg = CiscoIOSParser(text).parse()
        engine = ComplianceEngine()
        result = engine.evaluate(cfg)
        sec002 = [r for r in result.rules if r.rule_id == "SEC-002"]
        assert sec002[0].status == Status.FAIL

    def test_score_range(self):
        """Score must be between 0 and 100."""
        text = "hostname Minimal"
        cfg = CiscoIOSParser(text).parse()
        engine = ComplianceEngine()
        result = engine.evaluate(cfg)
        assert 0.0 <= result.score <= 100.0

    def test_to_dict(self):
        cfg = _parse()
        engine = ComplianceEngine()
        result = engine.evaluate(cfg)
        d = result.to_dict()
        assert "score" in d
        assert "rules" in d
        assert len(d["rules"]) == 8
