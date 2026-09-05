"""
Cisco IOS Configuration Parser
===============================
Pure-Python parser that converts raw Cisco IOS configuration text
into structured Python dataclasses.

Supported features:
  - Hostname & domain name
  - Interfaces (IP, mask, shutdown, description, duplex, speed)
  - Static routes (network, mask, next-hop, admin distance)
  - OSPF (process ID, router-ID, networks, passive interfaces)
  - BGP (ASN, router-ID, neighbors, networks)
  - ACLs (standard, extended, named)
  - SNMP community strings
  - NTP servers
  - AAA configuration
  - Line (console / vty) configuration
  - Banner MOTD
  - SSH version & password services

Usage:
    from app.parser import CiscoIOSParser

    parser = CiscoIOSParser(config_text)
    result = parser.parse()
    print(result.hostname)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any


# ── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class InterfaceConfig:
    """Parsed interface block."""
    name: str
    ip_address: str | None = None
    subnet_mask: str | None = None
    description: str | None = None
    shutdown: bool = False
    duplex: str | None = None
    speed: str | None = None


@dataclass
class StaticRoute:
    """Parsed ip route entry."""
    network: str
    mask: str
    next_hop: str
    admin_distance: int = 1


@dataclass
class OspfConfig:
    """Parsed router ospf block."""
    process_id: int
    router_id: str | None = None
    networks: list[dict[str, str]] = field(default_factory=list)
    passive_interfaces: list[str] = field(default_factory=list)


@dataclass
class BgpConfig:
    """Parsed router bgp block."""
    asn: int
    router_id: str | None = None
    neighbors: list[dict[str, str]] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)


@dataclass
class AclEntry:
    """Single ACL permit/deny entry."""
    sequence: int | None
    action: str
    protocol: str | None
    source: str
    destination: str | None = None
    port_info: str | None = None


@dataclass
class AccessList:
    """Parsed access-list (numbered or named)."""
    name_or_number: str
    acl_type: str
    entries: list[AclEntry] = field(default_factory=list)


@dataclass
class SnmpCommunity:
    """Parsed snmp-server community."""
    community_string: str
    access_type: str
    acl: str | None = None


@dataclass
class NtpServer:
    """Parsed ntp server entry."""
    address: str
    prefer: bool = False


@dataclass
class LineConfig:
    """Parsed line con/vty/aux block."""
    line_type: str
    range_start: int
    range_end: int
    login_method: str | None = None
    transport_input: list[str] = field(default_factory=list)
    password: str | None = None
    exec_timeout: str | None = None


@dataclass
class ParsedConfig:
    """Top-level container for all parsed Cisco IOS data."""
    hostname: str | None = None
    domain_name: str | None = None
    enable_secret: bool = False
    service_password_encryption: bool = False
    ip_ssh_version: str | None = None
    interfaces: list[InterfaceConfig] = field(default_factory=list)
    static_routes: list[StaticRoute] = field(default_factory=list)
    ospf_configs: list[OspfConfig] = field(default_factory=list)
    bgp_config: BgpConfig | None = None
    access_lists: list[AccessList] = field(default_factory=list)
    snmp_communities: list[SnmpCommunity] = field(default_factory=list)
    ntp_servers: list[NtpServer] = field(default_factory=list)
    aaa_new_model: bool = False
    aaa_authentication: list[str] = field(default_factory=list)
    aaa_authorization: list[str] = field(default_factory=list)
    line_configs: list[LineConfig] = field(default_factory=list)
    banner_motd: str | None = None
    raw_lines: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialise the entire parsed config to a plain dict (JSON-safe)."""
        def _convert(obj: Any) -> Any:
            if hasattr(obj, '__dataclass_fields__'):
                return {k: _convert(v) for k, v in asdict(obj).items()}
            if isinstance(obj, list):
                return [_convert(i) for i in obj]
            return obj
        return _convert(self)


# ── Parser ───────────────────────────────────────────────────────────────────

class CiscoIOSParser:
    """
    Parse a Cisco IOS configuration string into a :class:`ParsedConfig`.

    Example::

        >>> parser = CiscoIOSParser(raw_text)
        >>> cfg = parser.parse()
        >>> cfg.hostname
        'Router1'
    """

    # Compiled regex patterns (class-level for performance)
    _RE_HOSTNAME       = re.compile(r'^hostname\s+(\S+)', re.M)
    _RE_DOMAIN_NAME    = re.compile(r'^ip\s+domain.name\s+(\S+)', re.M)
    _RE_ENABLE_SECRET  = re.compile(r'^enable\s+secret\s+', re.M)
    _RE_SVC_PWD_ENC    = re.compile(r'^service\s+password-encryption', re.M)
    _RE_SSH_VERSION    = re.compile(r'^ip\s+ssh\s+version\s+(\d)', re.M)
    _RE_AAA_NEW_MODEL  = re.compile(r'^aaa\s+new-model', re.M)
    _RE_AAA_AUTH       = re.compile(r'^(aaa\s+authentication\s+.+)', re.M)
    _RE_AAA_AUTHZ      = re.compile(r'^(aaa\s+authorization\s+.+)', re.M)
    _RE_BANNER_START   = re.compile(r'^banner\s+motd\s+(.+)', re.M)
    _RE_INTF           = re.compile(r'^interface\s+(\S+.*)', re.M)
    _RE_IP_ADDR        = re.compile(r'^\s+ip\s+address\s+(\d[\d.]+)\s+(\d[\d.]+)', re.M)
    _RE_SHUTDOWN       = re.compile(r'^\s+shutdown', re.M)
    _RE_DESCRIPTION    = re.compile(r'^\s+description\s+(.*)', re.M)
    _RE_DUPLEX         = re.compile(r'^\s+duplex\s+(\S+)', re.M)
    _RE_SPEED          = re.compile(r'^\s+speed\s+(\S+)', re.M)
    _RE_IP_ROUTE       = re.compile(
        r'^ip\s+route\s+(\d[\d.]+)\s+(\d[\d.]+)\s+(\S+)(?:\s+(\d+))?', re.M)
    _RE_OSPF_START     = re.compile(r'^router\s+ospf\s+(\d+)', re.M)
    _RE_OSPF_RID       = re.compile(r'^\s+router-id\s+(\S+)', re.M)
    _RE_OSPF_NET       = re.compile(r'^\s+network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', re.M)
    _RE_OSPF_PASSIVE   = re.compile(r'^\s+passive-interface\s+(\S+)', re.M)
    _RE_BGP_START      = re.compile(r'^router\s+bgp\s+(\d+)', re.M)
    _RE_BGP_RID        = re.compile(r'^\s+bgp\s+router-id\s+(\S+)', re.M)
    _RE_BGP_NEIGHBOR   = re.compile(r'^\s+neighbor\s+(\S+)\s+remote-as\s+(\d+)', re.M)
    _RE_BGP_NET        = re.compile(r'^\s+network\s+(\S+)', re.M)
    _RE_STD_ACL        = re.compile(r'^access-list\s+(\d+)\s+(permit|deny)\s+(.*)', re.M)
    _RE_NAMED_ACL      = re.compile(r'^ip\s+access-list\s+(standard|extended)\s+(\S+)', re.M)
    _RE_NAMED_ENTRY    = re.compile(r'^\s+(\d+)?\s*(permit|deny)\s+(\S+)\s*(.*)', re.M)
    _RE_SNMP_COMM      = re.compile(
        r'^snmp-server\s+community\s+(\S+)\s+(RO|RW)(\s+\S+)?', re.M)
    _RE_NTP            = re.compile(r'^ntp\s+server\s+(\S+)(.*)', re.M)
    _RE_LINE           = re.compile(r'^line\s+(con|vty|aux)\s+(\d+)(?:\s+(\d+))?', re.M)
    _RE_TRANSPORT      = re.compile(r'^\s+transport\s+input\s+(.*)', re.M)
    _RE_LOGIN          = re.compile(r'^\s+login\s*(.*)', re.M)
    _RE_LINE_PWD       = re.compile(r'^\s+password\s+(\S+)', re.M)
    _RE_EXEC_TIMEOUT   = re.compile(r'^\s+exec-timeout\s+(\d+\s*\d*)', re.M)

    def __init__(self, config_text: str) -> None:
        self._text = config_text.strip()
        self._lines = self._text.splitlines()

    # ── Public API ───────────────────────────────────────────────────────

    def parse(self) -> ParsedConfig:
        """Parse the configuration and return a :class:`ParsedConfig`."""
        cfg = ParsedConfig(raw_lines=len(self._lines))
        cfg.hostname                    = self._scalar(self._RE_HOSTNAME)
        cfg.domain_name                 = self._scalar(self._RE_DOMAIN_NAME)
        cfg.enable_secret               = self._flag(self._RE_ENABLE_SECRET)
        cfg.service_password_encryption = self._flag(self._RE_SVC_PWD_ENC)
        cfg.ip_ssh_version              = self._scalar(self._RE_SSH_VERSION)
        cfg.aaa_new_model               = self._flag(self._RE_AAA_NEW_MODEL)
        cfg.aaa_authentication          = self._RE_AAA_AUTH.findall(self._text)
        cfg.aaa_authorization           = self._RE_AAA_AUTHZ.findall(self._text)
        cfg.banner_motd                 = self._parse_banner_motd()
        cfg.interfaces                  = self._parse_interfaces()
        cfg.static_routes               = self._parse_static_routes()
        cfg.ospf_configs                = self._parse_ospf()
        cfg.bgp_config                  = self._parse_bgp()
        cfg.access_lists                = self._parse_acls()
        cfg.snmp_communities            = self._parse_snmp()
        cfg.ntp_servers                 = self._parse_ntp()
        cfg.line_configs                = self._parse_lines()
        return cfg

    # ── Scalar / flag helpers ────────────────────────────────────────────

    def _scalar(self, pattern: re.Pattern) -> str | None:
        m = pattern.search(self._text)
        return m.group(1) if m else None

    def _flag(self, pattern: re.Pattern) -> bool:
        return bool(pattern.search(self._text))

    # ── Banner ───────────────────────────────────────────────────────────

    def _parse_banner_motd(self) -> str | None:
        m = self._RE_BANNER_START.search(self._text)
        if not m:
            return None
        first_line = m.group(1).strip()
        if not first_line:
            return None
        delimiter = first_line[0]
        pattern = re.compile(
            r'banner\s+motd\s+' + re.escape(delimiter)
            + r'(.*?)' + re.escape(delimiter),
            re.DOTALL,
        )
        bm = pattern.search(self._text)
        return bm.group(1).strip() if bm else first_line

    # ── Interfaces ───────────────────────────────────────────────────────

    def _parse_interfaces(self) -> list[InterfaceConfig]:
        interfaces: list[InterfaceConfig] = []
        current_name: str | None = None
        current_block: list[str] = []

        def _flush() -> None:
            if current_name is None:
                return
            block_text = '\n'.join(current_block)
            intf = InterfaceConfig(name=current_name)
            ip_m = self._RE_IP_ADDR.search(block_text)
            if ip_m:
                intf.ip_address  = ip_m.group(1)
                intf.subnet_mask = ip_m.group(2)
            desc_m = self._RE_DESCRIPTION.search(block_text)
            if desc_m:
                intf.description = desc_m.group(1).strip()
            intf.shutdown = bool(self._RE_SHUTDOWN.search(block_text))
            dup_m = self._RE_DUPLEX.search(block_text)
            if dup_m:
                intf.duplex = dup_m.group(1)
            spd_m = self._RE_SPEED.search(block_text)
            if spd_m:
                intf.speed = spd_m.group(1)
            interfaces.append(intf)

        for line in self._lines:
            m = self._RE_INTF.match(line)
            if m:
                _flush()
                current_name = m.group(1).strip()
                current_block = [line]
            elif current_name is not None:
                if line and not line[0].isspace() and not line.startswith('!'):
                    _flush()
                    current_name = None
                    current_block = []
                else:
                    current_block.append(line)
        _flush()
        return interfaces

    # ── Static routes ────────────────────────────────────────────────────

    def _parse_static_routes(self) -> list[StaticRoute]:
        return [
            StaticRoute(
                network=m.group(1),
                mask=m.group(2),
                next_hop=m.group(3),
                admin_distance=int(m.group(4)) if m.group(4) else 1,
            )
            for m in self._RE_IP_ROUTE.finditer(self._text)
        ]

    # ── OSPF ─────────────────────────────────────────────────────────────

    def _parse_ospf(self) -> list[OspfConfig]:
        ospf_list: list[OspfConfig] = []
        i = 0
        while i < len(self._lines):
            m = self._RE_OSPF_START.match(self._lines[i])
            if m:
                ospf = OspfConfig(process_id=int(m.group(1)))
                i += 1
                block: list[str] = []
                while i < len(self._lines) and (
                    not self._lines[i]
                    or self._lines[i][0].isspace()
                    or self._lines[i].startswith('!')
                ):
                    block.append(self._lines[i])
                    i += 1
                block_text = '\n'.join(block)
                rid = self._RE_OSPF_RID.search(block_text)
                if rid:
                    ospf.router_id = rid.group(1)
                for nm in self._RE_OSPF_NET.finditer(block_text):
                    ospf.networks.append({
                        'network': nm.group(1),
                        'wildcard': nm.group(2),
                        'area': nm.group(3),
                    })
                for pm in self._RE_OSPF_PASSIVE.finditer(block_text):
                    ospf.passive_interfaces.append(pm.group(1))
                ospf_list.append(ospf)
            else:
                i += 1
        return ospf_list

    # ── BGP ──────────────────────────────────────────────────────────────

    def _parse_bgp(self) -> BgpConfig | None:
        for idx, line in enumerate(self._lines):
            m = self._RE_BGP_START.match(line)
            if m:
                bgp = BgpConfig(asn=int(m.group(1)))
                block: list[str] = []
                for j in range(idx + 1, len(self._lines)):
                    if (
                        self._lines[j]
                        and not self._lines[j][0].isspace()
                        and not self._lines[j].startswith('!')
                    ):
                        break
                    block.append(self._lines[j])
                block_text = '\n'.join(block)
                rid = self._RE_BGP_RID.search(block_text)
                if rid:
                    bgp.router_id = rid.group(1)
                for nm in self._RE_BGP_NEIGHBOR.finditer(block_text):
                    bgp.neighbors.append(
                        {'address': nm.group(1), 'remote_as': nm.group(2)}
                    )
                for bm in self._RE_BGP_NET.finditer(block_text):
                    bgp.networks.append(bm.group(1))
                return bgp
        return None

    # ── ACLs ─────────────────────────────────────────────────────────────

    def _parse_acls(self) -> list[AccessList]:
        acls: dict[str, AccessList] = {}

        # Numbered ACLs
        for m in self._RE_STD_ACL.finditer(self._text):
            num = m.group(1)
            try:
                n = int(num)
                is_std = (1 <= n <= 99) or (1300 <= n <= 1999)
            except ValueError:
                is_std = True
            if num not in acls:
                acls[num] = AccessList(
                    name_or_number=num,
                    acl_type='standard' if is_std else 'extended',
                )
            acls[num].entries.append(AclEntry(
                sequence=None,
                action=m.group(2),
                protocol=None,
                source=m.group(3).strip(),
            ))

        # Named ACLs
        i = 0
        while i < len(self._lines):
            nm = self._RE_NAMED_ACL.match(self._lines[i])
            if nm:
                acl_type = nm.group(1)
                name = nm.group(2)
                acl = AccessList(name_or_number=name, acl_type=acl_type)
                i += 1
                while i < len(self._lines) and (
                    self._lines[i].startswith(' ')
                    or self._lines[i].startswith('\t')
                ):
                    em = self._RE_NAMED_ENTRY.match(self._lines[i])
                    if em:
                        acl.entries.append(AclEntry(
                            sequence=int(em.group(1)) if em.group(1) else None,
                            action=em.group(2),
                            protocol=None,
                            source=em.group(3),
                            destination=em.group(4).strip() or None,
                        ))
                    i += 1
                acls[name] = acl
            else:
                i += 1
        return list(acls.values())

    # ── SNMP ─────────────────────────────────────────────────────────────

    def _parse_snmp(self) -> list[SnmpCommunity]:
        return [
            SnmpCommunity(
                community_string=m.group(1),
                access_type=m.group(2),
                acl=m.group(3).strip() if m.group(3) else None,
            )
            for m in self._RE_SNMP_COMM.finditer(self._text)
        ]

    # ── NTP ──────────────────────────────────────────────────────────────

    def _parse_ntp(self) -> list[NtpServer]:
        return [
            NtpServer(
                address=m.group(1),
                prefer='prefer' in m.group(2),
            )
            for m in self._RE_NTP.finditer(self._text)
        ]

    # ── Line configs ─────────────────────────────────────────────────────

    def _parse_lines(self) -> list[LineConfig]:
        configs: list[LineConfig] = []
        i = 0
        while i < len(self._lines):
            m = self._RE_LINE.match(self._lines[i])
            if m:
                lc = LineConfig(
                    line_type=m.group(1),
                    range_start=int(m.group(2)),
                    range_end=int(m.group(3)) if m.group(3) else int(m.group(2)),
                )
                i += 1
                block: list[str] = []
                while i < len(self._lines) and (
                    self._lines[i].startswith(' ')
                    or self._lines[i].startswith('\t')
                ):
                    block.append(self._lines[i])
                    i += 1
                block_text = '\n'.join(block)
                t_m = self._RE_TRANSPORT.search(block_text)
                if t_m:
                    lc.transport_input = t_m.group(1).strip().split()
                l_m = self._RE_LOGIN.search(block_text)
                if l_m:
                    lc.login_method = l_m.group(1).strip() or 'local'
                p_m = self._RE_LINE_PWD.search(block_text)
                if p_m:
                    lc.password = p_m.group(1)
                e_m = self._RE_EXEC_TIMEOUT.search(block_text)
                if e_m:
                    lc.exec_timeout = e_m.group(1).strip()
                configs.append(lc)
            else:
                i += 1
        return configs
