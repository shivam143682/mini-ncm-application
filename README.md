# Mini NCM Application (Cisco IOS Compliance Platform)

A production-ready Python application that **parses Cisco IOS configurations**, **evaluates compliance** against security best-practices, and **stores results in PostgreSQL** — all served through a **FastAPI REST API** running in **Docker**.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Docker Compose                                                  │
│                                                                  │
│  ┌─────────────────────┐      ┌──────────────────────────────┐  │
│  │   FastAPI (api)     │      │   PostgreSQL 16 (postgres)   │  │
│  │   port 8000         │─────▶│   port 5432 (internal)       │  │
│  │                     │      │   volume: pgdata             │  │
│  │  app/               │      └──────────────────────────────┘  │
│  │  ├── parser/        │                                        │
│  │  │   └── ios_parser │  (Cisco IOS parser)                    │
│  │  ├── compliance/    │                                        │
│  │  │   └── engine     │  (8 security rules)                    │
│  │  ├── models         │  (SQLAlchemy ORM)                      │
│  │  ├── service        │  (orchestrator)                        │
│  │  ├── router         │  (7 API endpoints)                     │
│  │  └── main           │  (FastAPI app)                         │
│  └─────────────────────┘                                        │
└──────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites
- **Docker Desktop** installed and running

### 1. Start the stack

```bash
docker compose up --build
```

The first run builds the image and starts both services.
PostgreSQL tables are created automatically on first boot.

### 2. Open Swagger UI

```
http://localhost:8000/docs
```

### 3. Parse your first config (Bash / Linux / macOS)

```bash
curl -X POST http://localhost:8000/api/v1/parse \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "Core-Router-01",
    "config_text": "hostname Core-Router-01\nservice password-encryption\nip domain-name corp.local\nip ssh version 2\naaa new-model\naaa authentication login default local\nntp server 10.0.0.1 prefer\nntp server 10.0.0.2\nsnmp-server community MyStr0ngStr RO\nbanner motd ^Authorised access only^\ninterface Loopback0\n description Router-ID Loopback\n ip address 10.255.0.1 255.255.255.255\ninterface GigabitEthernet0/0\n description WAN Uplink\n ip address 192.168.1.1 255.255.255.0\ninterface GigabitEthernet0/1\n description LAN\n ip address 10.1.0.1 255.255.255.0\nip route 0.0.0.0 0.0.0.0 192.168.1.254\nline vty 0 4\n login local\n transport input ssh\n exec-timeout 5 0"
  }'
```

### 3b. Parse your first config (PowerShell / Windows)

```powershell
$body = @{
    device_name = "Core-Router-01"
    config_text = "hostname Core-Router-01`nservice password-encryption`nip domain-name corp.local`nip ssh version 2`naaa new-model`naaa authentication login default local`nntp server 10.0.0.1 prefer`nntp server 10.0.0.2`nsnmp-server community MyStr0ngStr RO`nbanner motd ^Authorised access only^`ninterface Loopback0`n description Router-ID Loopback`n ip address 10.255.0.1 255.255.255.255`ninterface GigabitEthernet0/0`n description WAN Uplink`n ip address 192.168.1.1 255.255.255.0`ninterface GigabitEthernet0/1`n description LAN`n ip address 10.1.0.1 255.255.255.0`nip route 0.0.0.0 0.0.0.0 192.168.1.254`nline vty 0 4`n login local`n transport input ssh`n exec-timeout 5 0"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/parse" `
    -ContentType "application/json" -Body $body
```

---

## Python SDK

A **Python client module** is included in the `sdk/` directory for programmatic interaction:

```python
from sdk import CiscoComplianceClient

client = CiscoComplianceClient(base_url="http://localhost:8000")

# Health check
print(client.health_check())

# Parse and evaluate a config
result = client.parse_config(
    config_text=open("examples/sample_config.ios").read(),
    device_name="Core-Router-01",
)
print(f"Score: {result['report']['score']}")
print(f"Compliant: {result['report']['is_compliant']}")

# List all configs
for cfg in client.list_configs():
    print(f"{cfg['device_name']} — {cfg['raw_lines']} lines")

# List compliance reports
for rpt in client.list_reports():
    print(f"Score: {rpt['score']}, Compliant: {rpt['is_compliant']}")
```

### Run the demo script

```bash
# Install SDK dependency
pip install requests

# Run the demo (API must be running)
python examples/demo.py
```

---

## API Reference

| Method   | Endpoint                             | Description                          |
|----------|--------------------------------------|--------------------------------------|
| `POST`   | `/api/v1/parse`                      | **Parse config + compliance + store**|
| `GET`    | `/api/v1/configs`                    | List all device configs              |
| `GET`    | `/api/v1/configs/{id}`               | Get config with full parsed data     |
| `DELETE` | `/api/v1/configs/{id}`               | Delete config and its report         |
| `GET`    | `/api/v1/reports`                    | List all compliance reports          |
| `GET`    | `/api/v1/reports/{id}`               | Get a specific compliance report     |
| `GET`    | `/api/v1/reports/by-config/{id}`     | Get report for a config              |
| `GET`    | `/health`                            | API + DB health check                |

### Pagination

```
GET /api/v1/configs?skip=0&limit=50
GET /api/v1/reports?skip=0&limit=50
```

---

## Compliance Rules

| Rule ID | Description                                    | Severity     |
|---------|------------------------------------------------|--------------|
| SEC-001 | `service password-encryption` must be enabled  | 🔴 HIGH      |
| SEC-002 | No SNMP community `public` or `private`        | 🔴 HIGH      |
| SEC-003 | SSH enabled, telnet not allowed on VTY          | 🔴 HIGH      |
| SEC-004 | At least one NTP server configured              | 🟡 MEDIUM    |
| SEC-005 | Loopback0 interface must exist                  | 🟢 LOW       |
| SEC-006 | All active interfaces must have description     | 🟢 LOW       |
| SEC-007 | Banner MOTD must be configured                  | 🟡 MEDIUM    |
| SEC-008 | AAA new-model must be configured                | 🔴 HIGH      |

### Scoring

- **Weighted**: HIGH = 3 pts, MEDIUM = 2 pts, LOW = 1 pt
- **Score** = (sum of passed weights / total weights) × 100
- **Compliant** = `true` when score ≥ 80

---

## Parser Capabilities

The `CiscoIOSParser` extracts:

| Feature | Details |
|---------|---------|
| Hostname & domain | `hostname`, `ip domain-name` |
| Interfaces | IP, mask, description, shutdown, duplex, speed |
| Static routes | Network, mask, next-hop, admin distance |
| OSPF | Process ID, router-ID, networks, passive interfaces |
| BGP | ASN, router-ID, neighbors, networks |
| ACLs | Standard, extended, named (with entries) |
| SNMP | Community strings and access types |
| NTP | Servers with prefer flag |
| AAA | new-model, authentication, authorization |
| Lines | VTY/CON transport, login, exec-timeout |
| Banner | MOTD with delimiter support |
| Security | Password encryption, enable secret, SSH version |

---

## Project Structure

```
cisco-ios-parser/
├── app/
│   ├── __init__.py
│   ├── main.py              ← FastAPI app entry point
│   ├── database.py          ← Async SQLAlchemy engine + session
│   ├── models.py            ← ORM: DeviceConfig, ComplianceReport
│   ├── schemas.py           ← Pydantic v2 request/response models
│   ├── router.py            ← All API routes (/api/v1/*)
│   ├── service.py           ← Business logic orchestrator
│   ├── parser/
│   │   ├── __init__.py
│   │   └── ios_parser.py    ← Cisco IOS parser (pure Python)
│   └── compliance/
│       ├── __init__.py
│       └── engine.py        ← 8-rule compliance engine
├── sdk/
│   ├── __init__.py
│   └── client.py            ← Python SDK client
├── examples/
│   ├── sample_config.ios    ← Sample Cisco IOS config
│   └── demo.py              ← End-to-end demo script
├── tests/
│   └── test_parser.py       ← Unit tests for parser & engine
├── Dockerfile               ← Multi-stage, non-root
├── docker-compose.yml       ← api + postgres with healthchecks
├── requirements.txt         ← Python dependencies
├── .env                     ← Environment variables
├── .gitignore
└── README.md
```

---

## Testing

### Unit Tests (no Docker needed)

```bash
pip install pytest
python -m pytest tests/ -v
```

### Integration Test (Docker)

```bash
docker compose up --build -d
pip install requests
python examples/demo.py
```

---

## Useful Commands

```bash
# Start (build if needed)
docker compose up --build

# Start in background
docker compose up -d --build

# View logs
docker compose logs -f api
docker compose logs -f postgres

# Stop
docker compose down

# Stop and wipe DB data
docker compose down -v

# Rebuild only the API image
docker compose build api

# Check health
curl http://localhost:8000/health
```

---

## Database

Tables are created automatically on startup — no migrations needed.

| Table | Description |
|-------|-------------|
| `device_configs` | Raw config text + parsed JSON + metadata |
| `compliance_reports` | Compliance result + score, linked to device config |

Data is persisted in the Docker named volume `pgdata`.
