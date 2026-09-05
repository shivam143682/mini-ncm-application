# Mini NCM Application (Cisco IOS Compliance Platform)

This is a small backend project I built to parse Cisco IOS configuration files, check them against a set of security best practices, and store the results in a database. Everything runs behind a FastAPI service, and the whole thing is containerized with Docker so it's easy to spin up anywhere.

## What it actually does

You feed it a raw Cisco IOS config (as text), and it:

1. Parses the config into structured data (interfaces, routing, ACLs, AAA, etc.)
2. Runs it through a compliance engine that checks it against 8 security rules
3. Saves both the parsed config and the compliance report to PostgreSQL
4. Gives you all of this back through a REST API

## How it's put together

Two containers, wired together with Docker Compose:

- **api** — the FastAPI app, listening on port 8000
- **postgres** — Postgres 16, keeping data in a named volume so it survives restarts

Inside the API container, the code is split roughly like this:

- `parser/` — the actual Cisco IOS parser
- `compliance/` — the rule engine (8 rules right now)
- `models.py` — SQLAlchemy ORM models
- `service.py` — the layer that ties parsing + compliance + DB together
- `router.py` — the API routes
- `main.py` — where the FastAPI app gets created

## Getting it running

You just need Docker Desktop installed.

```bash
docker compose up --build
```

First run will build the image and bring both containers up. Tables get created automatically the first time Postgres boots — there's no separate migration step to run.

Once it's up, the interactive docs are at:

```
http://localhost:8000/docs
```

### Trying it out

Here's a quick example of sending a config in on Linux/macOS:

```bash
curl -X POST http://localhost:8000/api/v1/parse \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "Core-Router-01",
    "config_text": "hostname Core-Router-01\nservice password-encryption\nip domain-name corp.local\nip ssh version 2\naaa new-model\naaa authentication login default local\nntp server 10.0.0.1 prefer\nntp server 10.0.0.2\nsnmp-server community MyStr0ngStr RO\nbanner motd ^Authorised access only^\ninterface Loopback0\n description Router-ID Loopback\n ip address 10.255.0.1 255.255.255.255\ninterface GigabitEthernet0/0\n description WAN Uplink\n ip address 192.168.1.1 255.255.255.0\ninterface GigabitEthernet0/1\n description LAN\n ip address 10.1.0.1 255.255.255.0\nip route 0.0.0.0 0.0.0.0 192.168.1.254\nline vty 0 4\n login local\n transport input ssh\n exec-timeout 5 0"
  }'
```

And the same thing from PowerShell, if you're on Windows:

```powershell
$body = @{
    device_name = "Core-Router-01"
    config_text = "hostname Core-Router-01`nservice password-encryption`nip domain-name corp.local`nip ssh version 2`naaa new-model`naaa authentication login default local`nntp server 10.0.0.1 prefer`nntp server 10.0.0.2`nsnmp-server community MyStr0ngStr RO`nbanner motd ^Authorised access only^`ninterface Loopback0`n description Router-ID Loopback`n ip address 10.255.0.1 255.255.255.255`ninterface GigabitEthernet0/0`n description WAN Uplink`n ip address 192.168.1.1 255.255.255.0`ninterface GigabitEthernet0/1`n description LAN`n ip address 10.1.0.1 255.255.255.0`nip route 0.0.0.0 0.0.0.0 192.168.1.254`nline vty 0 4`n login local`n transport input ssh`n exec-timeout 5 0"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/parse" `
    -ContentType "application/json" -Body $body
```

## Python SDK

There's a small client wrapper in `sdk/` if you'd rather not hit the API with raw HTTP calls:

```python
from sdk import CiscoComplianceClient

client = CiscoComplianceClient(base_url="http://localhost:8000")

print(client.health_check())

result = client.parse_config(
    config_text=open("examples/sample_config.ios").read(),
    device_name="Core-Router-01",
)
print(f"Score: {result['report']['score']}")
print(f"Compliant: {result['report']['is_compliant']}")

for cfg in client.list_configs():
    print(f"{cfg['device_name']} — {cfg['raw_lines']} lines")

for rpt in client.list_reports():
    print(f"Score: {rpt['score']}, Compliant: {rpt['is_compliant']}")
```

To run the included demo (with the API already up):

```bash
pip install requests
python examples/demo.py
```

## API endpoints

| Method   | Endpoint                             | What it does                          |
|----------|---------------------------------------|----------------------------------------|
| POST     | `/api/v1/parse`                       | Parses a config, runs compliance, saves both |
| GET      | `/api/v1/configs`                     | Lists all stored device configs        |
| GET      | `/api/v1/configs/{id}`                | Returns a config with its full parsed data |
| DELETE   | `/api/v1/configs/{id}`                | Deletes a config and its report        |
| GET      | `/api/v1/reports`                     | Lists all compliance reports           |
| GET      | `/api/v1/reports/{id}`                | Returns one specific report            |
| GET      | `/api/v1/reports/by-config/{id}`      | Returns the report tied to a config    |
| GET      | `/health`                             | Basic API + DB health check            |

List endpoints support pagination through `?skip=` and `?limit=`, e.g. `/api/v1/configs?skip=0&limit=50`.

## The 8 compliance rules

| Rule    | Checks for                                      | Severity |
|---------|--------------------------------------------------|----------|
| SEC-001 | `service password-encryption` is enabled          | High     |
| SEC-002 | No SNMP community left as `public`/`private`      | High     |
| SEC-003 | SSH is on, telnet isn't allowed on VTY lines       | High     |
| SEC-004 | At least one NTP server is configured             | Medium   |
| SEC-005 | A Loopback0 interface exists                      | Low      |
| SEC-006 | Every active interface has a description          | Low      |
| SEC-007 | A banner MOTD is set                              | Medium   |
| SEC-008 | AAA new-model is configured                       | High     |

Scoring is weighted — High = 3 points, Medium = 2, Low = 1. The score is just (points passed / total possible points) × 100, and a config counts as compliant once it hits 80 or above.

## What the parser can read

Right now the parser pulls out:

- Hostname and domain name
- Interfaces — IP, mask, description, shutdown state, duplex/speed
- Static routes, including next-hop and admin distance
- OSPF (process ID, router ID, networks, passive interfaces)
- BGP (ASN, router ID, neighbors, networks)
- ACLs — standard, extended, and named, with their entries
- SNMP community strings and access types
- NTP servers, including the `prefer` flag
- AAA settings (new-model, authentication, authorization)
- VTY/CON line settings (transport, login, exec-timeout)
- Banner MOTD, including delimiter handling
- Security basics like password encryption, enable secret, SSH version

## Project layout

```
cisco-ios-parser/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app entry point
│   ├── database.py          # Async SQLAlchemy engine + session
│   ├── models.py            # ORM: DeviceConfig, ComplianceReport
│   ├── schemas.py           # Pydantic v2 request/response models
│   ├── router.py            # All API routes (/api/v1/*)
│   ├── service.py           # Business logic orchestrator
│   ├── parser/
│   │   ├── __init__.py
│   │   └── ios_parser.py    # Cisco IOS parser (pure Python)
│   └── compliance/
│       ├── __init__.py
│       └── engine.py        # 8-rule compliance engine
├── sdk/
│   ├── __init__.py
│   └── client.py            # Python SDK client
├── examples/
│   ├── sample_config.ios    # Sample Cisco IOS config
│   └── demo.py              # End-to-end demo script
├── tests/
│   └── test_parser.py       # Unit tests for parser & engine
├── Dockerfile                # Multi-stage, non-root
├── docker-compose.yml        # api + postgres with healthchecks
├── requirements.txt
├── .env
├── .gitignore
└── README.md
```

## Running the tests

Unit tests don't need Docker at all:

```bash
pip install pytest
python -m pytest tests/ -v
```

For a fuller integration check, bring the stack up and run the demo script against it:

```bash
docker compose up --build -d
pip install requests
python examples/demo.py
```

## Commands I keep coming back to

```bash
# Start (build if needed)
docker compose up --build

# Start in background
docker compose up -d --build

# Tail logs
docker compose logs -f api
docker compose logs -f postgres

# Stop
docker compose down

# Stop and also wipe the DB volume
docker compose down -v

# Rebuild just the API image
docker compose build api

# Quick health check
curl http://localhost:8000/health
```

## Database

No migrations to run — tables are created automatically the first time the app starts up.

| Table                | What's in it |
|-----------------------|---------------|
| `device_configs`       | Raw config text, the parsed JSON, and some metadata |
| `compliance_reports`   | The compliance result and score, linked back to its device config |

Data itself lives in the `pgdata` Docker volume, so it sticks around between restarts unless you explicitly wipe it.
