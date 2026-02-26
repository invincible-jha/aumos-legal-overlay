# aumos-legal-overlay

[![CI](https://github.com/aumos-enterprise/aumos-legal-overlay/actions/workflows/ci.yml/badge.svg)](https://github.com/aumos-enterprise/aumos-legal-overlay/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/aumos-enterprise/aumos-legal-overlay/branch/main/graph/badge.svg)](https://codecov.io/gh/aumos-enterprise/aumos-legal-overlay)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> Attorney-client privilege preservation, e-discovery data generation, court-admissible audit trails, and legal hold compliance for AumOS synthetic data.

## Overview

`aumos-legal-overlay` provides legal industry compliance capabilities for the AumOS synthetic data
platform. It enables law firms, legal departments, and litigation support teams to generate synthetic
datasets that preserve attorney-client privilege, support e-discovery workflows, and maintain
court-admissible chain-of-custody documentation.

The service manages five core capabilities: privilege preservation checks with configurable confidence
thresholds, e-discovery synthetic document generation jobs, hash-chained audit trails for tamper-evident
court submission, automated privilege log generation compliant with Federal Rule of Civil Procedure
26(b)(5), and legal hold lifecycle management including custodian notification and acknowledgement tracking.

**Product:** Industry Overlays (Product 7)
**Tier:** Tier 4: Industry Verticals
**Phase:** 3B (Months 16-20)

## Architecture

```
aumos-common ──► aumos-legal-overlay ──► aumos-governance-engine
aumos-proto  ──►                     ──► Kafka: legal.privilege.checked
                                     ──► Kafka: legal.ediscovery.job.created
                                     ──► Kafka: legal.hold.created
```

This service follows AumOS hexagonal architecture:

- `api/` — FastAPI routes (thin, delegates to services)
- `core/` — Business logic with no framework dependencies
- `adapters/` — External integrations (PostgreSQL, Kafka, document processor)

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Access to AumOS internal PyPI for `aumos-common` and `aumos-proto`

### Local Development

```bash
# Clone the repo
git clone https://github.com/aumos-enterprise/aumos-legal-overlay.git
cd aumos-legal-overlay

# Set up environment
cp .env.example .env
# Edit .env with your local values

# Install dependencies
make install

# Start infrastructure (PostgreSQL, Redis)
make docker-run

# Run the service
uvicorn aumos_legal_overlay.main:app --reload
```

The service will be available at `http://localhost:8000`.

Health check: `http://localhost:8000/live`
API docs: `http://localhost:8000/docs`

## API Reference

### Authentication

All endpoints require a Bearer JWT token:

```
Authorization: Bearer <token>
X-Tenant-ID: <tenant-uuid>
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/live` | Liveness probe |
| GET | `/ready` | Readiness probe |
| POST | `/api/v1/legal/privilege/check` | Check privilege preservation |
| GET | `/api/v1/legal/privilege/status/{id}` | Get privilege status |
| POST | `/api/v1/legal/ediscovery/generate` | Generate e-discovery data |
| GET | `/api/v1/legal/ediscovery/jobs/{id}` | Get job status |
| POST | `/api/v1/legal/audit/export` | Export audit trail |
| GET | `/api/v1/legal/privilege-log` | List privilege log entries |
| POST | `/api/v1/legal/hold` | Create legal hold |
| GET | `/api/v1/legal/hold/{id}` | Get hold status |

Full OpenAPI spec available at `/docs` when running locally.

## Configuration

All configuration is via environment variables. See `.env.example` for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `AUMOS_SERVICE_NAME` | `aumos-legal-overlay` | Service identifier |
| `AUMOS_ENVIRONMENT` | `development` | Runtime environment |
| `AUMOS_DATABASE__URL` | — | PostgreSQL connection string |
| `AUMOS_KAFKA__BROKERS` | `localhost:9092` | Kafka broker list |
| `AUMOS_LEGAL_PRIVILEGE_CONFIDENCE_THRESHOLD` | `0.85` | Minimum score for privilege flag |
| `AUMOS_LEGAL_AUDIT_TRAIL_HASH_ALGORITHM` | `sha256` | Hash algorithm for audit integrity |
| `AUMOS_LEGAL_LEGAL_HOLD_NOTIFICATION_INTERVAL_DAYS` | `30` | Days between hold reminders |

## Development

### Running Tests

```bash
# Full test suite with coverage
make test

# Fast run (stop on first failure)
make test-quick
```

### Linting and Formatting

```bash
# Check for issues
make lint

# Auto-fix formatting
make format

# Type checking
make typecheck
```

## Database Tables

| Table | Prefix | Description |
|-------|--------|-------------|
| `lgl_privilege_checks` | `lgl_` | Privilege preservation check results |
| `lgl_ediscovery_jobs` | `lgl_` | E-discovery data generation jobs |
| `lgl_audit_trails` | `lgl_` | Court-admissible audit entries (immutable) |
| `lgl_privilege_logs` | `lgl_` | FRCP 26(b)(5) privilege log entries |
| `lgl_legal_holds` | `lgl_` | Legal hold tracking |

**Important:** `lgl_audit_trails` is append-only. Entries are cryptographically chained
via SHA-256 hashes and must never be modified or deleted.

## Related Repos

| Repo | Relationship | Description |
|------|-------------|-------------|
| [aumos-common](https://github.com/aumos-enterprise/aumos-common) | Dependency | Shared utilities, auth, database, events |
| [aumos-proto](https://github.com/aumos-enterprise/aumos-proto) | Dependency | Protobuf event schemas |
| [aumos-governance-engine](https://github.com/aumos-enterprise/aumos-governance-engine) | Downstream | Consumes privilege events for compliance |

## License

Copyright 2026 AumOS Enterprise. Licensed under the [Apache License 2.0](LICENSE).

This software must not incorporate AGPL or GPL licensed components.
See [CONTRIBUTING.md](CONTRIBUTING.md) for license compliance requirements.
