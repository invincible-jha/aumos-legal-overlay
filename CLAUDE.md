# CLAUDE.md — AumOS Legal Overlay

## Project Overview

AumOS Enterprise is a composable enterprise AI platform with 9 products + 2 services
across 62 repositories. This repo (`aumos-legal-overlay`) is part of **Tier 4: Industry Overlays**:
Legal industry compliance and privilege management for synthetic data.

**Release Tier:** B: Open Core
**Product Mapping:** Product 7 — Industry Overlays
**Phase:** 3B (Months 16-20)

## Repo Purpose

`aumos-legal-overlay` provides attorney-client privilege preservation in synthetic data,
e-discovery data generation, court-admissible audit trails, automated privilege log management,
and legal hold compliance tracking. It enables legal departments and law firms to generate
litigation-ready synthetic datasets while preserving all privilege and chain-of-custody requirements.

## Architecture Position

```
aumos-platform-core → aumos-auth-gateway → aumos-legal-overlay
aumos-common       ──►                   → aumos-event-bus (publishes legal events)
aumos-proto        ──►                   → aumos-data-layer (stores lgl_ tables)
                                         → aumos-governance-engine (compliance hooks)
```

**Upstream dependencies (this repo IMPORTS from):**
- `aumos-common` — auth, database, events, errors, config, health, pagination
- `aumos-proto` — Protobuf message definitions for Kafka events

**Downstream dependents (other repos IMPORT from this):**
- `aumos-governance-engine` — consumes privilege check events for compliance reporting

## Tech Stack (DO NOT DEVIATE)

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.110+ | REST API framework |
| SQLAlchemy | 2.0+ (async) | Database ORM |
| asyncpg | 0.29+ | PostgreSQL async driver |
| Pydantic | 2.6+ | Data validation, settings, API schemas |
| confluent-kafka | 2.3+ | Kafka producer/consumer |
| structlog | 24.1+ | Structured JSON logging |
| OpenTelemetry | 1.23+ | Distributed tracing |
| pytest | 8.0+ | Testing framework |
| ruff | 0.3+ | Linting and formatting |
| mypy | 1.8+ | Type checking |

## Coding Standards

### ABSOLUTE RULES (violations will break integration with other repos)

1. **Import aumos-common, never reimplement.**
2. **Type hints on EVERY function.** No exceptions.
3. **Pydantic models for ALL API inputs/outputs.** Never return raw dicts.
4. **RLS tenant isolation via aumos-common.** Never write raw SQL that bypasses RLS.
5. **Structured logging via structlog.** Never use print() or logging.getLogger().
6. **Publish domain events to Kafka after state changes.**
7. **Async by default.** All I/O operations must be async.
8. **Google-style docstrings** on all public classes and functions.

## API Conventions

- All endpoints under `/api/v1/legal/` prefix
- Auth: Bearer JWT token (validated by aumos-common)
- Tenant: `X-Tenant-ID` header (set by auth middleware)

## Database Conventions

- Table prefix: `lgl_` (e.g., `lgl_privilege_checks`, `lgl_audit_trails`)
- ALL tenant-scoped tables extend `AumOSModel`
- `lgl_audit_trails` is append-only — NEVER implement update/delete paths
- Audit trail integrity is maintained by SHA-256 hash chaining

## Kafka Topics Used

- `Topics.LEGAL_PRIVILEGE_CHECKED` — privilege determination completed
- `Topics.LEGAL_EDISCOVERY_JOB_CREATED` — e-discovery job queued
- `Topics.LEGAL_PRIVILEGE_LOG_ENTRY_CREATED` — log entry created
- `Topics.LEGAL_HOLD_CREATED` — legal hold issued (triggers custodian notification)
- `Topics.LEGAL_HOLD_RELEASED` — legal hold released

## Repo-Specific Context

### Legal Domain Terminology

- **Attorney-Client Privilege**: Protects communications between attorney and client
- **Work Product Doctrine**: Protects materials prepared in anticipation of litigation
- **FRCP 26(b)(5)**: Federal Rule requiring privilege log for withheld documents
- **Legal Hold**: Preservation notice to custodians to retain relevant documents
- **Custodian**: Individual whose data is subject to a legal hold
- **E-Discovery**: Electronic discovery — production of electronically stored information

### Integrity and Immutability Requirements

- Audit trail entries (`lgl_audit_trails`) must NEVER be modified after creation
- Each entry's `integrity_hash` chains to `previous_hash` for tamper detection
- The `is_immutable` flag must always be `True` for audit entries
- When exporting audit trails, always compute and include an `export_hash`

### Privilege Analysis

- `confidence_threshold` (default 0.85) determines `is_privileged` flag
- The `DocumentProcessor` adapter provides pattern-based scoring as a baseline
- In production, this will be replaced by an ML model via aumos-llm-serving

### What Claude Code Should NOT Do

1. Do NOT implement any update or delete operations on `lgl_audit_trails`
2. Do NOT skip the hash-chaining logic — it is legally critical
3. Do NOT log privileged document content in audit entries
4. Do NOT return raw document content — only metadata and privilege status
5. Do NOT implement cross-tenant privilege checks — all operations are tenant-scoped
6. Do NOT hardcode confidence thresholds — they come from Settings
