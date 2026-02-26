# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffolding from aumos-repo-template
- PrivilegeService for attorney-client privilege preservation checks
- EDiscoveryService for synthetic e-discovery data generation jobs
- AuditTrailService with hash-chained court-admissible audit entries
- PrivilegeLogService for FRCP 26(b)(5) compliant privilege log management
- LegalHoldService for custodian tracking and preservation compliance
- REST API endpoints for all five services under /api/v1/legal/
- DocumentProcessor adapter for pattern-based privilege indicator detection
- Kafka event publishing for all domain state changes
- Full unit test suite with mocked dependencies
