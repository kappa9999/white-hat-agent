# Changelog

All notable changes to White Hat Agent are documented here. The project follows semantic versioning while public
Python, CLI, MCP, and JSON Schema contracts remain pre-1.0.

## [0.2.0] - 2026-07-29

### Added

- production ingestion for CISA KEV and incremental OSV records, with optional FIRST EPSS enrichment;
- immutable content-addressed source snapshots, durable sync state, alias correlation, and transparent KEV-first
  prioritization;
- local CLI, MCP, Python, and JSON Schema intelligence surfaces;
- a scheduled GitHub Actions monitor that publishes retained machine-readable reports and ranked briefs;
- a production goal function, operating gates, scorecard, source contract, and professional collaboration policy;
  and
- a structured intelligence and data-quality contribution form.

### Changed

- campaign pause and cancellation are execution barriers: active leases are revoked, cancelled work is terminalized,
  and stale heartbeat or result tokens fail closed;
- the public project status now distinguishes fixed official-source intelligence from target-interacting adapters;
  and
- repository issue routing now includes adapter, knowledge, triage, and intelligence queues.

### Security

- intelligence HTTP access is GET-only, bounded, uses an explicit user agent, and is restricted to documented official
  provider endpoints;
- advisory collection never treats a public vulnerability record as authorization to interact with an affected
  target; and
- paused or cancelled campaigns cannot continue through previously issued leases.

## [0.1.0] - 2026-07-29

Initial public alpha with typed knowledge intake, corpus composition, campaign scope, fleet leasing, evidence-bound
findings, adaptive discovery, MCP, CLI, JSON Schema, installers, governance, and CI.

[0.2.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kappa9999/white-hat-agent/releases/tag/v0.1.0
