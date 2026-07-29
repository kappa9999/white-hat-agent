# Changelog

All notable changes to White Hat Agent are documented here. The project follows semantic versioning while public
Python, CLI, MCP, and JSON Schema contracts remain pre-1.0.

## [0.5.0] - 2026-07-29

### Added

- a concrete adapter registry, observed host status, exact capability-cover resolver, and CLI/MCP/JSON Schema surfaces
  beneath the existing provider-neutral planner;
- reviewed manifests for Ghidra, Frida, LLVM, YARA-X, TShark, capa, JADX, MITRE ATT&CK STIX, and capa rules; and
- explicit plan/apply provisioning for digest-bearing official GitHub releases and exact Git knowledge snapshots,
  plus bounded revision-preserving knowledge search and excerpts.

### Security

- search, status, resolution, campaign planning, fleet claims, and workspace health checks never provision implicitly;
- version probes cannot carry free-form command arguments, and adapter execution ceilings cannot underclassify their
  advertised capability contracts;
- apply revalidates host state, manifest, release or commit identity, upstream URLs, asset names, SHA-256, and byte
  ceilings before bounded workspace-local activation; and
- safe extraction rejects traversal, links, special files, duplicate paths, excess entries, and decompression bombs,
  while managed knowledge fails closed when its deterministic content-tree digest changes.

## [0.4.1] - 2026-07-29

### Fixed

- untyped CVE List V5 comparator expressions are now preserved as unresolved ranges instead of being mislabeled as
  exact affected versions; no version boundaries are inferred from provider shorthand.

## [0.4.0] - 2026-07-29

### Added

- a pure advisory-to-artifact applicability primitive across Python, CLI, MCP, and JSON Schema, with exact
  package/build/commit identity, source-snapshot binding, strict SemVer, bounded Git ancestry, and tri-state results.

### Security

- unsupported ranges, incomplete ancestry, rejected or withdrawn records, and unmatched package identities remain
  `indeterminate`; applicability never grants execution authority or creates opportunity, campaign, or fleet state.

## [0.3.2] - 2026-07-29

### Fixed

- release publication now captures the draft ID directly from the create response and uploads the exact asset
  allowlist through that release's ID-bound upload URL instead of a published-release-only tag lookup.

## [0.3.1] - 2026-07-29

### Fixed

- the least-privilege release gate now accepts GitHub's documented redaction of ruleset bypass actors while still
  validating the exact sole maintainer-role bypass whenever an admin-scoped response exposes it.

## [0.3.0] - 2026-07-29

### Added

- canonical CVE List V5 incremental ingestion with immutable delta and record snapshots, upstream-time checkpoints,
  bounded replay, and content-addressed selection manifests;
- distinct `PUBLISHED` and `REJECTED` CVE states, immutable raw CNA/ADP containers with compact provider indices,
  conservative affected-version translation, generic PURL, CWE, CVSS, and reference views, and explicit
  rejected-record query controls;
- a least-privilege release workflow with signed-tag and tag-ruleset gates, two isolated byte-identical builds,
  CycloneDX SBOMs, checksums, GitHub artifact attestations, and exact-candidate smoke tests.

### Changed

- the scheduled production intelligence loop now includes canonical CVE records and retains its cursor and HTTP
  validator after any partial run;
- ecosystem filters no longer create gaps in canonical CVE source state; and
- distribution smoke tests derive their expected version from project metadata instead of a duplicated release
  constant.

### Security

- CVE transport accepts only the official rolling delta and exact record paths and never follows record references;
- CVE rejection, provider withdrawal, and local source tombstoning remain separate states; and
- release publication is isolated behind protected environments and does not contain PyPI credentials or package
  upload permissions.

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

[0.5.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/kappa9999/white-hat-agent/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/kappa9999/white-hat-agent/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/kappa9999/white-hat-agent/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kappa9999/white-hat-agent/releases/tag/v0.1.0
