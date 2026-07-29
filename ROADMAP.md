# Roadmap

## Core platform — implemented

- strict multilingual knowledge intake and Playbook v1 schema;
- deterministic corpus index/search and semantic composition;
- provider-neutral capability catalog and compatibility checks;
- opportunity intake, lifecycle, and deterministic fleet-fit ranking;
- deterministic campaign blueprints, exact scope/intent decisions, playbook-contract snapshots, and campaign budgets;
- SQLite task deduplication, compatible-agent matching, hashed leases, and bounded retries;
- content-addressed evidence, evidence-bound findings, and reusable-learning queue;
- adaptive evidence-graph discovery kernel and causal verifier;
- namespaced MCP stdio/stateless HTTP, CLI, Python, and JSON Schema surfaces; and
- local fixtures, public governance, contribution templates, and CI.

## Adapter integrations

- concrete manifest, observed status, deterministic resolver, official release/Git provisioning, and bounded local
  knowledge search (initial built-in implementation complete);
- execution handshake and conformance test kit beyond tool/version availability;
- sandboxed local subprocess adapter runner with explicit filesystem/network resources;
- bounded HTTP observation adapter for owned labs and exact program scopes;
- repository/patch-diff adapter using local source artifacts;
- mobile and binary inspection adapters that preserve exact tool/database identities;
- browser and cloud adapters only after transport, credential, and tenant controls are defined; and
- evidence signing and adapter output truncation manifests.

## Campaign intelligence

- production advisory ingestion for CISA KEV, OSV, and FIRST EPSS with immutable source snapshots and transparent
  prioritization;
- CVE List V5 and NVD enrichment with alias-graph correlation, source-specific attribution, and periodic full
  reconciliation;
- importers for public bounty/open-source program feeds with exact policy and scope snapshots;
- corpus-aware campaign decomposition across target inventories;
- distributed coordinator with authenticated workers and tenant isolation;
- global rate/budget scheduling, cancellation, pause barriers, and recovery;
- duplicate/novelty clustering across campaigns without leaking confidential data; and
- disclosure bundle generation with configurable redaction and program templates.

The production intelligence lifecycle, goal function, operating gates, scorecard, and collaboration policy are
defined in [`docs/production-loop.md`](docs/production-loop.md).

## Corpus scale

- multilingual semantic retrieval and embeddings as an optional index;
- STIX 2.1 import/export views while preserving richer playbook procedure semantics;
- CWE, CAPEC, ATT&CK, OWASP, CVE, platform, and technology mapping validators;
- cross-version migration tools and compatibility policy;
- signed corpus releases, provenance attestations, and reproducible indexes;
- domain packs spanning web/API, cloud, identity, mobile, binary, hardware, network, supply chain, incident response,
  malware analysis, AI/ML systems, cryptography, and operational technology; and
- scalable review queues that separate translation, source rights, technical review, and execution validation.

## Evaluation and autonomy

- capability benchmark suites with hidden and public fixtures;
- counterfactual/ablation evaluation for architecture changes;
- transfer measurement across targets and domains;
- cost, false-positive, causal-proof, novelty, and disclosure-quality scorecards;
- multiple competing planner policies behind one deterministic evaluation contract; and
- long-running goal management with explicit operator controls, compaction summaries, and crash recovery.

## Stable release criteria

- package namespace and trusted publishing configured;
- protocol/schema compatibility policy documented;
- authenticated deployment reference available;
- at least three real adapter families pass conformance and bounded lab integration tests;
- security review and dependency/release supply-chain controls complete;
- contributor review process demonstrated on external playbook PRs; and
- wheel and source distribution reproducible from a protected tagged commit.
