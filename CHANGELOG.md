# Changelog

All notable changes to White Hat Agent are documented here. The project follows semantic versioning while public
Python, CLI, MCP, and JSON Schema contracts remain pre-1.0.

## [0.11.0] - 2026-07-29

### Added

- the provider-neutral `network.capture-inspect` capability, typed `packet-capture` campaign target, reviewed
  `tshark.packet-capture-map` operation, and a single-step protocol-mapping playbook;
- bounded ordered packet metadata, protocol counts, TCP/UDP stream endpoints, TCP analysis signals, and selected
  ARP, ICMP, DNS, HTTP, TLS, QUIC, and WebSocket fields without raw payload bytes; and
- a production TShark 4.2.2 fleet run over the inert 755-byte PCAP, decoding all seven DNS and HTTP fixture packets
  into two streams with no warning or truncation.

### Security

- callers cannot select interfaces, live capture, capture or display filters, decode-as rules, profiles, keys,
  plugins, commands, flags, paths, or environment;
- the fixed offline invocation disables name resolution and network access, limits packets and output, and exposes
  only a reviewed field set; and
- strict normalization rejects unselected fields, malformed values, duplicate or unordered frame numbers, schema
  drift, and resource overruns while conformance binds the exact decoder, contract, fixture, and sandbox identities.

## [0.10.0] - 2026-07-29

### Added

- the provider-neutral `artifact.signature-match` capability, a reviewed `yara-x.file-scan` operation, and a lean
  signature-evaluation playbook for one immutable artifact and one standalone rule;
- normalized YARA-X evidence retaining rule identity, metadata, tags, exact string offsets, bounded matched bytes,
  rule/artifact digests, match ceilings, and explicit truncation state; and
- a production YARA-X 1.19.0 fleet run against the inert native-code fixture, preserving one rule and one string match
  with no warning or truncation.

### Security

- callers cannot supply paths, commands, options, namespaces, module-data files, external variables, or external
  includes;
- the fixed offline one-file invocation caps occurrences and matched bytes, while strict NDJSON normalization rejects
  extra targets, records, fields, duplicate identities, malformed offsets, and inconsistent XOR output; and
- conformance binds the exact executable, rule, fixture, driver, operation, and sandbox identities, and measured YARA-X
  address-space and process/thread floors fail closed before execution.

### Fixed

- fleet heartbeats can extend but never shorten an active lease; and
- conformance and execution timestamps use monotonic elapsed time, preserving start/finish ordering across wall-clock
  corrections.

## [0.9.0] - 2026-07-29

### Added

- a reviewed `ghidra.native-code-map` operation exposing bounded decompiler text, exact callsites, defined strings,
  and string xrefs with function anchors from one immutable native artifact;
- the provider-neutral `binary.static-inspect` capability and `surface/native-code-map` result contract; and
- a deterministic 1,496-byte ELF conformance fixture proving decompilation, an internal call edge, a defined marker
  string, and its source-function xref on Ghidra 12.1.2, plus a production broker run that captured 28 complete
  records with no warnings or truncation.

### Security

- callers cannot supply Ghidra scripts, project names, symbols, addresses, options, arguments, paths, environment, or
  output locations;
- the packaged script divides record and character ceilings across functions, calls, strings, and xrefs, and exposes
  decompiler failures plus every truncation state; and
- conformance binds the exact Ghidra, Java, script, operation, sandbox, and fixture identities before the new
  capability becomes available to an agent.

## [0.8.0] - 2026-07-29

### Added

- a reviewed `jadx.android-static-map` operation for DEX/APK-family evidence, exposing structured decompiled classes,
  method signatures and code lines, a resolved call graph, decoded manifest text, and a bounded resource inventory;
- a deterministic 904-byte DEX 035 conformance fixture with source provenance and call-edge checks; and
- exact JADX launcher/JAR and Java runtime identity binding, fixed offline execution, CLI/MCP/schema exposure, and a
  production campaign run on JADX 1.5.6 with content-addressed static-map evidence.

### Security

- callers cannot supply JADX commands, flags, paths, environment, plugins, mappings, or output locations;
- normalization rejects links, special files, path escapes, duplicate or unsafe class mappings, unindexed source
  output, schema drift, and aggregate file, byte, and record overruns; and
- the output budget is reserved below the evidence ceiling, deterministic truncation is explicit, and tool or Java
  payload drift invalidates cached conformance before another fleet execution.

## [0.7.0] - 2026-07-29

### Added

- bounded NVD CVE API 2.0 last-modified ingestion with immutable page snapshots, a closed-window selection manifest,
  exact official attribution, fixed-endpoint pagination, and production workflow integration;
- additive CVSS, SSVC, CWE, and reference enrichment correlated with canonical CVE List V5 records; and
- source-native preservation of NVD CPE/configuration and affected data for a future Boolean applicability evaluator.

### Security

- NVD synchronization fails closed on record, page, pagination, duplicate, malformed-response, and 120-day window
  limits, and only advances its cursor after a complete checkpoint;
- the public client observes NVD's recommended six-second inter-page delay and the transport rejects arbitrary NVD
  query shapes; and
- NVD data cannot replace canonical CVE title, description, state, or affected-package semantics during merge.

## [0.6.0] - 2026-07-29

### Added

- reviewed typed operations for Ghidra headless binary summaries, capa behavior identification, and LLVM object
  inspection, available through Python, CLI, MCP, and generated JSON Schemas;
- fixed inert ELF conformance suites whose reports bind the exact manifest, operation, tool identity, provider driver,
  fixture, and offline sandbox profile; and
- lease- and task-bound execution that resolves only immutable local evidence IDs and persists normalized output,
  stdout, stderr, and an execution manifest as content-addressed evidence; and
- compact MCP execution receipts that keep bounded analyzer data behind evidence handles.

### Security

- tool availability and version health no longer grant executable capabilities; only a current passing conformance
  report does;
- the Linux/WSL supervisor clears the environment, drops capabilities, unshares network/PID/IPC/UTS namespaces,
  excludes host `/etc`, snapshots one immutable input, keeps captures outside the tool mount, mounts reviewed tool
  payloads read-only, and enforces wall, CPU, memory, monitored process, entry, record, and output ceilings; and
- callers cannot supply commands, arguments, environment variables, paths, scripts, plugins, mounts, or output
  directories, and lease tokens are neither returned nor persisted;
- passive status and resolution never launch PATH-discovered binaries; fixed version and dependency probes run only
  during explicit offline conformance, and tool plus dependency digests invalidate cached observations on drift;
- execution manifests reference normalized evidence by digest and ID instead of duplicating analyzer output, keeping
  each evidence artifact independently inside the configured import ceiling; and
- resolver output never routes an installed but unobservable tool to a conformance action that must refuse it.

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

[0.10.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/kappa9999/white-hat-agent/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/kappa9999/white-hat-agent/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/kappa9999/white-hat-agent/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kappa9999/white-hat-agent/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kappa9999/white-hat-agent/releases/tag/v0.1.0
