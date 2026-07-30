# Tools and knowledge adapters

White Hat Agent keeps **what a task needs** separate from **which concrete provider supplies it**:

- `capabilities/catalog.yaml` is the stable provider-neutral vocabulary used by playbooks and campaigns.
- `adapters/catalog.yaml` contains reviewed concrete tools and machine-readable knowledge sources.
- `.whitehat/adapters/` contains ignored workspace-local installations and exact source revisions.

This is one selection layer beneath the existing planner, not a second planner or package manager. Tool names never
enter playbooks. Installed and version-healthy are observations; only an exact passing operation conformance report
adds executable capabilities to agent status.

## Agent loop

```bash
# Discover concrete providers.
wha adapter list reverse
wha adapter show ghidra

# Observe paths, file metadata, cached conformance, and available capabilities.
wha adapter status ghidra
wha adapter status --kind tool

# Minimize new provisioning, then provider count, with deterministic tie-breaking.
wha adapter resolve --kind tool \
  --capability artifact.inspect \
  --capability binary.behavior-identify

# Read-only supply-chain plan, then exact application.
wha adapter plan ghidra --out ghidra-plan.json
wha adapter provision --plan ghidra-plan.json

# Explicit one-command form for local agents/operators.
wha adapter install ghidra --yes

# Exercise only the bundled inert fixture inside the offline sandbox.
wha adapter conform ghidra

# The status now exposes ghidra.binary-summary and artifact.inspect.
wha adapter status ghidra
```

Search, status, resolution, campaign planning, fleet claiming, and `wha doctor` never install or execute anything.
`adapter provision` and `adapter install --yes` write managed installations. `adapter conform` is the explicit local
execution boundary and writes its identity-bound conformance report.

`adapter conform` is the separate local execution gate. It never reads campaign evidence: inside the same offline
supervisor it runs fixed version/dependency probes, then the reviewed driver against a bundled 784-byte inert ELF
fixture, and writes one identity-bound report under
`.whitehat/adapters/.conformance/`. A tool or manifest change invalidates the report. `adapter resolve` reports a
present, identity-observable but unproven provider under `conformance_required`, not `ready_adapters`. An installed
tool whose identity cannot be read is repaired through its reviewed provisioner when one exists; it is otherwise an
explicit uncovered capability, never an impossible conformance action.

Status and resolution perform no command probe. They resolve and hash paths, read file-backed version metadata, and
consume only current cached conformance observations. A PATH-discovered command is launched only by explicit
`adapter conform`, with its fixed `--version` or `-version` argument inside Bubblewrap. The registry also rejects any
provider whose execution ceiling is lower than an advertised capability. Each runtime requirement executable is
content-digested into the report, so dependency drift invalidates cached health before capability resolution.

## Built-in providers

| Provider | Unique role | Provisioning |
|---|---|---|
| Ghidra | Multi-ISA static analysis, decompilation, headless scripting, binary comparison | Official release asset |
| Frida | Cross-platform dynamic instrumentation | Detect existing; no unverified PyPI install path |
| LLVM | LLDB, object/symbol tools, sanitizers, coverage, libFuzzer | Detect existing; OS channels vary |
| YARA-X | Deterministic artifact and rule matching | Official release asset |
| TShark | Headless packet and protocol decoding | Detect existing; capture privileges remain external |
| capa | Machine-readable executable capability triage | Official release asset |
| JADX | Android DEX/APK/AAB decompilation and resources | Official release asset |
| MITRE ATT&CK | Enterprise, mobile, and ICS STIX behavior knowledge | Exact release assets |
| capa rules | Executable-capability rules with ATT&CK/MBC mappings | Exact Git commit |

The vulnerability-intelligence layer already handles CVE List V5, NVD 2.0, CISA KEV, OSV, and EPSS with immutable
snapshots; those feeds are not duplicated here.

## Typed offline execution

The first executable family is deliberately small:

| Operation | Agent-visible result | Fixed provider boundary |
|---|---|---|
| `llvm.object-inspect` | ELF header, sections, symbols, and needed libraries | `llvm-readobj` JSON only |
| `capa.file-analyze` | Bounded behavior-rule summaries and analysis identity | capa JSON with embedded reviewed rules |
| `ghidra.binary-summary` | Program, memory-block, function, and external-symbol summary | bundled `WhaBinarySummary.java` only |

Execution requires one active fleet lease and one same-task local evidence ID. The request contains one required,
provider-specific operation discriminator and optional resource reductions; the operation selects its only reviewed
provider, so there is no duplicate provider field. It has no command, arguments, path, environment, script, plugin,
mount, or output-directory field. The broker rechecks campaign state, lease token, task capabilities/execution class,
evidence campaign/task/target/type/digest/length, conformance identity, and current tool payload before process start.
It renews the active lease for the bounded run, snapshots the verified input through a no-follow file descriptor, and
rechecks the lease before evidence registration.

On Linux/WSL, the broker executes through the fixed root-owned `/usr/bin/bwrap` with a minimal launch environment,
cleared sandbox environment, no network namespace, dropped capabilities, isolated PID/IPC/UTS namespaces, empty
home/tmp/var, no host `/etc`, read-only system/tool/input mounts, one tool work directory, and broker-private capture
files outside that mount. Wall time, CPU, memory, monitored process count, open files, all work-directory entries,
aggregate work bytes, output records, and input bytes are bounded by the operation contract; a request may only reduce
those ceilings. The effective output ceiling is also capped by the evidence store.

Every run returns normalized structured data to Python/CLI and registers bounded stdout, stderr, normalized JSON, and
a final execution manifest in the content-addressed evidence store. MCP returns a compact receipt with evidence
handles instead of embedding analyzer output. The manifest is also compact: it retains task/scope/intent, input,
manifest, operation, tool, conformance, sandbox, capture, and truncation identities while referencing normalized
evidence by ID and digest. It never duplicates analyzer data, persists or returns the lease token, completes the fleet
task, or promotes a finding automatically.

The current Bubblewrap profile is an offline least-authority execution layer, not a sealed malware detonation VM. It
still read-mounts host `/usr`, `/bin`, and runtime libraries, and process-tree limits use polling plus POSIX per-process
limits rather than cgroup accounting. Use a disposable VM for actively hostile artifacts until the sealed runtime
closure and cgroup-v2 profile on the roadmap are complete.

## Revision-bound knowledge

Knowledge sources are installed only when needed. Results retain the exact release or commit:

```bash
wha adapter install mitre-attack --yes
wha adapter search mitre-attack T1059.001

wha adapter install capa-rules --yes
wha adapter search capa-rules "reverse shell"
```

`search` is a bounded direct scan, not another index or semantic store. It returns file, line, snippet, and revision;
pass a returned file and line to `read` for a bounded excerpt from that same managed revision.

## Provisioning trust contract

GitHub release provisioning:

1. queries only `api.github.com/repos/<reviewed-owner>/<reviewed-repo>/releases/latest`;
2. requires each platform pattern to select exactly one asset;
3. requires GitHub's `sha256:` asset digest and declared size;
4. downloads with byte limits and verifies size plus SHA-256;
5. rejects archive traversal, links, devices, duplicate paths, excess entries, and decompression bombs; and
6. atomically activates a complete workspace-local installation.

Git knowledge provisioning resolves a reviewed branch/ref through GitHub to one commit, fetches that commit with
global/system Git configuration and hooks disabled, verifies `HEAD`, rejects symlinks and oversized trees, removes Git
metadata, then activates the exact snapshot. No catalog entry can contain a shell command.

Managed state records the manifest digest, upstream URLs, tag/commit, asset digests, deterministic content-tree digest,
version, entrypoints, and install time. Knowledge status, search, and read fail closed if current bytes no longer match
that installed digest. Re-running `adapter install` is idempotent when the observed version or revision is current.

## Deliberate exclusions

- no community Ghidra/Frida/debugger MCP servers by default; native headless, Python, JSON, QMP, and CLI APIs are more
  mature and expose less ambient authority;
- no automatic plugins, extensions, exploit bodies, malware samples, or mutable rule aggregations;
- no hidden `sudo`, package-manager, PowerShell, or shell recipes;
- no claim that a version probe proves runtime behavior; exact conformance remains a separate, explicit gate; and
- no automatic target interaction. Campaign scope, execution class, budgets, and evidence contracts still apply.
