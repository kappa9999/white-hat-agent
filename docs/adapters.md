# Tools and knowledge adapters

White Hat Agent keeps **what a task needs** separate from **which concrete provider supplies it**:

- `capabilities/catalog.yaml` is the stable provider-neutral vocabulary used by playbooks and campaigns.
- `adapters/catalog.yaml` contains reviewed concrete tools and machine-readable knowledge sources.
- `.whitehat/adapters/` contains ignored workspace-local installations and exact source revisions.

This is one selection layer beneath the existing planner, not a second planner or package manager. Tool names never
enter playbooks, and an installed binary does not by itself prove that a live execution adapter is authorized or fully
conformant.

## Agent loop

```bash
# Discover concrete providers.
wha adapter list reverse
wha adapter show ghidra

# Verify actual paths, versions, dependencies, and available capabilities.
wha adapter status ghidra
wha adapter status --kind tool

# Minimize new provisioning, then provider count, with deterministic tie-breaking.
wha adapter resolve --kind tool \
  --capability artifact.inspect \
  --capability code.search \
  --capability graph.reason

# Read-only supply-chain plan, then exact application.
wha adapter plan ghidra --out ghidra-plan.json
wha adapter provision --plan ghidra-plan.json

# Explicit one-command form for local agents/operators.
wha adapter install ghidra --yes
```

Search, status, resolution, campaign planning, fleet claiming, and `wha doctor` never install anything. Only
`adapter provision` and `adapter install --yes` mutate `.whitehat/adapters/`.

Executable status uses only a fixed `--version` or `-version` strategy; a file-backed probe executes
nothing. The registry also rejects any provider whose execution ceiling is lower than an advertised capability.

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

The vulnerability-intelligence layer already handles CVE List V5, CISA KEV, OSV, and EPSS with immutable snapshots;
those feeds are not duplicated here.

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
- no claim that a version probe proves an adapter's runtime behavior; conformance fixtures remain a separate gate; and
- no automatic target interaction. Campaign scope, execution class, budgets, and evidence contracts still apply.
