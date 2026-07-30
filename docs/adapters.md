# Tools and knowledge adapters

White Hat Agent keeps **what a task needs** separate from **which concrete provider supplies it**:

- `capabilities/catalog.yaml` is the stable provider-neutral vocabulary used by playbooks and campaigns.
- `adapters/catalog.yaml` contains reviewed concrete tools and machine-readable knowledge sources.
- `.whitehat/adapters/` contains ignored workspace-local installations and exact source revisions.

This is one selection layer beneath the existing planner, not a general host package manager. Tool names never enter
playbooks. Installed and version-healthy are observations; only an exact passing operation conformance report adds
executable capabilities to agent status.

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

# Explicit autonomous closure: select providers, update them, provision managed
# runtime dependencies only when needed, and run the relevant fixed fixtures.
wha adapter ensure --yes \
  --capability binary.static-inspect \
  --capability experiment.design

# Read-only supply-chain plan, then exact application.
wha adapter plan ghidra --out ghidra-plan.json
wha adapter provision --plan ghidra-plan.json

# Explicit one-command form for local agents/operators.
wha adapter install ghidra --yes

# Exercise only the bundled inert fixture inside the offline sandbox.
wha adapter conform ghidra

# The status now exposes both reviewed Ghidra operations and their capabilities.
wha adapter status ghidra
```

Search, status, resolution, campaign planning, fleet claiming, and `wha doctor` never install or execute anything.
`adapter provision`, `adapter install --yes`, and `adapter ensure --yes` write managed installations. `adapter ensure`
is an explicit composition of the same resolver, provision-plan validation, and fixed conformance boundaries; it is
never called by planning or fleet work. `adapter conform` remains the provider-specific local execution boundary and
writes its identity-bound conformance report.

When a selected Ghidra or JADX operation has no usable Java runtime, `ensure` provisions the reviewed `temurin-jdk`
dependency from Eclipse Adoptium's platform-specific API. If host Java exists, the first fixed conformance probe uses
it; a failed Java-version check causes exactly one managed-runtime install and retry. A valid host runtime therefore
does not trigger a redundant JDK download.

`adapter conform` is the separate local execution gate. It never reads campaign evidence: inside the same offline
supervisor it runs fixed version/dependency probes, then the reviewed driver against its bundled inert fixture (the
784-byte summary ELF, 1,496-byte native-map ELF, 15,584-byte Frida runtime ELF, 211-byte standalone YARA-X rule,
904-byte DEX, or 755-byte PCAP), and writes one
identity-bound report under `.whitehat/adapters/.conformance/`. A tool or manifest change invalidates the report.
`adapter resolve` reports a
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
| Eclipse Temurin JDK 21 | Managed Java runtime closure for reviewed JVM-backed tools | Platform-specific Adoptium package |
| Ghidra | Multi-ISA static analysis, decompilation, headless scripting, binary comparison | Official release asset |
| GoReSym | Go build, function, source, type, interface, and embedded-string recovery | Official release asset |
| unblob | Recursive archive, firmware-container, filesystem, and compressed-stream extraction | Exact official OCI image |
| Frida | Fixed load-time process, module, import, export, and dependency mapping | Exact standalone official release asset |
| LLVM | LLDB, object/symbol tools, sanitizers, coverage, libFuzzer | Detect existing; OS channels vary |
| YARA-X | Deterministic artifact and rule matching | Official release asset |
| TShark | Headless packet and protocol decoding | Detect existing; capture privileges remain external |
| capa | Machine-readable executable capability triage | Official release asset |
| JADX | Android DEX/APK/AAB decompilation and resources | Official release asset |
| MITRE ATT&CK | Enterprise, mobile, and ICS STIX behavior knowledge | Exact release assets |
| MITRE CWE | Canonical weakness definitions, relationships, detection, mitigations, and examples | Versioned official XML catalog |
| capa rules | Executable-capability rules with ATT&CK/MBC mappings | Exact Git commit |
| OWASP WSTG | Web/API test objectives, procedures, evidence, and remediation methodology | Exact Git commit |

The vulnerability-intelligence layer already handles CVE List V5, NVD 2.0, CISA KEV, OSV, and EPSS with immutable
snapshots; those feeds are not duplicated here.

## Typed offline execution

The first executable family is deliberately small:

| Operation | Agent-visible result | Fixed provider boundary |
|---|---|---|
| `llvm.object-inspect` | ELF header, sections, symbols, and needed libraries | `llvm-readobj` JSON only |
| `capa.file-analyze` | Bounded behavior-rule summaries and analysis identity | capa JSON with embedded reviewed rules |
| `ghidra.binary-summary` | Program, memory-block, function, and external-symbol summary | bundled `WhaBinarySummary.java` only |
| `ghidra.native-code-map` | Decompiled functions, exact callsites, defined strings, and anchored string xrefs | bundled `WhaNativeCodeMap.java` only |
| `goresym.symbol-map` | Go build/module identity, functions, source paths, types, interfaces, strings, dependencies, and settings | fixed full JSON extraction against one artifact |
| `unblob.extraction-map` | Verified files, directories, links, hashes, magic, chunks, handlers, and extraction errors | fixed depth-three extraction in the exact release/platform OCI image |
| `frida.executable-runtime-map` | Pre-main process, module, import, export, and dependency map | standalone `frida-inject` plus bundled `WhaRuntimeModuleMap.js` only |
| `yara-x.file-scan` | Rule identities, metadata, tags, string offsets, and bounded matched bytes | fixed YARA-X NDJSON mode against one artifact |
| `jadx.android-static-map` | Decompiled class JSON, method code, call graph, manifest text, and resource inventory | fixed JADX JSON and JSON call-graph modes |
| `tshark.packet-capture-map` | Ordered packets, protocol counts, stream endpoints, and selected application metadata | fixed TShark JSON fields against one offline capture |

The Ghidra native-code-map driver accepts one `artifact/file` evidence object and emits one
`surface/native-code-map`. Its only script is packaged with the release and content-digested with the Ghidra and Java
payloads. Record and character budgets are divided across functions, call edges, strings, and xrefs so one category
cannot consume the complete result. Every decompiler failure, per-function code truncation, section truncation, exact
callsite, and xref anchor remains explicit. The request has no script, symbol, address, option, path, environment, or
project field.

The GoReSym driver accepts one `artifact/file` and emits one `surface/go-symbol-map`. The request exposes no manual
address, compiler-version override, parser flag, path, command, or environment field. Its fixed offline invocation
recovers both standard and user functions, runtime tables, source paths, reconstructed types and interfaces, embedded
strings with virtual addresses, module dependencies, and build settings. A shared record and byte budget gives every
collection initial capacity before redistributing unused space, retains exact raw JSON as evidence, and marks both
collection and field truncation. Conformance analyzes the exact installed GoReSym payload itself, proving the parser
without shipping a redundant megabyte-scale fixture.

The unblob driver accepts one `artifact/file` and emits one `surface/extracted-file-map`. Provisioning resolves the
latest stable GitHub release to one source commit, GHCR index digest, platform-manifest digest, config digest, and
bounded layer set, then pulls only the exact platform manifest and stores a small identity descriptor. Execution uses
that digest with Docker pull disabled, no network, a read-only root filesystem, dropped capabilities, disabled
privilege escalation, read-only input, one private output mount, and CPU, memory, PID, wall, file, and byte ceilings.
The request exposes no image, tag, plugin, path, flag, process count, depth, extractor, environment, or network field.
Normalization independently hashes the complete transient extraction tree and rejects report/tree disagreement,
duplicate or escaped paths, special files, identity drift, schema drift, and invalid chunk ranges. The raw report and
normalized map are retained; bulk extracted contents remain transient.

The Frida driver accepts one `artifact/executable` evidence object and emits one
`surface/runtime-module-map`. Provisioning resolves the current platform-specific `frida-inject` asset from the
official Frida GitHub release, requires GitHub's declared size and SHA-256, decompresses the single-file `.xz` stream
under the install ceiling, and records the resulting content-tree identity. Execution temporarily adds only the user
execute bit to the broker's verified snapshot, mounts it read-only, and spawns that exact file in the offline PID
namespace. The bundled content-digested script observes the process before main, caps modules/imports/exports/
dependencies, emits one marked JSON record, and uses `--eternalize` so injector exit triggers namespace cleanup. No
request can select a device, PID, name, remote endpoint, script, hook, argument, environment, memory read, or CLI flag.
Normalization rejects duplicate markers, extra fields, malformed pointers, inconsistent counts, unknown collection
errors, and record/byte overruns; absolute load addresses remain run-specific evidence and must not be replayed.

The YARA-X driver accepts one `artifact/file` evidence object plus at most 64 KiB of complete standalone rule source
and emits one `evidence/signature-match`. The exact rule source is retained in the execution manifest and its digest is
bound into the normalized result. External includes are rejected; callers cannot select paths, namespaces, module-data
files, external variables, commands, or flags. The fixed one-file invocation emits NDJSON with rule metadata, tags,
and at most 32 occurrences per pattern with 64 matched bytes per occurrence. Strict normalization rejects extra targets,
records, fields, duplicate identities, malformed offsets, or inconsistent XOR output and reports every rule, string,
record, and engine ceiling. The measured YARA-X runtime floor is 2 GiB of address space and eight process/thread slots;
requests below either floor fail before execution.

The TShark driver accepts one `artifact/packet-capture` evidence object and emits one
`surface/network-protocol-map`. It fixes offline input, packet count, JSON mode, selected fields, temporary directory,
and disabled name resolution. Callers cannot select interfaces, capture filters, display filters, decode-as rules,
profiles, keys, plugins, commands, flags, paths, or environment. Normalization preserves ordered frame identities,
timestamps, lengths, protocol chains, endpoint and stream metadata, common DNS/HTTP/TLS/QUIC/WebSocket fields, TCP
analysis flags, packet ceilings, and conservative truncation. It rejects unselected fields, malformed values,
duplicate or unordered frame numbers, output schema drift, and record or byte overruns. It never emits raw payload
bytes or performs live capture.

The JADX driver accepts one `artifact/mobile-build` evidence object and emits one `surface/static-map`. It fixes the
configuration, mapping, deobfuscation, output, call-graph, thread, and logging modes; callers cannot add a plugin or
CLI option. Class documents retain JADX's structured declarations, signatures, offsets, and decompiled code lines.
All referenced class paths must remain canonical beneath the result root, and unexpected source files, links, special
files, path escapes, or aggregate limit overruns invalidate the output.

Execution requires one active fleet lease and one same-task local evidence ID. The request contains one required,
provider-specific operation discriminator and optional resource reductions; YARA-X also accepts only its bounded
standalone rule source. The operation selects its only reviewed provider, so there is no duplicate provider field. It
has no command, arguments, path, environment, plugin, mount, or output-directory field. The broker rechecks campaign
state, lease token, task capabilities/execution class,
evidence campaign/task/target/type/digest/length, conformance identity, and current tool payload before process start.
It renews the active lease for the bounded run, snapshots the verified input through a no-follow file descriptor, and
rechecks the lease before evidence registration.

On Linux/WSL, native-tool operations execute through the fixed root-owned `/usr/bin/bwrap` with a minimal launch environment,
cleared sandbox environment, no network namespace, dropped capabilities, isolated PID/IPC/UTS namespaces, empty
home/tmp/var, no host `/etc`, read-only system/tool/input mounts, one tool work directory, and broker-private capture
files outside that mount. Wall time, CPU, memory, monitored process count, open files, all work-directory entries,
aggregate work bytes, output records, and input bytes are bounded by the operation contract; a request may only reduce
those ceilings subject to any measured provider runtime floor. The effective output ceiling is also capped by the
evidence store.

Every run returns normalized structured data to Python/CLI and registers bounded stdout, stderr, normalized JSON, and
a final execution manifest in the content-addressed evidence store. MCP returns a compact receipt with evidence
handles instead of embedding analyzer output. The manifest is also compact: it retains task/scope/intent, input,
manifest, exact sanitized operation payload, tool, conformance, sandbox, capture, and truncation identities while
referencing normalized evidence by ID and digest. It never duplicates analyzer data, persists or returns the lease
token, completes the fleet task, or promotes a finding automatically.

The current Bubblewrap profile is an offline least-authority execution layer, not a sealed malware detonation VM. It
still read-mounts host `/usr`, `/bin`, and runtime libraries, and process-tree limits use polling plus POSIX per-process
limits rather than cgroup accounting. Use a disposable VM for actively hostile artifacts until the sealed runtime
closure and cgroup-v2 profile on the roadmap are complete.

## Revision-bound knowledge

Knowledge sources are installed only when needed. Results retain the exact release or commit:

```bash
wha adapter install mitre-attack --yes
wha adapter search mitre-attack T1059.001

wha adapter ensure --kind knowledge --capability weakness.lookup --yes
wha adapter search mitre-cwe CWE-79

wha adapter install capa-rules --yes
wha adapter search capa-rules "reverse shell"

wha adapter ensure --kind knowledge --capability experiment.design --yes
wha adapter search owasp-wstg "Test Objectives"
```

`search` is a bounded direct scan, not another index or semantic store. It returns file, line, snippet, and revision;
pass a returned file and line to `read` for a bounded excerpt from that same managed revision.

## Provisioning trust contract

GitHub release provisioning:

1. queries only `api.github.com/repos/<reviewed-owner>/<reviewed-repo>/releases/latest`;
2. requires each platform pattern to select exactly one asset;
3. requires GitHub's `sha256:` asset digest and declared size;
4. downloads with byte limits and verifies size plus SHA-256;
5. rejects archive traversal, links, devices, duplicate paths, excess entries, malformed raw `.xz` streams, and decompression bombs; and
6. atomically activates a complete workspace-local installation.

Adoptium runtime provisioning queries only the fixed Eclipse Adoptium API v3 `latest/<feature>/hotspot` surface with
an exact platform, architecture, JDK image type, normal heap, and Eclipse vendor tuple. It requires one package,
retains the release identity, declared size, and SHA-256 checksum, accepts only the official
`adoptium/temurin21-binaries` GitHub release URL, then uses the same bounded extraction and atomic activation path.

Git knowledge provisioning resolves a reviewed branch/ref through GitHub to one commit, fetches that commit with
global/system Git configuration and hooks disabled, verifies `HEAD`, rejects symlinks and oversized trees, removes Git
metadata, then activates the exact snapshot. No catalog entry can contain a shell command.

MITRE CWE provisioning queries only the fixed public version endpoint and canonical XML ZIP. Planning streams the
small catalog once to bind its exact size and SHA-256; application downloads it again and fails on drift. Extraction
then requires one version-named XML file whose version, content date, and weakness/category/view counts exactly match
the version response before atomic activation. The XML itself remains the bounded searchable source—no duplicate
index or transformed corpus is generated.

OCI image provisioning is currently restricted to reviewed public GHCR repositories. It resolves a stable GitHub
release tag and commit, verifies registry response bodies and digest headers, selects one declared Linux architecture,
checks config source/version/revision labels and the fixed entrypoint, enforces compressed-layer limits, pulls by the
platform-manifest digest, and verifies the local platform, repo digest, entrypoint, and release labels. Mutable tags
are never used during execution.

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
