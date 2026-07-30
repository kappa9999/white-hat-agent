# MCP integration

## Transports

The same server supports:

- local `stdio`, the default; and
- stateless Streamable HTTP at `/mcp`.

```bash
wha serve --workspace /absolute/path/to/workspace --transport stdio
wha serve --workspace /absolute/path/to/workspace --transport http --host 127.0.0.1 --port 8000
```

Do not expose the HTTP endpoint publicly without an authenticated reverse proxy, transport security, network policy,
and a reviewed tool policy. The built-in server binds localhost by default and contains no authentication provider.

## Generic client configuration

When White Hat Agent was installed with the one-line bootstrap, use the globally available `wha` executable:

```json
{
  "mcpServers": {
    "white-hat-agent": {
      "command": "wha",
      "args": [
        "serve",
        "--workspace",
        "/absolute/path/to/white-hat-workspace",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

The exact configuration envelope differs by client; the command and arguments are ordinary stdio MCP. If a desktop
client does not inherit the shell `PATH`, run `uv tool dir --bin` and use the absolute `wha` or `wha.exe` path as
`command`.

For a source checkout, the equivalent command is:

```bash
uv run --project /absolute/path/to/white-hat-agent \
  wha serve --workspace /absolute/path/to/white-hat-workspace --transport stdio
```

## Surface design

Mounted names become `knowledge_search`, `adapter_resolve`, `adapter_ensure`, `intelligence_sync`,
`intelligence_epss_history`, `campaign_enqueue`, and so on.
Tools use strict structured input/output. Resources expose workspace health, the corpus manifest, playbooks, and the
capability and concrete-adapter catalogs. Prompts help a host model compile submissions, normalize opportunities,
and plan campaigns without requiring one provider's API.

`campaign_plan` is the bridge from knowledge to fleet work: given exact scope, targets, initial and desired semantic
artifacts, an execution ceiling, and available adapter capabilities, it composes corpus playbooks and emits ordered
stages. Each stage carries its own `ProbeIntent` and freshly evaluated `ScopeDecision`. Planning is read-only; the
operator or host agent still persists the manifest, explicitly transitions its lifecycle, and enqueues chosen stages.

Four built-in tools are open-world. `intelligence_sync` performs bounded GET requests to fixed official CVE List V5,
NVD 2.0, CISA, OSV, and optional FIRST EPSS endpoints, then mutates only the local workspace state and snapshot store.
`adapter_plan_provision` performs read-only resolution against the reviewed provider's official GitHub release,
commit API, Adoptium API, or fixed MITRE CWE catalog endpoints. `adapter_provision` applies an exact plan by downloading only its resolved official artifacts or commit
into `.whitehat/adapters/`; it is both networked and mutating. `adapter_ensure` composes deterministic capability
resolution, those same exact provision plans, managed runtime closure, and relevant fixed-fixture conformance. None
contacts advisory targets. Clients should require approval for synchronization and provisioning when those side
effects are not already part of operator policy.

`adapter_conform` is local, closed-world execution: it runs fixed version/dependency checks and one synthetic fixture
through one reviewed typed driver in an offline Bubblewrap sandbox, then records the identity-bound result.
`adapter_execute` is also local and
closed-world: it requires an active fleet lease, exact immutable task evidence, a matching operation contract, and a
current passing conformance report. It emits normalized and raw evidence plus an execution manifest. Neither accepts
caller-defined commands, arguments, environment variables, paths, scripts, plugins, mounts, or output directories.
Both are mutating because they write local conformance or evidence records, so clients should normally require
approval. `adapter_execute` returns a compact receipt and evidence handles; normalized analyzer data stays in the
content-addressed evidence store instead of crossing the MCP response-size boundary.

The remaining adapter tools search manifests, resolve and hash paths, read file-backed version metadata or cached
conformance observations, resolve capability coverage, or query already provisioned snapshots. They never install or
execute adapters as a side effect. In particular, status, campaign planning, adapter resolution, and fleet claiming do
not invoke provisioning, conformance, or execution.

Mutating tools are visibly annotated and use explicit identifiers. Response limiting applies at the root, mounted
servers mask error details consistently, tool lists are bounded, and HTTP sessions are stateless. Tool results still
need client-side approval policy appropriate to the deployment.

## Model-neutrality

MCP is an interface, not the reasoning provider. Claude, ChatGPT, Codex, local models, custom orchestrators, and human
operators can use the same schema. A model should search the corpus and capability catalog before inventing a method,
then preserve exact scope, task, evidence, and hypothesis identities in every call.
