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

Mounted names become `knowledge_search`, `adapter_resolve`, `intelligence_sync`, `campaign_enqueue`, and so on.
Tools use strict structured input/output. Resources expose workspace health, the corpus manifest, playbooks, and the
capability and concrete-adapter catalogs. Prompts help a host model compile submissions, normalize opportunities,
and plan campaigns without requiring one provider's API.

`campaign_plan` is the bridge from knowledge to fleet work: given exact scope, targets, initial and desired semantic
artifacts, an execution ceiling, and available adapter capabilities, it composes corpus playbooks and emits ordered
stages. Each stage carries its own `ProbeIntent` and freshly evaluated `ScopeDecision`. Planning is read-only; the
operator or host agent still persists the manifest, explicitly transitions its lifecycle, and enqueues chosen stages.

Three built-in tools are open-world. `intelligence_sync` performs bounded GET requests to fixed official CVE List V5,
CISA, OSV, and optional FIRST EPSS endpoints, then mutates only the local workspace state and snapshot store.
`adapter_plan_provision` performs read-only resolution against the reviewed provider's official GitHub release or
commit API. `adapter_provision` applies an exact plan by downloading only its resolved official artifacts or commit
into `.whitehat/adapters/`; it is both networked and mutating. None contacts advisory targets. Clients should require
approval for synchronization and provisioning when those side effects are not already part of operator policy.

The other adapter tools search manifests, observe local versions, resolve capability coverage, or query already
provisioned snapshots. They never install as a side effect. In particular, campaign planning and fleet claiming do
not invoke provisioning.

Mutating tools are visibly annotated and use explicit identifiers. Response limiting applies at the root, mounted
servers mask error details consistently, tool lists are bounded, and HTTP sessions are stateless. Tool results still
need client-side approval policy appropriate to the deployment.

## Model-neutrality

MCP is an interface, not the reasoning provider. Claude, ChatGPT, Codex, local models, custom orchestrators, and human
operators can use the same schema. A model should search the corpus and capability catalog before inventing a method,
then preserve exact scope, task, evidence, and hypothesis identities in every call.
