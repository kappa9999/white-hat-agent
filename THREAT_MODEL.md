# Threat model

## Assets

- private program rules, credentials, target lists, and disclosure instructions;
- corpus integrity, source provenance, contributor rights, and validation state;
- campaign budgets, task identities, agent leases, and results;
- raw evidence, findings, personal data, and unpublished vulnerability details;
- local filesystem, adapter processes, model context, and MCP endpoint; and
- release, maintainer, and package-publishing identities.

## Trust boundaries and threats

| Boundary | Representative threats | Current controls |
|---|---|---|
| Community text → intake | prompt injection, hidden commands, plagiarism, hostile links, false claims | input treated as data; no execution; original retained; rights/source fields; draft lifecycle |
| Playbook PR → trusted corpus | schema smuggling, alias expansion, capability under-classification, symlinks, fabricated validation | strict models; bounded alias-free YAML; unknown-field rejection; DAG checks; symlink rejection; capability compatibility; validation record; campaign review floor |
| Model/agent → MCP | malformed calls, oversized output, confused-deputy mutation, secret leakage | bounded schemas and responses; namespaced tools; explicit identifiers; local default; masked errors |
| Opportunity → campaign | stale or fake scope, inferred automation permission, wrong target | opportunity distinct from scope; scope digest; validity window; exact rules; exclusion precedence |
| Campaign → fleet | fabricated allow decision, under-declared playbook, duplicates, budget exhaustion, lease theft | fleet-side re-evaluation; scope/intent/playbook digests; contract snapshots; dedup keys; coordinator clock; budgets; random tokens stored only as hashes |
| Fleet → adapter | overstated capability, wrong execution class, hidden side effects | catalog contracts; agent capability inventory; execution ceiling; typed intent; adapter integration tests required |
| Adapter → evidence | fabricated/truncated output, target drift, TOCTOU, malicious file | provenance fields; exact target/task; max import size; symlink rejection; streaming hash; atomic copy; post-copy hash |
| Evidence → finding | cross-campaign mix-up, unsupported mechanism, sensitive disclosure | campaign/task binding; evidence requirement; sensitivity/redaction fields; causal verification; disclosure policy |
| Result → corpus learning | self-certification, poisoned memory, rights ambiguity | candidate queue; explicit rights; lossless source; manual PR/promotion; no automatic trusted write |
| Repository → release | malicious dependency/action, stolen maintainer identity, package confusion | lockfile; minimal CI permissions; pinned action commit; sole release authority; publication checklist |

## Explicit non-goals and residual risk

The core does not currently sandbox arbitrary adapter processes, manage secrets, authenticate its HTTP MCP endpoint,
verify a remote program page, provide multi-tenant isolation, sign evidence with hardware keys, or prove an agent's
self-reported capability. Deployments must add those controls around live adapters.

SQLite provides strong local coordination but is not a distributed consensus system. A future remote coordinator must
define tenant identity, authentication, authorization, replay protection, rate limiting, encryption, audit logging,
and failure semantics before accepting untrusted network workers.

No schema can establish legal authorization from prose alone. `authorization_reference`, captured rules, and scope
digests preserve operator evidence and prevent drift; the operator remains responsible for the accuracy and current
applicability of that evidence.

## Security invariants

1. Untrusted knowledge never becomes campaign-eligible merely by being parsed; reviewed/validated status is required.
2. A caller cannot supply its own trusted “allowed” flag to enqueue work.
3. A scope decision is bound to exact scope and intent digests.
4. Every intent is bound to an exact selected playbook version, digest, and minimum execution contract.
5. Only a compatible registered agent can claim a task from a running campaign.
6. A lease token is never stored or returned after completion.
7. Supported/verified findings name registered evidence from the same campaign.
8. Fleet learning cannot auto-promote into the trusted corpus.
9. Generated/bundled assets must match their public source copies in CI.
