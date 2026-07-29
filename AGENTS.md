# White Hat Agent Core

- Build a model-neutral public application layer for composable, evidence-backed cyber discovery.
- Optimize for novel, causally verified, reproducible discoveries per unit of cost.
- Preserve exact target identity, evidence provenance, negative results, and alternate findings.
- Keep the corpus capable of representing techniques from every cyber domain and perspective. Execution scope is
  campaign data, not a knowledge-censorship mechanism.
- Keep the core target-neutral and model-neutral. Side effects belong behind explicit adapters; planners emit typed
  operations rather than tool-specific shell prose.
- Community knowledge must retain original language and source provenance, compile into strict versioned playbooks,
  and remain reviewable before promotion.
- MCP surfaces are namespaced, bounded, and structured. Prefer stdio and stateless Streamable HTTP; do not add SSE.
- Fleet mutations require explicit campaign, target, lease, and evidence identities.
- Every planning decision must be deterministic from the episode manifest and explain its score and blockers.
- A changed hypothesis revision may justify a new probe; an unchanged failed probe must not be retried blindly.
- Treat apparent success as a hypothesis until causal and differential checks establish the actual path.
- Use bounded replay or synthetic fixtures for routine tests. Adapter-specific integration tests own their environments.
- Use `apply_patch` for hand-authored changes and run corpus/schema validation, `pytest`, `ruff check`, package build,
  and MCP smoke tests before handoff.
