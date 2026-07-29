# Playbook authoring

## Start with what you know

A useful raw contribution answers as many of these as possible:

1. What exact target/artifact/context does the method need?
2. What observation or problem makes you choose it?
3. What are the smallest ordered steps?
4. What tools or capabilities are required?
5. What success and failure signals are observable?
6. What evidence proves the path or mechanism?
7. What side effects, budgets, timeouts, retries, and cleanup apply?
8. What assumptions or environment details make it fail?
9. What new artifact can another method consume?
10. What source and reuse rights apply?

Write in any language. Do not translate away domain-specific meaning just to fit English terminology.

## Compile a draft

```bash
wha knowledge ingest \
  --workspace . \
  --file technique.md \
  --language ja \
  --rights original-contribution \
  --playbook-yaml /tmp/technique.yaml
```

The heuristic compiler is deliberately conservative. It preserves the source and emits unresolved work. Through MCP,
a host model can request `knowledge_compile_submission`; its answer must still validate and be reviewed.

## Make it composable

Prefer semantic artifacts over tool prose:

```yaml
composition:
  consumes: [artifact/vulnerable-build, artifact/fixed-build]
  provides: [evidence/semantic-diff, hypothesis/variant]
```

Prefer capability contracts over one vendor command:

```yaml
required_capabilities: [artifact.hash, binary.diff, code.search]
```

A tool-specific adapter can fulfill those contracts without locking the playbook to that tool forever.

## Prove rather than narrate

For each step, specify observable success and failure signals. A visible effect may come through an alternate path;
when mechanism matters, add reproduction, direct path observation, a narrow intervention or fixed-variant
differential, shortcut exclusion, and regression closure.

Keep negative results. They prevent exact retries and reveal assumptions that future models can use.

## Validate

Use synthetic, replayed, owned, or explicitly scoped fixtures. Record the fixture IDs, exact commands, validator, date,
and known limitations. Run:

```bash
wha corpus validate --workspace .
wha capability validate --workspace .
pytest tests/test_corpus.py tests/test_composition.py
```
