# Contributing

White Hat Agent Core accepts reusable knowledge from every cyber domain and perspective. The corpus records what a
method does, what it needs, what it produces, how it fails, and how it is verified. It does not erase a technique
because someone labels it offensive or defensive. Executable tests must still use a target the contributor controls
or an explicitly captured program scope so results are reproducible and attributable.

## The easiest contribution path

You do not need to know Python, AI prompting, MCP, English, or the playbook schema.

1. Open the **Knowledge contribution** issue form.
2. Write the method in your language, including prerequisites, steps, expected signals, failure signals, side
   effects, cleanup, and how you know the mechanism is real.
3. State whether the text is original, permitted, compatibly licensed, or public domain. Link every source.
4. A maintainer or agent runs `wha knowledge ingest`; the original text remains embedded in the draft.
5. Reviewers resolve the compiler's unknowns, add a fixture, and submit the versioned playbook.

For local intake:

```bash
wha knowledge ingest \
  --file my-technique.md \
  --language es \
  --rights original-contribution \
  --playbook-yaml /tmp/playbook.yaml
```

The generated YAML is a **draft**, not proof that the method works.

## Pull-request types

### Corpus playbook

- Place one version at `corpus/playbooks/<domain>/<technique>/playbook.yaml`.
- Use namespaced capability IDs from `capabilities/catalog.yaml`; propose a capability when none fits.
- Preserve original-language instructions and source provenance.
- Declare semantic inputs/outputs so the composer can chain the method.
- Declare the highest execution class required by any step or capability.
- Add a bounded replay, synthetic fixture, or reproducible validation command.
- Do not mark a playbook `validated` without a validation time, validator identity, and fixture/test command.

### Capability or adapter contract

- Describe observable inputs, outputs, errors, bounds, side effects, and cleanup.
- Keep the contract provider-neutral. A concrete adapter may target a tool or MCP server.
- Do not hide sessions, credentials, scope decisions, or target identity from the calling model.

### Intelligence source or data-quality change

- Prefer an authoritative producer feed and document its identifiers, update semantics, deletions, rate limits,
  availability caveats, schema evolution, license, and attribution.
- Preserve exact raw source material by digest and keep source-native records even when aliases overlap another feed.
- Use closed incremental windows with overlap and idempotent upserts; add periodic reconciliation when a cursor cannot
  represent edits or tombstones.
- Add synthetic or sanitized frozen fixtures. Unit tests must not depend on a live network response.
- Treat prioritization data as a dated signal. Confirmed exploitation, probability, severity, and applicability are
  different facts and must remain independently inspectable.

### Core code

- Preserve strict Pydantic boundaries and deterministic IDs.
- Add tests for success, negative, malformed, stale, duplicate, and cross-identity cases.
- Keep live side effects behind adapters; routine CI uses local fixtures.

## Local verification

```bash
uv sync --locked --extra dev
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv run wha corpus validate --workspace .
uv run wha capability validate --workspace .
uv run python scripts/check_builtin_assets.py
uv run python scripts/export_schemas.py
git diff --exit-code -- schemas
uv build
```

## Evidence and publication hygiene

- Never commit credentials, session tokens, private keys, personal data, proprietary binaries, raw customer data, or
  undisclosed vulnerability details.
- Use synthetic or sanitized fixtures and preserve hashes/provenance of non-committed source artifacts.
- Do not copy an article, book, exploit, report, or codebase into the corpus merely because it is publicly readable.
  Distill it in original language and honor its license.
- Separate technical validity, authorship, authorization, and disclosure status.
- Report vulnerabilities in this repository through [SECURITY.md](SECURITY.md), not a public issue.

## Developer Certificate of Origin

Sign each commit:

```text
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s`. The sign-off certifies that you authored the contribution or otherwise have the right to submit
it under the project's license. The full DCO is at <https://developercertificate.org/>.
