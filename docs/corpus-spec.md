# Corpus specification

## Directory and identity

One playbook version lives at:

```text
corpus/playbooks/<primary-domain>/<technique>/playbook.yaml
```

`metadata.playbook_id` is a stable lowercase slug. `metadata.version` uses SemVer. A version is immutable after
release; corrections that change meaning create a new version. The deterministic corpus manifest records each path,
version, digest, lifecycle state, capabilities, and composition contract.

## Lifecycle

| State | Meaning |
|---|---|
| `draft` | Machine- or human-produced intake with unresolved semantics. |
| `proposed` | Submitted for corpus review with provenance and intended contract. |
| `reviewed` | Technical/source review completed; execution evidence may still be limited. |
| `validated` | The declared behavior has a named validator, date, and fixture/test command. |
| `deprecated` | Retained for reproducibility and linked to a replacement. |

Structural validity does not imply technical validity. A `validated` record says what validation occurred; adapter-
and target-specific limitations remain explicit.

All lifecycle states remain available to search and review. Default composition and campaign creation accept only
`reviewed` or `validated` versions. A caller can explicitly compose a draft for analysis, but cannot persist it as a
fleet campaign until its review state is promoted through the contribution process.

## Semantic contracts

Use open, lowercase semantic types such as `target/context`, `artifact/mobile-build`, `finding/candidate`, and
`finding/verified`. `composition.consumes` names the artifacts required before a playbook can run;
`composition.provides` names the artifacts available afterward.

Capability IDs are provider-neutral verbs such as `artifact.hash`, `http.capture`, and `experiment.intervene`. Add a
catalog definition when introducing a new ID. The playbook's execution class must be at least as high as every
required capability's class.

`scope.action_tags` declares behavior categories relevant to program prohibitions; it is distinct from descriptive
metadata tags. Side effects belong on the exact steps that can produce them. Campaign planning snapshots action tags,
the union of side effects, required capabilities, execution floor, request floor, version, and digest so a later task
cannot quietly weaken the reviewed playbook contract.

## Sources and rights

Every imported submission declares one of:

- `original-contribution`;
- `permission-granted`;
- `compatible-source-license`; or
- `public-domain`.

Source references identify author, title, URL, kind, license, content digest when available, access time, and notes.
Public readability is not permission to copy. Prefer original distillation, link to the source, and preserve any
required attribution.

## Validation

The loader rejects malformed YAML, unknown fields, dependency cycles, duplicate IDs/versions, symlinks, invalid
taxonomy normalization, inconsistent deprecation state, and unsubstantiated `validated` state. CI additionally checks
that built-in package assets match the public corpus and that all capabilities exist and are correctly classified.

See the generated [Playbook JSON Schema](../schemas/playbook.schema.json).
