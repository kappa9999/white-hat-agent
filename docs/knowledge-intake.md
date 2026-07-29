# Knowledge intake and learning loop

## Community source

`KnowledgeSubmission` is an append-only source envelope. It keeps original language/text, rights, provenance, and
contributor identity beside the generated draft. A draft can be translated or normalized, but the source is never
discarded.

The ingestion boundary treats submitted instructions as data. It never executes commands embedded in prose, URLs,
playbook fields, or referenced files.

## Fleet source

A completed `TaskResult` can include `reusable_learning`. The fleet exposes those values as `LearningCandidate`
records tied to campaign, task, agent, evidence IDs, completion time, and a result digest.

```bash
wha knowledge candidates --workspace . --campaign-id example-lab-campaign
wha knowledge ingest-result \
  --workspace . \
  <candidate-id> \
  --rights original-contribution \
  --contributor <handle> \
  --persist
```

The second step requires an explicit rights declaration. It creates another draft and does not write to
`corpus/playbooks/`.

## Promotion gate

Promotion is a pull request that resolves applicability, capabilities, semantic artifacts, execution class, evidence,
failure modes, cleanup, source licensing, and validation. Automatic learning may propose; it cannot certify its own
claim or merge itself.
