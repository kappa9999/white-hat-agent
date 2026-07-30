# Production intelligence and research loop

White Hat Agent is operated as an evidence-producing research system, not as an unbounded scanner. The first
production slice continuously collects public vulnerability intelligence, preserves exact source material, ranks
work, and hands selected records to scoped local or explicitly authorized investigations.

## Goal function

The long-running objective is to maximize durable public-security value:

```text
research value
  = verified novelty + expected impact + reproducibility
    + transferability + information gain + negative-result reuse
    - compute cost - reviewer cost - duplicate work - blast radius
```

The score is subordinate to hard invariants. A high-value idea is ineligible when target identity or authorization is
ambiguous, evidence provenance is missing, the proposed action exceeds the captured scope, or publication would
violate a disclosure or source-rights obligation. Public advisories are leads, not authorization to interact with a
deployed target.

This objective is measured over completed, reproducible outcomes rather than tool calls, findings claimed, or raw
scan volume. A strong negative result can be valuable when it closes a hypothesis and prevents repeated work.

## Operating cycle

```mermaid
flowchart LR
    S[Sense official sources] --> N[Normalize and correlate]
    N --> R[Rank transparent signals]
    R --> M[Match exact artifact]
    M --> C[Capture exact scope]
    C --> I[Investigate in a local or authorized lab]
    I --> V[Verify differential and causal evidence]
    V --> P[Publish or disclose]
    P --> L[Learn and evaluate]
    L --> S
    V -->|negative result| L
```

1. **Sense:** fetch only fixed, documented public sources with bounded requests. Preserve response identity, retrieval
   time, content type, ETag/Last-Modified when supplied, digest, attribution, and the exact raw bytes used.
2. **Normalize:** retain source-native records. Correlate CVE, GHSA, OSV, PYSEC, and ecosystem identities as aliases;
   never erase one provider's provenance by collapsing it into another provider's record.
3. **Rank:** combine confirmed exploitation, dated probability signals, recency, severity, and evidence completeness.
   Store the factors and reasons alongside the score. CISA KEV confirmation outranks a low EPSS forecast.
4. **Match:** compare the advisory with one exact package/build/commit. Preserve `indeterminate`
   when normalized facts or range semantics are incomplete; never treat rejection, withdrawal, or a name miss as
   proof that an artifact is unaffected.
5. **Scope:** convert a lead into executable work only after exact target/build and authorization are captured in a
   `ScopeManifest`. Automation permission is never inferred from the existence of a CVE or a public repository.
6. **Investigate:** prefer source review, patch-differential analysis, deterministic fixtures, and locally built
   vulnerable/fixed versions. Any live adapter must enforce scope, rate, budget, cancellation, and evidence limits.
7. **Verify:** require exact identities, raw artifacts, controls, repeated observations, and causal/differential proof
   before escalating a claim. Preserve alternate findings and failed hypotheses.
8. **Publish:** public intelligence briefs may be generated automatically. Vulnerability claims and external patches
   must be deduplicated, reproducible, minimally disclosed, and sent through the affected project's policy.
9. **Learn:** promote reusable procedure only through the existing rights, review, and validation lifecycle. Compare
   later campaign outcomes so weak heuristics can be revised or retired.

## Initial source contract

| Source | Role | Initial cadence | State rule |
|---|---|---:|---|
| CISA Known Exploited Vulnerabilities | Confirmed exploitation | 6 hours | Snapshot and diff the complete catalog; `dateAdded` is not a cursor |
| CVE List V5 | Canonical CNA/ADP records and CVE state | 6 hours | Checkpoint the captured upstream batch time with overlap; never equate rejection, withdrawal, and source deletion |
| OSV | Package, version, and Git-range applicability | 6 hours | Read the reverse-chronological modified index with an overlap window, then snapshot selected records |
| FIRST EPSS | Dated probability enrichment | With each selected CVE set | Preserve current plus bounded time-series observations; never treat probability as proof of exploitation |
| NVD 2.0 | CVSS, SSVC, CWE, CPE/configuration, and reference enrichment | 6 hours; no more than every 2 hours | Closed overlapping last-modified windows, fail-closed pagination, and documented rate limits |

OSV aggregates records with different upstream licenses. Every snapshot and normalized record therefore retains its
own source URI and attribution metadata; the corpus license is never assumed to replace an upstream source license.
EPSS is enrichment-only: missing scores remain visible as a partial enrichment result but do not invalidate a
successful primary-source checkpoint. NVD records use the required attribution: "This product uses data from the NVD
API but is not endorsed or certified by the NVD."

### NVD record contract

The `nvd` adapter requests only the official CVE API 2.0 endpoint with a closed last-modified start/end window,
`resultsPerPage`, and `startIndex`. The public-client path waits six seconds between pages. A successful checkpoint
advances only after every declared result is captured within the configured record and page ceilings; a changing
`totalResults`, duplicate CVE, malformed page, or exceeded ceiling retains evidence but fails the checkpoint closed.

Each page and its selection manifest are immutable snapshots. Normalized CVSS, SSVC, CWE, and reference fields enrich
the correlated CVE without replacing canonical CVE List V5 title, description, state, or affected-package semantics.
The full NVD `configurations` and `affected` values remain source-native evidence. White Hat Agent does not flatten
NVD's Boolean CPE applicability tree into package claims without a dedicated evaluator.

### CVE Program record contract

The `cve-list-v5` adapter reads the CVE Program's official rolling delta log and only the exact record URLs derived
from validated CVE IDs. It snapshots the delta and every selected record before interpreting JSON. It never follows
references embedded in a record.

- The rolling log normally covers 30 days. Selection is based on the enclosing batch `fetchTime`; `dateUpdated` is
  retained as a record consistency check. A successful cursor advances only to the greatest captured upstream
  `fetchTime`, never the workstation clock.
- Replays subtract a two-hour overlap and deduplicate by CVE ID. Limits, malformed data, upstream batch errors,
  throttling, missing records, or a history gap retain successful idempotent upserts but do not advance the cursor or
  HTTP validator.
- Record versions `5.0`, `5.1`, and `5.2` map to the published CVE schema releases `5.0.0`, `5.1.1`, and `5.2.0`.
  Unknown future versions are preserved as raw snapshots and fail the checkpoint closed until their contract is
  reviewed.
- A CVE Record state is `PUBLISHED` or `REJECTED`. `dateReserved` is preserved as metadata; `RESERVED` is not a CVE
  List V5 record state. Rejection remains explicitly queryable and is not rewritten as withdrawal or disappearance.
- The immutable raw record snapshot is canonical for the complete CNA container and every ADP container. Normalized
  source metadata keeps only compact JSON-pointer/`providerMetadata` indices into that snapshot.
- Normalized affected packages, PURLs, CWEs, references, and CVSS signals are additive views. Native CVE version
  ranges become normalized events only when their default/status transitions can be represented exactly; otherwise
  the native range remains available through its JSON pointer without an invented `fixed` event.

The data is attributed to the CVE Program under the [CVE Program Terms of
Use](https://www.cve.org/Legal/TermsOfUse). Provider/assigner identity remains attached to the record, and no CVE
entry implies CVE Program, CNA, or ADP endorsement of White Hat Agent.

## Automation levels

| Level | Default automation | Required gate |
|---|---|---|
| Intelligence | Fetch, validate, correlate, score, brief | Fixed official endpoint, byte/item/time bounds, immutable snapshot |
| Triage | Select local patch-diff or fixture candidates | Exact repository/version identity and duplicate search |
| Investigation | Build and test vulnerable/fixed versions locally | Reproducible environment, timeout, resource budget, evidence manifest |
| Authorized live work | Execute a bounded adapter | Current scope digest, explicit automation permission, target/rate/budget match |
| Publication | Generate a draft report or patch | Causal evidence, redaction/disclosure check, project policy, no duplicate thread |

Remote multi-tenant MCP deployment is outside the first production slice. Until authentication, authorization,
tenant isolation, audit principals, and a secrets boundary exist, use stdio or bind Streamable HTTP to localhost.

## Service objectives and scorecard

The scheduled monitor is healthy when:

- every successful run emits machine-readable source reports, a bounded ranked selection, a Markdown brief, and raw
  content-addressed snapshots;
- the latest successful CISA, CVE List V5, NVD, and OSV checkpoints are no more than 12 hours old;
- repeated overlapping runs are idempotent and record source updates without duplicating advisories;
- malformed, oversized, or partial upstream data fails closed and is visible in the run report;
- every ranked item exposes its score factors, aliases, source timestamp, observed time, raw digest, and attribution;
- KEV items are never demoted below non-KEV items solely because EPSS is low or absent; and
- no network interaction with an advisory's affected target occurs during intelligence ingestion.

The project-level scorecard tracks feed freshness, source coverage, snapshot integrity, correlation accuracy,
evidence completeness, false-positive rate, cost per reproduced result, negative-result reuse, time to triage,
external contribution acceptance, and time to close or revise invalid claims.

## Professional collaboration loop

External interaction is selective. Before opening an issue, comment, or pull request:

1. read the repository's security and contribution policy;
2. search for an existing advisory, issue, pull request, or embargoed process;
3. reproduce the exact problem on an allowed local artifact and test the proposed change;
4. minimize the patch and separate confirmed evidence from inference;
5. use one appropriate channel and avoid repetitive status comments; and
6. record the outcome so accepted and rejected approaches improve later routing.

An external contribution is successful when it saves maintainers work and survives their tests—not when it merely
creates activity.

## Deployment and recovery

`.github/workflows/intelligence.yml` runs the read-only source collectors on a recurring schedule and through manual
dispatch. Each hosted run restores the latest successful state artifact when available, writes a unique report, and
uploads the report, brief, normalized records, and the exact snapshots referenced or first observed in that run. A
separate two-day state handoff carries the SQLite index and cumulative content-addressed store to the next run. This
keeps cursors, validators, alias history, and recovery durable without repeatedly retaining the full cumulative store
as long-lived evidence. Persistent workstation or self-hosted-runner workspaces use the same overlapping windows and
idempotent upserts directly.

For a workstation or self-hosted runner:

```bash
wha init white-hat-workspace
wha intelligence sync \
  --workspace white-hat-workspace \
  --source cisa-kev --source osv \
  --since-hours 48 --limit-per-source 1000 --enrich-epss --require-success \
  --out white-hat-workspace/.whitehat/intelligence/reports/sync.json
wha intelligence sync \
  --workspace white-hat-workspace \
  --source cve-list-v5 \
  --since-hours 6 --limit-per-source 5000 --require-success \
  --out white-hat-workspace/.whitehat/intelligence/reports/cve-list-v5-sync.json
wha intelligence sync \
  --workspace white-hat-workspace \
  --source nvd \
  --since-hours 6 --limit-per-source 5000 --require-success \
  --out white-hat-workspace/.whitehat/intelligence/reports/nvd-sync.json
wha intelligence brief \
  --workspace white-hat-workspace \
  --source osv --source cve-list-v5 --source nvd \
  --limit 25 \
  --out white-hat-workspace/.whitehat/intelligence/reports/brief.md
wha intelligence epss-history CVE-2023-44487 \
  --workspace white-hat-workspace \
  --as-of 2026-07-01 \
  --out white-hat-workspace/.whitehat/intelligence/reports/epss-history.json
wha intelligence applicability \
  --request applicability-request.json \
  --out applicability-decision.json
```

`applicability` is a pure local check. Its generated request/decision schemas bind the normalized advisory and exact
artifact digests; the result never substitutes for the existing scope evaluator.

`limit-per-source` is a CVE List V5, NVD, OSV, or EPSS fail-closed ceiling, not a request target; CISA always validates
and diffs its complete bounded catalog. Incremental readers stop at their closed-window boundaries. If a ceiling is
reached first, the source reports `partial`, and `--require-success` prevents cursor advancement from being mistaken
for a complete production run. Use `--include-rejected` on `list` or `brief` only when rejected CVE records are part
of the analysis. Ecosystem filters narrow OSV acquisition and query views; canonical CVE records are always persisted
unfiltered so a later query cannot inherit gaps from an earlier filtered checkpoint.

If a run is interrupted, it is explicitly recorded as `interrupted` and retains its snapshots. A source that completed
before interruption keeps its own checkpoint; the active source does not receive a successful checkpoint. Re-run with
an overlapping window; content addressing and idempotent upserts make replay safe.
