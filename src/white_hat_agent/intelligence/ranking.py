from __future__ import annotations

from datetime import UTC, datetime

from .models import IntelligenceSource, NormalizedAdvisory, PriorityFactors, SeverityKind


def rank_advisory(advisory: NormalizedAdvisory, *, as_of: datetime) -> PriorityFactors:
    """Rank public advisories with a deterministic, inspectable KEV-first formula.

    A current CISA KEV confirmation contributes 1000 points. Every non-KEV
    factor combined is capped at 220 points, so weak EPSS noise can never
    outrank confirmed exploitation evidence.
    """

    as_of = _aware_utc(as_of)
    confirmed_kev = (
        advisory.known_exploited
        and IntelligenceSource.CISA_KEV in advisory.sources
        and not _kev_is_tombstoned(advisory)
    )
    kev_component = 1000.0 if confirmed_kev else 0.0

    epss_signals = [
        signal
        for signal in advisory.severity
        if signal.kind == SeverityKind.EPSS
        and signal.probability is not None
        and (signal.observed_at is None or _aware_utc(signal.observed_at) <= as_of)
    ]
    epss_signal = max(
        epss_signals,
        key=lambda signal: (
            _aware_utc(signal.observed_at).timestamp() if signal.observed_at else float("-inf"),
            signal.probability or 0.0,
        ),
        default=None,
    )
    epss_probability = epss_signal.probability if epss_signal else None
    epss_provider = "FIRST EPSS" if epss_signal else None
    epss_observed_at = epss_signal.observed_at if epss_signal else None
    epss_component = (epss_probability or 0.0) * 100.0

    reference_time = advisory.modified_at or advisory.published_at
    if reference_time is None:
        recency_age_days = None
        recency_score = 0.0
    else:
        age_seconds = max(0.0, (as_of - _aware_utc(reference_time)).total_seconds())
        recency_age_days = age_seconds / 86_400.0
        recency_score = max(0.0, 1.0 - (recency_age_days / 90.0))
    recency_component = recency_score * 40.0

    severity_score = _severity_score(advisory)
    severity_component = severity_score * 60.0
    evidence_completeness = _evidence_completeness(advisory)
    evidence_component = evidence_completeness * 20.0
    total_score = kev_component + epss_component + recency_component + severity_component + evidence_component

    reasons: list[str] = []
    if confirmed_kev:
        reasons.append("confirmed CISA KEV evidence (+1000.000)")
    else:
        reasons.append("no current CISA KEV confirmation (+0.000)")
    if epss_probability is None:
        reasons.append("no EPSS probability (+0.000)")
    else:
        observed = epss_observed_at.date().isoformat() if epss_observed_at else "undated"
        reasons.append(
            f"FIRST EPSS probability {epss_probability:.6f} observed {observed} (+{epss_component:.3f})"
        )
    if recency_age_days is None:
        reasons.append("no advisory timestamp (+0.000)")
    else:
        reasons.append(f"modified/published {recency_age_days:.3f} days ago (+{recency_component:.3f})")
    reasons.append(f"normalized severity {severity_score:.3f} (+{severity_component:.3f})")
    reasons.append(f"evidence completeness {evidence_completeness:.3f} (+{evidence_component:.3f})")
    return PriorityFactors(
        as_of=as_of,
        confirmed_kev=confirmed_kev,
        kev_component=_rounded(kev_component),
        epss_probability=epss_probability,
        epss_provider=epss_provider,
        epss_observed_at=epss_observed_at,
        epss_component=_rounded(epss_component),
        recency_age_days=None if recency_age_days is None else _rounded(recency_age_days),
        recency_score=_rounded(recency_score),
        recency_component=_rounded(recency_component),
        severity_score=_rounded(severity_score),
        severity_component=_rounded(severity_component),
        evidence_completeness=_rounded(evidence_completeness),
        evidence_component=_rounded(evidence_component),
        total_score=_rounded(total_score),
        reasons=reasons,
    )


def _severity_score(advisory: NormalizedAdvisory) -> float:
    values: list[float] = []
    labels = {"critical": 1.0, "high": 0.8, "moderate": 0.5, "medium": 0.5, "low": 0.2}
    for signal in advisory.severity:
        if signal.score is not None:
            values.append(signal.score / 10.0)
        if signal.label:
            values.append(labels.get(signal.label.casefold(), 0.0))
    return max(values, default=0.0)


def _evidence_completeness(advisory: NormalizedAdvisory) -> float:
    return (
        (0.15 if advisory.identifiers else 0.0)
        + (0.15 if advisory.title or advisory.summary else 0.0)
        + (0.25 if advisory.affected else 0.0)
        + (0.20 if advisory.references else 0.0)
        + (0.15 if advisory.severity else 0.0)
        + (0.10 if advisory.provenance else 0.0)
    )


def _kev_is_tombstoned(advisory: NormalizedAdvisory) -> bool:
    return IntelligenceSource.CISA_KEV in advisory.tombstoned_sources


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("ranking as_of must be timezone-aware")
    return value.astimezone(UTC)


def _rounded(value: float) -> float:
    return round(value, 6)
