from __future__ import annotations

from pathlib import Path

from white_hat_agent.capabilities.catalog import CapabilityCatalog
from white_hat_agent.knowledge.corpus import Corpus

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_capability_catalog_covers_and_classifies_builtin_corpus() -> None:
    catalog = CapabilityCatalog(REPOSITORY_ROOT / "capabilities" / "catalog.yaml")
    corpus = Corpus(REPOSITORY_ROOT / "corpus" / "playbooks")
    catalog_report = catalog.load()
    corpus_report = corpus.load()

    assert catalog_report.valid
    assert catalog_report.capability_count == 24
    assert corpus_report.valid
    compatibility = catalog.validate_playbooks(corpus.all())
    assert compatibility.valid, compatibility.issues


def test_capability_search_and_gap_analysis_are_explainable() -> None:
    catalog = CapabilityCatalog(REPOSITORY_ROOT / "capabilities" / "catalog.yaml")
    corpus = Corpus(REPOSITORY_ROOT / "corpus" / "playbooks")
    assert catalog.load().valid and corpus.load().valid

    hits = catalog.search("http request")
    gaps = catalog.gaps(
        [corpus.get("http-response-surface-map")],
        ["http.request", "http.capture"],
    )

    assert hits[0].capability.capability_id == "http.request"
    assert gaps.missing == ["data.diff", "evidence.write"]
    assert gaps.unknown == []
    assert not gaps.complete
