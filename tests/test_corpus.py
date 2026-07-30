from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from white_hat_agent.knowledge.corpus import Corpus
from white_hat_agent.knowledge.models import semver_key

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_corpus_is_valid_and_deterministic() -> None:
    corpus = Corpus(REPOSITORY_ROOT / "corpus" / "playbooks")
    first = corpus.load()
    first_manifest = corpus.manifest()
    second = corpus.load()
    second_manifest = corpus.manifest()

    assert first.valid and second.valid
    assert first.playbook_count == 6
    assert first_manifest.manifest_digest == second_manifest.manifest_digest
    assert corpus.get("http-response-surface-map").metadata.version == "1.0.0"


def test_corpus_search_applies_capability_subset_filter() -> None:
    corpus = Corpus(REPOSITORY_ROOT / "corpus" / "playbooks")
    assert corpus.load().valid

    no_adapter = corpus.search("http", capabilities=["http.request"])
    full_adapter = corpus.search(
        "http",
        capabilities=["http.request", "http.capture", "data.diff", "evidence.write"],
    )

    assert no_adapter == []
    assert [hit.playbook_id for hit in full_adapter] == ["http-response-surface-map"]


def test_duplicate_playbook_and_symlink_are_rejected(tmp_path) -> None:
    source = REPOSITORY_ROOT / "corpus" / "playbooks" / "web" / "http-observation" / "playbook.yaml"
    first = tmp_path / "one.yaml"
    second = tmp_path / "two.yaml"
    shutil.copy2(source, first)
    shutil.copy2(source, second)
    linked = tmp_path / "linked.yaml"
    linked.symlink_to(first)

    report = Corpus(tmp_path).load()
    codes = {issue.code for issue in report.issues}

    assert not report.valid
    assert "playbook.duplicate" in codes
    assert "corpus.symlink" in codes


def test_validated_playbook_requires_validation_evidence(tmp_path) -> None:
    source = REPOSITORY_ROOT / "corpus" / "playbooks" / "web" / "http-observation" / "playbook.yaml"
    payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    payload.pop("validation")
    (tmp_path / "invalid.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")

    report = Corpus(tmp_path).load()

    assert not report.valid
    assert "validated playbooks require validation time" in report.issues[0].message


def test_semver_precedence_handles_prerelease_and_build_metadata() -> None:
    assert semver_key("1.0.0") > semver_key("1.0.0-rc.10")
    assert semver_key("1.0.0-rc.10") > semver_key("1.0.0-rc.2")
    assert semver_key("1.0.0+build.2") == semver_key("1.0.0+build.1")


def test_corpus_rejects_oversized_playbook_before_yaml_parsing(tmp_path) -> None:
    (tmp_path / "oversized.yaml").write_text("x" * 101, encoding="utf-8")

    report = Corpus(tmp_path, max_playbook_bytes=100).load()

    assert not report.valid
    assert "maximum is 100" in report.issues[0].message


def test_corpus_rejects_yaml_aliases_and_excessive_nesting(tmp_path) -> None:
    (tmp_path / "alias.yaml").write_text("value: &shared [x]\ncopy: *shared\n", encoding="utf-8")
    deep_lines = ["value:"]
    deep_lines.extend(f"{'  ' * level}-" for level in range(1, 102))
    deep_lines.append(f"{'  ' * 102}leaf")
    deep = "\n".join(deep_lines) + "\n"
    (tmp_path / "deep.yaml").write_text(deep, encoding="utf-8")

    report = Corpus(tmp_path).load()
    messages = " ".join(issue.message for issue in report.issues)

    assert not report.valid
    assert "aliases are not allowed" in messages
    assert "nesting exceeds 100" in messages
