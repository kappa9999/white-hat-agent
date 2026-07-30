from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from white_hat_agent.evidence.models import (
    EvidenceDescriptor,
    FindingRecord,
    FindingSeverity,
    FindingStatus,
)
from white_hat_agent.evidence.store import EvidenceError, EvidenceStore
from white_hat_agent.models import ProofTier


def _descriptor(*, campaign_id: str = "example-lab-campaign") -> EvidenceDescriptor:
    return EvidenceDescriptor(
        campaign_id=campaign_id,
        task_id="task-fixture",
        target="api.example.test",
        evidence_type="evidence/http-transaction",
        title="Synthetic baseline transaction",
        description="Bounded request and response fixture",
        producer="fixture-adapter",
        captured_at=datetime(2026, 7, 29, tzinfo=UTC),
        provenance={"adapter_version": "1.0.0"},
    )


def test_content_addressed_import_is_verified_and_idempotent(tmp_path) -> None:
    source = tmp_path / "transaction.json"
    source.write_text('{"status": 200}\n', encoding="utf-8")
    store = EvidenceStore(tmp_path / "state.db", tmp_path / "artifacts")
    store.initialize()

    first = store.import_file(source, _descriptor(), media_type="application/json")
    second = store.import_file(source, _descriptor(), media_type="application/json")
    stored = tmp_path / "artifacts" / first.storage_path

    assert first.evidence_id == second.evidence_id
    assert first.content_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert stored.read_bytes() == source.read_bytes()
    assert store.get_evidence(first.evidence_id) == first
    assert store.list_evidence(campaign_id="example-lab-campaign") == [first]


def test_local_file_resolution_requires_exact_binding_and_reverifies_content(tmp_path) -> None:
    source = tmp_path / "trace.txt"
    source.write_text("trace fixture", encoding="utf-8")
    store = EvidenceStore(tmp_path / "state.db", tmp_path / "artifacts")
    store.initialize()
    evidence = store.import_file(source, _descriptor(), media_type="text/plain")

    resolved_record, resolved_path = store.resolve_local_file(
        evidence.evidence_id,
        "example-lab-campaign",
        "task-fixture",
    )

    assert resolved_record == evidence
    assert resolved_path == (store.artifacts_dir / evidence.storage_path).resolve()
    with pytest.raises(EvidenceError, match="different campaign"):
        store.resolve_local_file(evidence.evidence_id, "different-campaign", "task-fixture")
    with pytest.raises(EvidenceError, match="exact task"):
        store.resolve_local_file(evidence.evidence_id, "example-lab-campaign", "different-task")

    unbound_source = tmp_path / "unbound.txt"
    unbound_source.write_text("unbound", encoding="utf-8")
    unbound = store.import_file(
        unbound_source,
        _descriptor().model_copy(update={"task_id": None}),
        media_type="text/plain",
    )
    with pytest.raises(EvidenceError, match="exact task"):
        store.resolve_local_file(unbound.evidence_id, "example-lab-campaign", "task-fixture")

    resolved_path.write_text("drift fixture", encoding="utf-8")
    assert resolved_path.stat().st_size == evidence.byte_length
    with pytest.raises(EvidenceError, match="digest verification"):
        store.resolve_local_file(evidence.evidence_id, "example-lab-campaign", "task-fixture")

    resolved_path.write_text("short", encoding="utf-8")
    with pytest.raises(EvidenceError, match="byte length verification"):
        store.resolve_local_file(evidence.evidence_id, "example-lab-campaign", "task-fixture")


def test_local_file_snapshot_is_private_digest_verified_and_bounded(tmp_path) -> None:
    source = tmp_path / "binary"
    source.write_bytes(b"owned fixture")
    store = EvidenceStore(tmp_path / "state.db", tmp_path / "artifacts")
    store.initialize()
    evidence = store.import_file(source, _descriptor(), media_type="application/octet-stream")

    record, snapshot = store.snapshot_local_file(
        evidence.evidence_id,
        "example-lab-campaign",
        "task-fixture",
        tmp_path / "broker/input.artifact",
        max_bytes=1024,
    )

    assert record == evidence
    assert snapshot.read_bytes() == b"owned fixture"
    assert snapshot.stat().st_mode & 0o777 == 0o400
    with pytest.raises(EvidenceError, match="snapshot byte limit"):
        store.snapshot_local_file(
            evidence.evidence_id,
            "example-lab-campaign",
            "task-fixture",
            tmp_path / "broker/second.artifact",
            max_bytes=1,
        )


def test_local_file_resolution_rejects_external_links_special_files_and_path_drift(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "state.db", tmp_path / "artifacts")
    store.initialize()
    external = store.register_external(
        _descriptor(),
        content_sha256="a" * 64,
        byte_length=1,
        media_type="text/plain",
        external_uri="https://evidence.invalid/fixture",
    )
    with pytest.raises(EvidenceError, match="not local content-addressed"):
        store.resolve_local_file(external.evidence_id, "example-lab-campaign", "task-fixture")

    source = tmp_path / "local.txt"
    source.write_text("local fixture", encoding="utf-8")
    evidence = store.import_file(source, _descriptor(), media_type="text/plain")
    stored = store.artifacts_dir / evidence.storage_path
    stored.unlink()
    stored.symlink_to(source)
    with pytest.raises(EvidenceError, match="symbolic link"):
        store.resolve_local_file(evidence.evidence_id, "example-lab-campaign", "task-fixture")

    stored.unlink()
    stored.mkdir()
    with pytest.raises(EvidenceError, match="regular file"):
        store.resolve_local_file(evidence.evidence_id, "example-lab-campaign", "task-fixture")

    payload = evidence.model_dump(mode="json")
    payload["storage_path"] = "../local.txt"
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE evidence_records SET record_json = ? WHERE evidence_id = ?",
            (json.dumps(payload, sort_keys=True), evidence.evidence_id),
        )
    with pytest.raises(EvidenceError, match="not content-addressed"):
        store.resolve_local_file(evidence.evidence_id, "example-lab-campaign", "task-fixture")


def test_symlink_and_oversized_imports_are_rejected(tmp_path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("12345", encoding="utf-8")
    linked = tmp_path / "linked.txt"
    linked.symlink_to(source)
    store = EvidenceStore(tmp_path / "state.db", tmp_path / "artifacts", max_import_bytes=4)
    store.initialize()

    with pytest.raises(EvidenceError, match="non-symlink"):
        store.import_file(linked, _descriptor())
    with pytest.raises(EvidenceError, match="exceeds import limit"):
        store.import_file(source, _descriptor())


def test_verified_finding_is_bound_to_existing_same_campaign_evidence(tmp_path) -> None:
    source = tmp_path / "trace.txt"
    source.write_text("trace fixture", encoding="utf-8")
    store = EvidenceStore(tmp_path / "state.db", tmp_path / "artifacts")
    store.initialize()
    evidence = store.import_file(source, _descriptor(), media_type="text/plain")
    finding = FindingRecord.create(
        campaign_id="example-lab-campaign",
        task_id="task-fixture",
        target="api.example.test",
        playbook_id="http-response-surface-map",
        title="Synthetic response differential",
        summary="A controlled fixture demonstrates the evidence binding path.",
        status=FindingStatus.VERIFIED,
        severity=FindingSeverity.INFORMATIONAL,
        proof_tier=ProofTier.DIFFERENTIAL,
        evidence_ids=[evidence.evidence_id],
    )

    assert store.add_finding(finding) == finding
    assert store.get_finding(finding.finding_id) == finding
    assert store.list_findings(campaign_id="example-lab-campaign") == [finding]

    revised_payload = finding.model_dump(mode="json")
    revised_payload.update(
        {
            "revision": 2,
            "previous_digest": finding.digest(),
            "status": FindingStatus.SUBMITTED.value,
            "updated_at": finding.updated_at + timedelta(minutes=1),
            "disclosure_notes": ["Submitted through the synthetic fixture channel."],
        }
    )
    revised = FindingRecord.model_validate(revised_payload)
    store.add_finding(revised)
    assert store.get_finding(finding.finding_id) == revised
    assert store.finding_history(finding.finding_id) == [finding, revised]

    wrong_campaign = finding.model_copy(
        update={"finding_id": "finding-wrong-campaign", "campaign_id": "different-campaign"}
    )
    with pytest.raises(EvidenceError, match="different campaign"):
        store.add_finding(wrong_campaign)

    skipped_payload = revised.model_dump(mode="json")
    skipped_payload.update(
        {
            "revision": 4,
            "previous_digest": revised.digest(),
            "updated_at": revised.updated_at + timedelta(minutes=1),
        }
    )
    with pytest.raises(EvidenceError, match="exactly one"):
        store.add_finding(FindingRecord.model_validate(skipped_payload))


def test_supported_finding_without_evidence_is_invalid() -> None:
    with pytest.raises(ValidationError, match="require evidence"):
        FindingRecord.create(
            campaign_id="example-lab-campaign",
            target="api.example.test",
            playbook_id="http-response-surface-map",
            title="Unsupported claim",
            summary="This should remain a candidate.",
            status=FindingStatus.SUPPORTED,
        )
