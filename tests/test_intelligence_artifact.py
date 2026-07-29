from __future__ import annotations

import json

from white_hat_agent.intelligence import (
    IntelligenceSource,
    NormalizedAdvisory,
    RankedAdvisory,
    SnapshotKind,
    SourceAttribution,
    rank_advisory,
    stage_run_artifact,
)
from white_hat_agent.models import utc_now
from white_hat_agent.workspace import Workspace


def test_stage_run_includes_referenced_and_new_snapshots(tmp_path) -> None:
    workspace = Workspace.initialize(tmp_path)
    store = workspace.intelligence
    attribution = SourceAttribution(
        publisher="Fixture",
        dataset="Synthetic",
        attribution="Synthetic test fixture",
        license_name="CC0-1.0",
    )
    referenced = store.save_snapshot(
        b"referenced",
        source=IntelligenceSource.CISA_KEV,
        kind=SnapshotKind.FULL_FEED,
        source_url=("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
        retrieved_at=utc_now(),
        media_type="application/json",
        attribution=attribution,
    )
    shared_content = store.save_snapshot(
        b"referenced",
        source=IntelligenceSource.OSV,
        kind=SnapshotKind.SOURCE_RECORD,
        source_url="https://api.osv.dev/v1/vulns/GHSA-shared-content",
        source_record_id="GHSA-shared-content",
        retrieved_at=utc_now(),
        media_type="application/json",
        attribution=attribution,
    )
    assert shared_content.storage_path == referenced.storage_path
    assert shared_content.snapshot_id != referenced.snapshot_id
    before = tmp_path / "before.txt"
    before.write_text(referenced.storage_path + "\n", encoding="utf-8")
    new_snapshot = store.save_snapshot(
        b"new",
        source=IntelligenceSource.OSV,
        kind=SnapshotKind.SOURCE_RECORD,
        source_url="https://api.osv.dev/v1/vulns/GHSA-fixture",
        source_record_id="GHSA-fixture",
        retrieved_at=utc_now(),
        media_type="application/json",
        attribution=attribution,
    )
    reports = tmp_path / "reports"
    reports.mkdir()
    advisory = NormalizedAdvisory(
        advisory_id="CVE-2026-4242",
        identifiers=["CVE-2026-4242"],
        sources=[IntelligenceSource.CISA_KEV],
        modified_at=utc_now(),
        provenance=[referenced],
        source_metadata={"cisa-kev": {"attacker_snapshot_id": "not-a-local-snapshot"}},
    )
    ranked = RankedAdvisory(advisory=advisory, priority=rank_advisory(advisory, as_of=utc_now()))
    (reports / "advisories.json").write_text(
        json.dumps([ranked.model_dump(mode="json")]),
        encoding="utf-8",
    )

    manifest_path = stage_run_artifact(tmp_path, reports, before, tmp_path / "staged")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["snapshot_count"] == 2
    assert manifest["referenced_snapshot_ids"] == [referenced.snapshot_id]
    staged_paths = {item["storage_path"] for item in manifest["snapshots"]}
    assert staged_paths == {referenced.storage_path, new_snapshot.storage_path}
    for relative in staged_paths:
        assert (manifest_path.parent / relative).is_file()
    provenance_ids = {
        item["snapshot_id"] for snapshot in manifest["snapshots"] for item in snapshot["provenance"]
    }
    assert provenance_ids == {
        referenced.snapshot_id,
        shared_content.snapshot_id,
        new_snapshot.snapshot_id,
    }


def test_stage_run_preserves_new_snapshot_when_sync_report_is_missing(tmp_path) -> None:
    workspace = Workspace.initialize(tmp_path)
    snapshot = workspace.intelligence.save_snapshot(
        b"written-before-sync-crash",
        source=IntelligenceSource.OSV,
        kind=SnapshotKind.SOURCE_RECORD,
        source_url="https://api.osv.dev/v1/vulns/GHSA-crash-fixture",
        source_record_id="GHSA-crash-fixture",
        retrieved_at=utc_now(),
        media_type="application/json",
        attribution=SourceAttribution(
            publisher="Fixture",
            dataset="Synthetic",
            attribution="Synthetic test fixture",
            license_name="CC0-1.0",
        ),
    )
    before = tmp_path / "before.txt"
    before.write_text("", encoding="utf-8")

    manifest_path = stage_run_artifact(
        tmp_path,
        tmp_path / "missing-reports",
        before,
        tmp_path / "staged",
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["referenced_snapshot_ids"] == []
    assert manifest["snapshot_count"] == 1
    assert manifest["snapshots"][0]["storage_path"] == snapshot.storage_path
    assert manifest["snapshots"][0]["provenance"][0]["snapshot_id"] == snapshot.snapshot_id
