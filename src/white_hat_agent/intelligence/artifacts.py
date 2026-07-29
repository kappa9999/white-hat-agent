from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any


def _snapshot_ids(value: Any) -> set[str]:
    """Extract only model-owned snapshot references from generated report shapes."""

    from .models import (
        IntelligenceStatus,
        IntelligenceSyncReport,
        NormalizedAdvisory,
        RankedAdvisory,
    )

    found: set[str] = set()
    if isinstance(value, dict):
        if {"run_id", "requested_sources", "results"}.issubset(value):
            found.update(_sync_snapshot_ids(IntelligenceSyncReport.model_validate(value)))
        elif {"initialized", "sources"}.issubset(value):
            status = IntelligenceStatus.model_validate(value)
            for source in status.sources:
                if source.state and source.state.last_snapshot_id:
                    found.add(source.state.last_snapshot_id)
            if status.latest_sync:
                found.update(_sync_snapshot_ids(status.latest_sync))
        elif {"advisory_id", "identifiers", "sources", "provenance"}.issubset(value):
            advisory = NormalizedAdvisory.model_validate(value)
            found.update(item.snapshot_id for item in advisory.provenance)
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, dict) and {"advisory", "priority"}.issubset(child):
                ranked = RankedAdvisory.model_validate(child)
                found.update(item.snapshot_id for item in ranked.advisory.provenance)
    return found


def _sync_snapshot_ids(report) -> set[str]:
    trusted_metadata_keys = {
        "feed_snapshot_id",
        "index_prefix_snapshot_id",
        "selection_manifest_id",
    }
    return {
        value
        for result in report.results
        for key, value in result.metadata.items()
        if key in trusted_metadata_keys and isinstance(value, str)
    }


def _load_before(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def stage_run_artifact(
    workspace_root: Path,
    reports_dir: Path,
    before_manifest: Path,
    output_dir: Path,
) -> Path:
    """Copy snapshots referenced by, or first observed during, one sync into a verified bundle."""

    # Workspace imports IntelligenceStore, so keep this import local to avoid a
    # package-initialization cycle when callers import white_hat_agent.workspace.
    from ..workspace import Workspace

    workspace = Workspace.load(workspace_root)
    store = workspace.intelligence
    store.initialize()
    snapshots_root = store.snapshots_dir
    referenced_ids: set[str] = set()
    for report in sorted(reports_dir.glob("*.json")):
        referenced_ids.update(_snapshot_ids(json.loads(report.read_text(encoding="utf-8"))))

    selected_paths: set[str] = set()
    for snapshot_id in sorted(referenced_ids):
        provenance = store.get_snapshot(snapshot_id)
        store.verify_snapshot(snapshot_id)
        selected_paths.add(provenance.storage_path)

    before = _load_before(before_manifest)
    current = {
        path.relative_to(snapshots_root).as_posix() for path in snapshots_root.rglob("*") if path.is_file()
    }
    selected_paths.update(current - before)
    provenance_by_path = store.snapshot_provenance_for_paths(selected_paths)

    output_dir.mkdir(parents=True, exist_ok=True)
    staged: list[dict[str, Any]] = []
    for relative_name in sorted(selected_paths):
        relative = Path(relative_name)
        source = (snapshots_root / relative).resolve()
        if source != snapshots_root and snapshots_root not in source.parents:
            raise ValueError(f"snapshot path escapes source root: {relative_name}")
        if not source.is_file():
            raise FileNotFoundError(f"snapshot file is unavailable: {relative_name}")
        destination = output_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        content = destination.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest != destination.name:
            raise ValueError(f"content-addressed snapshot failed verification: {relative_name}")
        staged.append(
            {
                "storage_path": relative.as_posix(),
                "content_sha256": digest,
                "byte_length": len(content),
                "provenance": [
                    item.model_dump(mode="json", exclude_none=True)
                    for item in provenance_by_path.get(relative.as_posix(), [])
                ],
            }
        )

    manifest_path = output_dir / "manifest.json"
    payload = (
        json.dumps(
            {
                "schema_version": "1.0",
                "referenced_snapshot_ids": sorted(referenced_ids),
                "snapshot_count": len(staged),
                "snapshots": staged,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    _atomic_write(manifest_path, payload)
    return manifest_path


def _atomic_write(path: Path, payload: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise
