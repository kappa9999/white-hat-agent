from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .models import EvidenceDescriptor, EvidenceRecord, FindingRecord


class EvidenceError(RuntimeError):
    """Evidence identity, storage, or finding invariant failed."""


class EvidenceStore:
    def __init__(self, database: Path, artifacts_dir: Path, *, max_import_bytes: int = 104_857_600) -> None:
        self.database = database.resolve()
        self.artifacts_dir = artifacts_dir.resolve()
        self.max_import_bytes = max_import_bytes

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_records (
                    evidence_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    task_id TEXT,
                    content_sha256 TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    registered_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_campaign
                    ON evidence_records(campaign_id, task_id, registered_at);
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    task_id TEXT,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_digest TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_campaign
                    ON findings(campaign_id, status, severity, updated_at);
                CREATE TABLE IF NOT EXISTS finding_revisions (
                    finding_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    record_digest TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    PRIMARY KEY(finding_id, revision)
                );
                """
            )

    def import_file(
        self,
        source: Path,
        descriptor: EvidenceDescriptor,
        *,
        media_type: str = "application/octet-stream",
    ) -> EvidenceRecord:
        if source.is_symlink():
            raise EvidenceError("evidence source must be a regular non-symlink file")
        source = source.resolve(strict=True)
        if not source.is_file():
            raise EvidenceError("evidence source must be a regular non-symlink file")
        byte_length = source.stat().st_size
        if byte_length > self.max_import_bytes:
            raise EvidenceError(
                f"evidence exceeds import limit: {byte_length} > {self.max_import_bytes} bytes"
            )
        digest = _hash_file(source)
        relative = Path("sha256") / digest[:2] / digest
        destination = self.artifacts_dir / relative
        if not destination.exists():
            _atomic_copy(source, destination)
        if _hash_file(destination) != digest:
            raise EvidenceError("content-addressed evidence copy failed digest verification")
        record = EvidenceRecord.create(
            descriptor=descriptor,
            content_sha256=digest,
            byte_length=byte_length,
            media_type=media_type,
            storage_path=str(relative),
        )
        self._register(record)
        return record

    def register_external(
        self,
        descriptor: EvidenceDescriptor,
        *,
        content_sha256: str,
        byte_length: int,
        media_type: str,
        external_uri: str,
    ) -> EvidenceRecord:
        record = EvidenceRecord.create(
            descriptor=descriptor,
            content_sha256=content_sha256,
            byte_length=byte_length,
            media_type=media_type,
            external_uri=external_uri,
        )
        self._register(record)
        return record

    def get_evidence(self, evidence_id: str) -> EvidenceRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM evidence_records WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        if not row:
            raise EvidenceError(f"unknown evidence: {evidence_id}")
        return EvidenceRecord.model_validate_json(row["record_json"])

    def list_evidence(
        self,
        *,
        campaign_id: str,
        task_id: str | None = None,
        limit: int = 100,
    ) -> list[EvidenceRecord]:
        _validate_limit(limit)
        query = "SELECT record_json FROM evidence_records WHERE campaign_id = ?"
        parameters: list[str | int] = [campaign_id]
        if task_id is not None:
            query += " AND task_id = ?"
            parameters.append(task_id)
        query += " ORDER BY registered_at, evidence_id LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [EvidenceRecord.model_validate_json(row["record_json"]) for row in rows]

    def add_finding(self, finding: FindingRecord) -> FindingRecord:
        for evidence_id in finding.evidence_ids:
            evidence = self.get_evidence(evidence_id)
            if evidence.descriptor.campaign_id != finding.campaign_id:
                raise EvidenceError(f"evidence {evidence_id} belongs to a different campaign")
            if finding.task_id and evidence.descriptor.task_id not in {None, finding.task_id}:
                raise EvidenceError(f"evidence {evidence_id} belongs to a different task")
        payload = json.dumps(finding.model_dump(mode="json"), sort_keys=True)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT record_json, record_digest FROM findings WHERE finding_id = ?",
                (finding.finding_id,),
            ).fetchone()
            if existing:
                if existing["record_digest"] == finding.digest():
                    connection.commit()
                    return finding
                previous = FindingRecord.model_validate_json(existing["record_json"])
                _assert_finding_revision(previous, finding)
                connection.execute(
                    """
                    UPDATE findings SET
                        status = ?, severity = ?, record_json = ?,
                        record_digest = ?, updated_at = ?
                    WHERE finding_id = ?
                    """,
                    (
                        finding.status.value,
                        finding.severity.value,
                        payload,
                        finding.digest(),
                        finding.updated_at.isoformat(),
                        finding.finding_id,
                    ),
                )
            else:
                if finding.revision != 1 or finding.previous_digest is not None:
                    raise EvidenceError("a new finding must start at revision 1")
                connection.execute(
                    """
                    INSERT INTO findings(
                        finding_id, campaign_id, task_id, status, severity,
                        record_json, record_digest, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.finding_id,
                        finding.campaign_id,
                        finding.task_id,
                        finding.status.value,
                        finding.severity.value,
                        payload,
                        finding.digest(),
                        finding.updated_at.isoformat(),
                    ),
                )
            connection.execute(
                """
                INSERT INTO finding_revisions(
                    finding_id, revision, record_json, record_digest, recorded_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    finding.revision,
                    payload,
                    finding.digest(),
                    finding.updated_at.isoformat(),
                ),
            )
        return finding

    def get_finding(self, finding_id: str) -> FindingRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
        if not row:
            raise EvidenceError(f"unknown finding: {finding_id}")
        return FindingRecord.model_validate_json(row["record_json"])

    def list_findings(self, *, campaign_id: str, limit: int = 100) -> list[FindingRecord]:
        _validate_limit(limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json FROM findings WHERE campaign_id = ? "
                "ORDER BY updated_at, finding_id LIMIT ?",
                (campaign_id, limit),
            ).fetchall()
        return [FindingRecord.model_validate_json(row["record_json"]) for row in rows]

    def finding_history(self, finding_id: str, *, limit: int = 100) -> list[FindingRecord]:
        _validate_limit(limit)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT record_json FROM finding_revisions
                WHERE finding_id = ? ORDER BY revision LIMIT ?
                """,
                (finding_id, limit),
            ).fetchall()
        if not rows:
            raise EvidenceError(f"unknown finding: {finding_id}")
        return [FindingRecord.model_validate_json(row["record_json"]) for row in rows]

    def assert_evidence_exists(self, evidence_ids: list[str], *, campaign_id: str) -> None:
        for evidence_id in evidence_ids:
            record = self.get_evidence(evidence_id)
            if record.descriptor.campaign_id != campaign_id:
                raise EvidenceError(f"evidence {evidence_id} belongs to a different campaign")

    def _register(self, record: EvidenceRecord) -> None:
        payload = json.dumps(record.model_dump(mode="json"), sort_keys=True)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT record_json FROM evidence_records WHERE evidence_id = ?",
                (record.evidence_id,),
            ).fetchone()
            if existing:
                if EvidenceRecord.model_validate_json(existing["record_json"]).digest() != record.digest():
                    raise EvidenceError("evidence id already exists with different metadata")
                return
            connection.execute(
                """
                INSERT INTO evidence_records(
                    evidence_id, campaign_id, task_id, content_sha256, record_json, registered_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.evidence_id,
                    record.descriptor.campaign_id,
                    record.descriptor.task_id,
                    record.content_sha256,
                    payload,
                    record.registered_at.isoformat(),
                ),
            )

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            if connection.in_transaction:
                connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with source.open("rb") as source_handle, os.fdopen(descriptor, "wb") as destination_handle:
            for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                destination_handle.write(chunk)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _assert_finding_revision(previous: FindingRecord, current: FindingRecord) -> None:
    if current.revision != previous.revision + 1:
        raise EvidenceError("finding revision must increase by exactly one")
    if current.previous_digest != previous.digest():
        raise EvidenceError("finding revision is not linked to the previous digest")
    immutable = ("campaign_id", "task_id", "target", "playbook_id", "title", "created_at")
    changed = [name for name in immutable if getattr(previous, name) != getattr(current, name)]
    if changed:
        raise EvidenceError(f"finding identity fields cannot change across revisions: {changed}")


def _validate_limit(limit: int) -> None:
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
