from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..models import stable_id
from .errors import AdvisoryNotFoundError, IntelligenceLimitError, IntelligenceStoreError
from .models import (
    CveRecordState,
    IntelligenceSource,
    IntelligenceStatus,
    IntelligenceSyncReport,
    NormalizedAdvisory,
    RawSnapshotProvenance,
    SnapshotKind,
    SourceAttribution,
    SourceState,
    SourceStatus,
    UpsertState,
)
from .sources import ParsedSourceRecord


@dataclass(frozen=True, slots=True)
class SourceRecordState:
    source_record_id: str
    raw_record_sha256: str
    advisory_id: str
    tombstoned: bool


class IntelligenceStore:
    """SQLite index plus immutable content-addressed public-source payloads."""

    def __init__(
        self,
        database: Path,
        snapshots_dir: Path,
        *,
        max_snapshot_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.database = database.resolve()
        self.snapshots_dir = snapshots_dir.resolve()
        self.max_snapshot_bytes = max_snapshot_bytes

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS intelligence_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    source_record_id TEXT,
                    content_sha256 TEXT NOT NULL,
                    byte_length INTEGER NOT NULL,
                    storage_path TEXT NOT NULL,
                    retrieved_at TEXT NOT NULL,
                    provenance_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_intelligence_snapshots_source
                    ON intelligence_snapshots(source, retrieved_at DESC);
                CREATE TABLE IF NOT EXISTS intelligence_advisories (
                    advisory_id TEXT PRIMARY KEY,
                    known_exploited INTEGER NOT NULL,
                    withdrawn INTEGER NOT NULL,
                    cve_rejected INTEGER NOT NULL DEFAULT 0,
                    published_at TEXT,
                    modified_at TEXT,
                    record_json TEXT NOT NULL,
                    record_digest TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_intelligence_advisories_sort
                    ON intelligence_advisories(known_exploited DESC, modified_at DESC, advisory_id);
                CREATE TABLE IF NOT EXISTS intelligence_identifiers (
                    identifier_key TEXT PRIMARY KEY,
                    identifier TEXT NOT NULL,
                    advisory_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_intelligence_identifiers_advisory
                    ON intelligence_identifiers(advisory_id);
                CREATE TABLE IF NOT EXISTS intelligence_source_records (
                    source TEXT NOT NULL,
                    source_record_id TEXT NOT NULL,
                    advisory_id TEXT NOT NULL,
                    raw_record_sha256 TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    tombstoned INTEGER NOT NULL DEFAULT 0,
                    tombstoned_at TEXT,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    PRIMARY KEY(source, source_record_id)
                );
                CREATE INDEX IF NOT EXISTS idx_intelligence_source_records_advisory
                    ON intelligence_source_records(advisory_id, source, tombstoned);
                CREATE TABLE IF NOT EXISTS intelligence_advisory_sources (
                    advisory_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tombstoned INTEGER NOT NULL,
                    PRIMARY KEY(advisory_id, source)
                );
                CREATE INDEX IF NOT EXISTS idx_intelligence_advisory_sources_source
                    ON intelligence_advisory_sources(source, tombstoned, advisory_id);
                CREATE TABLE IF NOT EXISTS intelligence_advisory_ecosystems (
                    advisory_id TEXT NOT NULL,
                    ecosystem_key TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    PRIMARY KEY(advisory_id, ecosystem_key)
                );
                CREATE INDEX IF NOT EXISTS idx_intelligence_ecosystems_key
                    ON intelligence_advisory_ecosystems(ecosystem_key, advisory_id);
                CREATE TABLE IF NOT EXISTS intelligence_source_state (
                    source TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS intelligence_sync_runs (
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    request_json TEXT NOT NULL,
                    report_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_intelligence_sync_runs_started
                    ON intelligence_sync_runs(started_at DESC, run_id DESC);
                """
            )
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(intelligence_advisories)")
            }
            if "cve_rejected" not in columns:
                connection.execute(
                    "ALTER TABLE intelligence_advisories ADD COLUMN cve_rejected INTEGER NOT NULL DEFAULT 0"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_intelligence_advisories_cve_rejected "
                "ON intelligence_advisories(cve_rejected, advisory_id)"
            )

    def save_snapshot(
        self,
        content: bytes,
        *,
        source: IntelligenceSource,
        kind: SnapshotKind,
        source_url: str,
        retrieved_at: datetime,
        media_type: str,
        attribution: SourceAttribution,
        source_record_id: str | None = None,
        http_status: int = 200,
        etag: str | None = None,
        last_modified: str | None = None,
        source_schema_version: str | None = None,
        source_metadata: dict | None = None,
    ) -> RawSnapshotProvenance:
        if len(content) > self.max_snapshot_bytes:
            raise IntelligenceLimitError(
                f"snapshot exceeds {self.max_snapshot_bytes} byte storage limit", source=source
            )
        digest = hashlib.sha256(content).hexdigest()
        relative = Path("sha256") / digest[:2] / digest
        snapshot_id = stable_id(
            "snapshot",
            {
                "source": source.value,
                "kind": kind.value,
                "source_url": source_url,
                "source_record_id": source_record_id,
                "content_sha256": digest,
            },
        )
        destination = self.snapshots_dir / relative
        _write_content_once(destination, content, digest)
        candidate = RawSnapshotProvenance(
            snapshot_id=snapshot_id,
            source=source,
            kind=kind,
            source_url=source_url,
            source_record_id=source_record_id,
            retrieved_at=retrieved_at,
            content_sha256=digest,
            byte_length=len(content),
            media_type=media_type,
            http_status=http_status,
            etag=etag,
            last_modified=last_modified,
            source_schema_version=source_schema_version,
            source_metadata=source_metadata or {},
            attribution=attribution,
            storage_path=str(relative),
        )
        payload = _model_json(candidate)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT provenance_json FROM intelligence_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            if existing:
                stored = RawSnapshotProvenance.model_validate_json(existing["provenance_json"])
                if stored.content_sha256 != digest or stored.byte_length != len(content):
                    raise IntelligenceStoreError("snapshot identity collision")
                return stored
            connection.execute(
                """
                INSERT INTO intelligence_snapshots(
                    snapshot_id, source, kind, source_url, source_record_id,
                    content_sha256, byte_length, storage_path, retrieved_at, provenance_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    source.value,
                    kind.value,
                    source_url,
                    source_record_id,
                    digest,
                    len(content),
                    str(relative),
                    retrieved_at.isoformat(),
                    payload,
                ),
            )
        return candidate

    def get_snapshot(self, snapshot_id: str) -> RawSnapshotProvenance:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT provenance_json FROM intelligence_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
        if not row:
            raise IntelligenceStoreError(f"unknown intelligence snapshot: {snapshot_id}")
        return RawSnapshotProvenance.model_validate_json(row["provenance_json"])

    def read_snapshot(self, snapshot_id: str) -> bytes:
        provenance = self.get_snapshot(snapshot_id)
        path = (self.snapshots_dir / provenance.storage_path).resolve()
        if path != self.snapshots_dir and self.snapshots_dir not in path.parents:
            raise IntelligenceStoreError("snapshot path escapes storage root")
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise IntelligenceStoreError("snapshot content is unavailable") from exc
        if len(content) != provenance.byte_length:
            raise IntelligenceStoreError("snapshot byte length verification failed")
        if hashlib.sha256(content).hexdigest() != provenance.content_sha256:
            raise IntelligenceStoreError("snapshot digest verification failed")
        return content

    def verify_snapshot(self, snapshot_id: str) -> bool:
        self.read_snapshot(snapshot_id)
        return True

    def snapshot_provenance_for_paths(
        self,
        storage_paths: Iterable[str],
    ) -> dict[str, list[RawSnapshotProvenance]]:
        paths = sorted(set(storage_paths))
        if len(paths) > 10_000:
            raise IntelligenceLimitError("snapshot provenance lookup exceeds 10000 paths")
        result: dict[str, list[RawSnapshotProvenance]] = {path: [] for path in paths}
        with self._connect() as connection:
            for offset in range(0, len(paths), 500):
                chunk = paths[offset : offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows = connection.execute(
                    f"""
                    SELECT storage_path, provenance_json FROM intelligence_snapshots
                    WHERE storage_path IN ({placeholders})
                    ORDER BY storage_path, snapshot_id
                    """,
                    chunk,
                ).fetchall()
                for row in rows:
                    result[row["storage_path"]].append(
                        RawSnapshotProvenance.model_validate_json(row["provenance_json"])
                    )
        return result

    def upsert_source_record(
        self, record: ParsedSourceRecord, *, snapshot_id: str, seen_at: datetime
    ) -> UpsertState:
        if record.source not in record.advisory.sources:
            raise IntelligenceStoreError("source record advisory is missing its source")
        if len(record.raw_record_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in record.raw_record_sha256
        ):
            raise IntelligenceStoreError("source record digest is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_snapshot(connection, snapshot_id, record.source)
            previous = connection.execute(
                """
                SELECT advisory_id, raw_record_sha256, tombstoned
                FROM intelligence_source_records
                WHERE source = ? AND source_record_id = ?
                """,
                (record.source.value, record.source_record_id),
            ).fetchone()
            linked = self._linked_advisory_ids(connection, record.advisory.identifiers)
            if previous:
                linked.add(previous["advisory_id"])
            target_id = (
                previous["advisory_id"]
                if previous
                else _choose_advisory_id(linked, record.advisory.advisory_id)
            )
            for other_id in sorted(linked - {target_id}):
                self._merge_identity(connection, target_id=target_id, other_id=other_id)
            for identifier in record.advisory.identifiers:
                connection.execute(
                    """
                    INSERT INTO intelligence_identifiers(identifier_key, identifier, advisory_id)
                    VALUES (?, ?, ?)
                    ON CONFLICT(identifier_key) DO UPDATE SET advisory_id = excluded.advisory_id
                    """,
                    (_identifier_key(identifier), identifier, target_id),
                )
            payload = _model_json(record.advisory)
            if previous:
                unchanged = previous["raw_record_sha256"] == record.raw_record_sha256 and not bool(
                    previous["tombstoned"]
                )
                connection.execute(
                    """
                    UPDATE intelligence_source_records SET
                        advisory_id = ?, snapshot_id = ?, last_seen_at = ?,
                        tombstoned = 0, tombstoned_at = NULL,
                        raw_record_sha256 = ?, record_json = ?
                    WHERE source = ? AND source_record_id = ?
                    """,
                    (
                        target_id,
                        snapshot_id,
                        seen_at.isoformat(),
                        record.raw_record_sha256,
                        payload,
                        record.source.value,
                        record.source_record_id,
                    ),
                )
                state = UpsertState.UNCHANGED if unchanged else UpsertState.UPDATED
            else:
                connection.execute(
                    """
                    INSERT INTO intelligence_source_records(
                        source, source_record_id, advisory_id, raw_record_sha256,
                        snapshot_id, record_json, tombstoned, tombstoned_at,
                        first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)
                    """,
                    (
                        record.source.value,
                        record.source_record_id,
                        target_id,
                        record.raw_record_sha256,
                        snapshot_id,
                        payload,
                        seen_at.isoformat(),
                        seen_at.isoformat(),
                    ),
                )
                state = UpsertState.INSERTED
            if state != UpsertState.UNCHANGED or linked - {target_id}:
                self._rebuild_advisory(connection, target_id, updated_at=seen_at)
            return state

    def tombstone_source_record(
        self,
        source: IntelligenceSource,
        source_record_id: str,
        *,
        snapshot_id: str,
        tombstoned_at: datetime,
    ) -> UpsertState:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_snapshot(connection, snapshot_id, source)
            row = connection.execute(
                """
                SELECT advisory_id, tombstoned FROM intelligence_source_records
                WHERE source = ? AND source_record_id = ?
                """,
                (source.value, source_record_id),
            ).fetchone()
            if not row or bool(row["tombstoned"]):
                return UpsertState.UNCHANGED
            connection.execute(
                """
                UPDATE intelligence_source_records SET
                    tombstoned = 1, tombstoned_at = ?, snapshot_id = ?, last_seen_at = ?
                WHERE source = ? AND source_record_id = ?
                """,
                (
                    tombstoned_at.isoformat(),
                    snapshot_id,
                    tombstoned_at.isoformat(),
                    source.value,
                    source_record_id,
                ),
            )
            self._rebuild_advisory(connection, row["advisory_id"], updated_at=tombstoned_at)
            return UpsertState.TOMBSTONED

    def source_record_states(self, source: IntelligenceSource) -> dict[str, SourceRecordState]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT source_record_id, advisory_id, raw_record_sha256, tombstoned
                FROM intelligence_source_records WHERE source = ?
                """,
                (source.value,),
            ).fetchall()
        return {
            row["source_record_id"]: SourceRecordState(
                source_record_id=row["source_record_id"],
                raw_record_sha256=row["raw_record_sha256"],
                advisory_id=row["advisory_id"],
                tombstoned=bool(row["tombstoned"]),
            )
            for row in rows
        }

    def get_advisory(self, identifier: str) -> NormalizedAdvisory:
        key = _identifier_key(identifier)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT a.record_json FROM intelligence_advisories AS a
                LEFT JOIN intelligence_identifiers AS i ON i.advisory_id = a.advisory_id
                WHERE a.advisory_id = ? OR i.identifier_key = ?
                LIMIT 1
                """,
                (identifier, key),
            ).fetchone()
        if not row:
            raise AdvisoryNotFoundError(f"unknown advisory: {identifier}")
        return NormalizedAdvisory.model_validate_json(row["record_json"])

    def list_advisories(
        self,
        *,
        sources: Iterable[IntelligenceSource] | None = None,
        ecosystems: Iterable[str] | None = None,
        known_exploited: bool | None = None,
        withdrawn: bool | None = None,
        rejected: bool | None = None,
        limit: int = 100,
    ) -> list[NormalizedAdvisory]:
        _validate_limit(limit)
        query = "SELECT a.record_json FROM intelligence_advisories AS a WHERE 1 = 1"
        parameters: list[str | int] = []
        source_values = sorted({source.value for source in sources or []})
        ecosystem_values = sorted({_identifier_key(value) for value in ecosystems or []})
        if source_values:
            placeholders = ",".join("?" for _ in source_values)
            query += (
                " AND EXISTS (SELECT 1 FROM intelligence_advisory_sources s "
                f"WHERE s.advisory_id = a.advisory_id AND s.source IN ({placeholders}))"
            )
            parameters.extend(source_values)
        if ecosystem_values:
            placeholders = ",".join("?" for _ in ecosystem_values)
            query += (
                " AND EXISTS (SELECT 1 FROM intelligence_advisory_ecosystems e "
                f"WHERE e.advisory_id = a.advisory_id AND e.ecosystem_key IN ({placeholders}))"
            )
            parameters.extend(ecosystem_values)
        if known_exploited is not None:
            query += " AND a.known_exploited = ?"
            parameters.append(int(known_exploited))
        if withdrawn is not None:
            query += " AND a.withdrawn = ?"
            parameters.append(int(withdrawn))
        if rejected is True:
            query += " AND a.cve_rejected = 1"
        elif rejected is False:
            query += (
                " AND NOT (a.cve_rejected = 1 AND NOT EXISTS ("
                "SELECT 1 FROM intelligence_advisory_sources active_source "
                "WHERE active_source.advisory_id = a.advisory_id "
                "AND active_source.tombstoned = 0 "
                "AND active_source.source IN ('cisa-kev', 'osv')))"
            )
        query += (
            " ORDER BY a.known_exploited DESC, "
            "COALESCE(a.modified_at, a.published_at) DESC, a.advisory_id LIMIT ?"
        )
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [NormalizedAdvisory.model_validate_json(row["record_json"]) for row in rows]

    def get_source_state(self, source: IntelligenceSource) -> SourceState | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state_json FROM intelligence_source_state WHERE source = ?",
                (source.value,),
            ).fetchone()
        return SourceState.model_validate_json(row["state_json"]) if row else None

    def set_source_state(self, state: SourceState) -> None:
        payload = _model_json(state)
        updated_at = state.last_attempt_at or state.last_success_at
        if updated_at is None:
            raise IntelligenceStoreError("source state requires an attempt or success time")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO intelligence_source_state(source, state_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    state_json = excluded.state_json,
                    updated_at = excluded.updated_at
                """,
                (state.source.value, payload, updated_at.isoformat()),
            )

    def begin_sync(self, run_id: str, *, started_at: datetime, request: dict) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO intelligence_sync_runs(
                    run_id, status, started_at, finished_at, request_json, report_json
                ) VALUES (?, ?, ?, NULL, ?, NULL)
                """,
                (run_id, "running", started_at.isoformat(), _json(request)),
            )

    def finish_sync(self, report: IntelligenceSyncReport) -> None:
        with self._connect() as connection:
            changed = connection.execute(
                """
                UPDATE intelligence_sync_runs SET
                    status = ?, finished_at = ?, report_json = ?
                WHERE run_id = ?
                """,
                (
                    report.status.value,
                    report.finished_at.isoformat(),
                    _model_json(report),
                    report.run_id,
                ),
            ).rowcount
        if changed != 1:
            raise IntelligenceStoreError(f"unknown intelligence sync run: {report.run_id}")

    def status(self) -> IntelligenceStatus:
        if not self.database.exists():
            return IntelligenceStatus(initialized=False)
        try:
            with self._connect() as connection:
                tables = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                required = {
                    "intelligence_snapshots",
                    "intelligence_advisories",
                    "intelligence_identifiers",
                    "intelligence_source_records",
                    "intelligence_advisory_sources",
                    "intelligence_advisory_ecosystems",
                    "intelligence_source_state",
                    "intelligence_sync_runs",
                }
                if not required.issubset(tables):
                    return IntelligenceStatus(initialized=False)
                advisory_row = connection.execute(
                    """
                    SELECT COUNT(*) AS total, SUM(withdrawn) AS withdrawn,
                           SUM(cve_rejected) AS cve_rejected
                    FROM intelligence_advisories
                    """
                ).fetchone()
                snapshot_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM intelligence_snapshots"
                ).fetchone()["count"]
                sync_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM intelligence_sync_runs"
                ).fetchone()["count"]
                source_rows = connection.execute(
                    """
                    SELECT source,
                           SUM(CASE WHEN tombstoned = 0 THEN 1 ELSE 0 END) AS active,
                           SUM(CASE WHEN tombstoned = 1 THEN 1 ELSE 0 END) AS tombstoned
                    FROM intelligence_source_records GROUP BY source
                    """
                ).fetchall()
                states = {
                    row["source"]: SourceState.model_validate_json(row["state_json"])
                    for row in connection.execute(
                        "SELECT source, state_json FROM intelligence_source_state"
                    ).fetchall()
                }
                latest = connection.execute(
                    """
                    SELECT report_json FROM intelligence_sync_runs
                    WHERE report_json IS NOT NULL ORDER BY started_at DESC, run_id DESC LIMIT 1
                    """
                ).fetchone()
        except sqlite3.Error as exc:
            raise IntelligenceStoreError("intelligence status query failed") from exc
        counts = {
            row["source"]: (int(row["active"] or 0), int(row["tombstoned"] or 0)) for row in source_rows
        }
        source_statuses = []
        for source in IntelligenceSource:
            active, tombstoned = counts.get(source.value, (0, 0))
            source_statuses.append(
                SourceStatus(
                    source=source,
                    state=states.get(source.value),
                    active_records=active,
                    tombstoned_records=tombstoned,
                )
            )
        return IntelligenceStatus(
            initialized=True,
            advisory_count=int(advisory_row["total"] or 0),
            withdrawn_count=int(advisory_row["withdrawn"] or 0),
            rejected_cve_count=int(advisory_row["cve_rejected"] or 0),
            snapshot_count=int(snapshot_count),
            sync_run_count=int(sync_count),
            sources=source_statuses,
            latest_sync=(
                IntelligenceSyncReport.model_validate_json(latest["report_json"]) if latest else None
            ),
        )

    def snapshot_count(self) -> int:
        with self._connect() as connection:
            return int(
                connection.execute("SELECT COUNT(*) AS count FROM intelligence_snapshots").fetchone()["count"]
            )

    @staticmethod
    def _assert_snapshot(
        connection: sqlite3.Connection, snapshot_id: str, source: IntelligenceSource
    ) -> None:
        row = connection.execute(
            "SELECT source FROM intelligence_snapshots WHERE snapshot_id = ?", (snapshot_id,)
        ).fetchone()
        if not row:
            raise IntelligenceStoreError(f"unknown intelligence snapshot: {snapshot_id}")
        if row["source"] != source.value:
            raise IntelligenceStoreError("source record and snapshot sources differ")

    @staticmethod
    def _linked_advisory_ids(connection: sqlite3.Connection, identifiers: list[str]) -> set[str]:
        result: set[str] = set()
        keys = [_identifier_key(identifier) for identifier in identifiers]
        for offset in range(0, len(keys), 500):
            chunk = keys[offset : offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            rows = connection.execute(
                f"SELECT advisory_id FROM intelligence_identifiers WHERE identifier_key IN ({placeholders})",
                chunk,
            ).fetchall()
            result.update(row["advisory_id"] for row in rows)
        return result

    @staticmethod
    def _merge_identity(connection: sqlite3.Connection, *, target_id: str, other_id: str) -> None:
        if target_id == other_id:
            return
        connection.execute(
            "UPDATE intelligence_source_records SET advisory_id = ? WHERE advisory_id = ?",
            (target_id, other_id),
        )
        connection.execute(
            "UPDATE intelligence_identifiers SET advisory_id = ? WHERE advisory_id = ?",
            (target_id, other_id),
        )
        connection.execute("DELETE FROM intelligence_advisory_sources WHERE advisory_id = ?", (other_id,))
        connection.execute("DELETE FROM intelligence_advisory_ecosystems WHERE advisory_id = ?", (other_id,))
        connection.execute("DELETE FROM intelligence_advisories WHERE advisory_id = ?", (other_id,))

    @staticmethod
    def _rebuild_advisory(connection: sqlite3.Connection, advisory_id: str, *, updated_at: datetime) -> None:
        rows = connection.execute(
            """
            SELECT source, source_record_id, record_json, tombstoned
            FROM intelligence_source_records
            WHERE advisory_id = ? ORDER BY source, source_record_id
            """,
            (advisory_id,),
        ).fetchall()
        if not rows:
            raise IntelligenceStoreError("cannot rebuild advisory without source records")
        aggregate = _merge_source_records(advisory_id, rows)
        payload = _model_json(aggregate)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO intelligence_advisories(
                advisory_id, known_exploited, withdrawn, cve_rejected,
                published_at, modified_at, record_json, record_digest, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(advisory_id) DO UPDATE SET
                known_exploited = excluded.known_exploited,
                withdrawn = excluded.withdrawn,
                cve_rejected = excluded.cve_rejected,
                published_at = excluded.published_at,
                modified_at = excluded.modified_at,
                record_json = excluded.record_json,
                record_digest = excluded.record_digest,
                updated_at = excluded.updated_at
            """,
            (
                advisory_id,
                int(aggregate.known_exploited),
                int(aggregate.withdrawn_at is not None),
                int(aggregate.cve_record_state == CveRecordState.REJECTED),
                aggregate.published_at.isoformat() if aggregate.published_at else None,
                aggregate.modified_at.isoformat() if aggregate.modified_at else None,
                payload,
                digest,
                updated_at.isoformat(),
            ),
        )
        connection.execute("DELETE FROM intelligence_advisory_sources WHERE advisory_id = ?", (advisory_id,))
        for source in aggregate.sources:
            connection.execute(
                """
                INSERT INTO intelligence_advisory_sources(advisory_id, source, tombstoned)
                VALUES (?, ?, ?)
                """,
                (advisory_id, source.value, int(source in aggregate.tombstoned_sources)),
            )
        connection.execute(
            "DELETE FROM intelligence_advisory_ecosystems WHERE advisory_id = ?", (advisory_id,)
        )
        ecosystems = sorted(
            {item.ecosystem for item in aggregate.affected if item.ecosystem}, key=str.casefold
        )
        for ecosystem in ecosystems:
            connection.execute(
                """
                INSERT INTO intelligence_advisory_ecosystems(
                    advisory_id, ecosystem_key, ecosystem
                ) VALUES (?, ?, ?)
                """,
                (advisory_id, _identifier_key(ecosystem), ecosystem),
            )

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA foreign_keys = ON")
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


def _merge_source_records(advisory_id: str, rows: list[sqlite3.Row]) -> NormalizedAdvisory:
    parsed = [
        (
            IntelligenceSource(row["source"]),
            row["source_record_id"],
            NormalizedAdvisory.model_validate_json(row["record_json"]),
            bool(row["tombstoned"]),
        )
        for row in rows
    ]
    active = [item for item in parsed if not item[3]]
    semantic = active or parsed
    preference = {
        IntelligenceSource.CVE_LIST_V5: 0,
        IntelligenceSource.OSV: 1,
        IntelligenceSource.CISA_KEV: 2,
        IntelligenceSource.EPSS: 3,
    }
    semantic.sort(
        key=lambda item: (
            4
            if item[0] == IntelligenceSource.CVE_LIST_V5
            and item[2].cve_record_state == CveRecordState.REJECTED
            else preference[item[0]],
            item[1].casefold(),
        )
    )
    sources = sorted({item[0] for item in parsed}, key=lambda item: item.value)
    tombstoned_sources = sorted(
        {source for source in sources if all(item[3] for item in parsed if item[0] == source)},
        key=lambda item: item.value,
    )
    identifiers = _unique_strings(
        [identifier for _, _, record, _ in parsed for identifier in record.identifiers]
    )
    if advisory_id.casefold() not in {item.casefold() for item in identifiers}:
        identifiers.append(advisory_id)
    related = _unique_strings(
        [identifier for _, _, record, _ in parsed for identifier in record.related_identifiers]
    )
    links = _unique_models(
        [link for _, _, record, _ in parsed for link in record.identifier_links],
        key=lambda item: (
            item.left.casefold(),
            item.right.casefold(),
            item.relation.value,
            item.source.value,
        ),
    )
    affected = _unique_models(
        [item for _, _, record, _ in semantic for item in record.affected],
        key=lambda item: _model_json(item),
    )
    references = _unique_models(
        [item for _, _, record, _ in semantic for item in record.references],
        key=lambda item: (item.url, item.type.value, item.source.value),
    )
    severity = _unique_models(
        [item for _, _, record, _ in semantic for item in record.severity],
        key=lambda item: _model_json(item),
    )
    provenance = _unique_models(
        [item for _, _, record, _ in parsed for item in record.provenance],
        key=lambda item: item.snapshot_id,
    )
    published = [record.published_at for _, _, record, _ in semantic if record.published_at]
    modified = [record.modified_at for _, _, record, _ in semantic if record.modified_at]
    withdrawn = [record.withdrawn_at for _, _, record, _ in semantic if record.withdrawn_at]
    metadata: dict[str, object] = {}
    for source, _, record, _ in parsed:
        value = record.source_metadata.get(source.value, {})
        previous = metadata.get(source.value)
        if previous is None:
            metadata[source.value] = value
        elif previous != value:
            values = previous if isinstance(previous, list) else [previous]
            if value not in values:
                values.append(value)
            metadata[source.value] = values
    return NormalizedAdvisory(
        advisory_id=advisory_id,
        identifiers=identifiers,
        related_identifiers=related,
        identifier_links=links,
        sources=sources,
        tombstoned_sources=tombstoned_sources,
        cve_record_state=_first_value(semantic, "cve_record_state"),
        title=_first_text(semantic, "title"),
        summary=_first_text(semantic, "summary"),
        details=_first_text(semantic, "details"),
        published_at=min(published) if published else None,
        modified_at=max(modified) if modified else None,
        withdrawn_at=max(withdrawn) if withdrawn else None,
        known_exploited=any(record.known_exploited for _, _, record, _ in active),
        cisa_due_date=_first_value(semantic, "cisa_due_date"),
        required_action=_first_text(semantic, "required_action"),
        known_ransomware_use=_first_text(semantic, "known_ransomware_use"),
        cwes=_unique_strings([cwe for _, _, record, _ in semantic for cwe in record.cwes]),
        affected=affected,
        references=references,
        severity=severity,
        provenance=provenance,
        source_metadata=metadata,
    )


def _first_text(records, field: str) -> str | None:
    return next(
        (
            value
            for _, _, record, _ in records
            if isinstance((value := getattr(record, field)), str) and value
        ),
        None,
    )


def _first_value(records, field: str):
    return next((value for _, _, record, _ in records if (value := getattr(record, field))), None)


def _choose_advisory_id(linked: set[str], proposed: str) -> str:
    if not linked:
        return proposed
    if proposed in linked:
        return proposed
    return min(linked, key=str.casefold)


def _identifier_key(value: str) -> str:
    normalized = value.strip().casefold()
    if not normalized:
        raise ValueError("identifier cannot be empty")
    return normalized


def _validate_limit(limit: int) -> None:
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")


def _model_json(value) -> str:
    return json.dumps(value.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _unique_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value.casefold() in seen:
            continue
        seen.add(value.casefold())
        result.append(value)
    return result


def _unique_models(items, *, key):
    result = []
    seen = set()
    for item in items:
        identity = key(item)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(item)
    return result


def _write_content_once(destination: Path, content: bytes, expected_digest: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        pass
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            destination.unlink(missing_ok=True)
        raise
    try:
        stored = destination.read_bytes()
    except OSError as exc:
        raise IntelligenceStoreError("content-addressed snapshot write failed") from exc
    if hashlib.sha256(stored).hexdigest() != expected_digest:
        raise IntelligenceStoreError("content-addressed snapshot digest verification failed")
