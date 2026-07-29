from __future__ import annotations

import importlib.resources
import os
import shutil
import sqlite3
import sys
import tomllib
from pathlib import Path

from pydantic import Field

from .campaign.fleet import FleetStore
from .capabilities.catalog import CapabilityCatalog
from .evidence.store import EvidenceStore
from .knowledge.corpus import Corpus
from .models import StrictModel


class WorkspaceConfig(StrictModel):
    schema_version: str = "1.0"
    corpus_dir: str = "corpus/playbooks"
    capability_catalog: str = "capabilities/catalog.yaml"
    submissions_dir: str = ".whitehat/submissions"
    campaigns_dir: str = ".whitehat/campaigns"
    artifacts_dir: str = ".whitehat/artifacts"
    state_database: str = ".whitehat/state/whitehat.db"
    max_tool_response_bytes: int = Field(default=262144, ge=4096, le=16777216)
    max_evidence_import_bytes: int = Field(default=104857600, ge=1, le=10737418240)


class DoctorCheck(StrictModel):
    name: str
    ok: bool
    detail: str


class DoctorReport(StrictModel):
    workspace: str
    healthy: bool
    checks: list[DoctorCheck]


class Workspace:
    def __init__(self, root: Path, config: WorkspaceConfig) -> None:
        self.root = root.resolve()
        self.config = config

    @classmethod
    def initialize(cls, root: Path, *, copy_builtin_corpus: bool = True) -> Workspace:
        resolved = root.resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        config_path = resolved / "whitehat.toml"
        if not config_path.exists():
            config_path.write_text(_default_config(), encoding="utf-8")
        workspace = cls.load(resolved)
        for path in (
            workspace.submissions_dir,
            workspace.campaigns_dir,
            workspace.artifacts_dir,
            workspace.state_database.parent,
            workspace.corpus_dir,
            workspace.capability_catalog_path.parent,
        ):
            path.mkdir(parents=True, exist_ok=True)
        workspace.fleet.initialize()
        workspace.evidence.initialize()
        if copy_builtin_corpus:
            workspace._copy_builtin_corpus()
        workspace._copy_builtin_capabilities()
        return workspace

    @classmethod
    def load(cls, root: Path) -> Workspace:
        resolved = root.resolve()
        config_path = resolved / "whitehat.toml"
        if not config_path.is_file():
            raise FileNotFoundError(f"White Hat Agent workspace not initialized: {config_path}")
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
        config = WorkspaceConfig.model_validate(raw.get("whitehat", raw))
        workspace = cls(resolved, config)
        workspace._validate_paths()
        return workspace

    @classmethod
    def discover(cls, start: Path | None = None) -> Workspace:
        environment = os.environ.get("WHA_WORKSPACE")
        if environment:
            return cls.load(Path(environment))
        current = (start or Path.cwd()).resolve()
        for candidate in (current, *current.parents):
            if (candidate / "whitehat.toml").is_file():
                return cls.load(candidate)
        raise FileNotFoundError("no whitehat.toml found; run `wha init` or set WHA_WORKSPACE")

    @property
    def corpus_dir(self) -> Path:
        return self._resolve(self.config.corpus_dir)

    @property
    def submissions_dir(self) -> Path:
        return self._resolve(self.config.submissions_dir)

    @property
    def capability_catalog_path(self) -> Path:
        return self._resolve(self.config.capability_catalog)

    @property
    def capability_catalog(self) -> CapabilityCatalog:
        catalog = CapabilityCatalog(self.capability_catalog_path)
        report = catalog.load()
        if not report.valid:
            raise ValueError(f"invalid capability catalog: {report.issues}")
        return catalog

    @property
    def campaigns_dir(self) -> Path:
        return self._resolve(self.config.campaigns_dir)

    @property
    def artifacts_dir(self) -> Path:
        return self._resolve(self.config.artifacts_dir)

    @property
    def state_database(self) -> Path:
        return self._resolve(self.config.state_database)

    @property
    def corpus(self) -> Corpus:
        corpus = Corpus(self.corpus_dir)
        report = corpus.load()
        if not report.valid:
            raise ValueError(f"invalid playbook corpus: {report.issues}")
        return corpus

    @property
    def fleet(self) -> FleetStore:
        return FleetStore(self.state_database)

    @property
    def evidence(self) -> EvidenceStore:
        return EvidenceStore(
            self.state_database,
            self.artifacts_dir,
            max_import_bytes=self.config.max_evidence_import_bytes,
        )

    def doctor(self) -> DoctorReport:
        checks: list[DoctorCheck] = [
            DoctorCheck(
                name="python",
                ok=sys.version_info >= (3, 12),
                detail=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            ),
            DoctorCheck(
                name="configuration",
                ok=(self.root / "whitehat.toml").is_file(),
                detail=str(self.root / "whitehat.toml"),
            ),
        ]
        for name, path in (
            ("corpus", self.corpus_dir),
            ("capabilities", self.capability_catalog_path.parent),
            ("submissions", self.submissions_dir),
            ("campaigns", self.campaigns_dir),
            ("artifacts", self.artifacts_dir),
        ):
            checks.append(DoctorCheck(name=name, ok=path.is_dir(), detail=str(path)))
        corpus = Corpus(self.corpus_dir)
        corpus_report = corpus.load()
        checks.append(
            DoctorCheck(
                name="corpus-validation",
                ok=corpus_report.valid,
                detail=f"{corpus_report.playbook_count} playbooks; {len(corpus_report.issues)} issues",
            )
        )
        catalog = CapabilityCatalog(self.capability_catalog_path)
        catalog_report = catalog.load()
        checks.append(
            DoctorCheck(
                name="capability-catalog",
                ok=catalog_report.valid,
                detail=(
                    f"{catalog_report.capability_count} capabilities; {len(catalog_report.issues)} issues"
                ),
            )
        )
        if corpus_report.valid and catalog_report.valid:
            available = [item.capability_id for item in catalog.all()]
            gaps = catalog.gaps(corpus.all(), available)
            compatibility = catalog.validate_playbooks(corpus.all())
            checks.append(
                DoctorCheck(
                    name="corpus-capability-references",
                    ok=not gaps.unknown and compatibility.valid,
                    detail=(
                        "all capabilities are catalogued and correctly classified"
                        if not gaps.unknown and compatibility.valid
                        else f"unknown={gaps.unknown}; issues={compatibility.issues}"
                    ),
                )
            )
        state_ok, state_detail, tables = _inspect_database(self.state_database)
        fleet_tables = {"campaigns", "agents", "tasks", "task_results", "opportunities"}
        fleet_ok = state_ok and fleet_tables.issubset(tables)
        fleet_detail = (
            state_detail if fleet_ok else f"{state_detail}; missing={sorted(fleet_tables - tables)}"
        )
        checks.append(DoctorCheck(name="fleet-database", ok=fleet_ok, detail=fleet_detail))
        evidence_tables = {"evidence_records", "findings", "finding_revisions"}
        evidence_ok = state_ok and self.artifacts_dir.is_dir() and evidence_tables.issubset(tables)
        evidence_detail = (
            str(self.artifacts_dir)
            if evidence_ok
            else f"{state_detail}; missing={sorted(evidence_tables - tables)}"
        )
        checks.append(DoctorCheck(name="evidence-store", ok=evidence_ok, detail=evidence_detail))
        return DoctorReport(
            workspace=str(self.root),
            healthy=all(item.ok for item in checks),
            checks=checks,
        )

    def _resolve(self, relative: str) -> Path:
        candidate = (self.root / relative).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError(f"workspace path escapes root: {relative}")
        return candidate

    def _validate_paths(self) -> None:
        for value in (
            self.config.corpus_dir,
            self.config.capability_catalog,
            self.config.submissions_dir,
            self.config.campaigns_dir,
            self.config.artifacts_dir,
            self.config.state_database,
        ):
            self._resolve(value)

    def _copy_builtin_corpus(self) -> None:
        resource = importlib.resources.files("white_hat_agent").joinpath("builtin_corpus")
        with importlib.resources.as_file(resource) as source:
            for path in source.rglob("*.yaml"):
                relative = path.relative_to(source)
                destination = self.corpus_dir / relative
                if destination.exists():
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, destination)

    def _copy_builtin_capabilities(self) -> None:
        resource = importlib.resources.files("white_hat_agent").joinpath("builtin_capabilities/catalog.yaml")
        with importlib.resources.as_file(resource) as source:
            if not self.capability_catalog_path.exists():
                shutil.copy2(source, self.capability_catalog_path)


def _default_config() -> str:
    return """[whitehat]
schema_version = "1.0"
corpus_dir = "corpus/playbooks"
capability_catalog = "capabilities/catalog.yaml"
submissions_dir = ".whitehat/submissions"
campaigns_dir = ".whitehat/campaigns"
artifacts_dir = ".whitehat/artifacts"
state_database = ".whitehat/state/whitehat.db"
max_tool_response_bytes = 262144
max_evidence_import_bytes = 104857600
"""


def _inspect_database(path: Path) -> tuple[bool, str, set[str]]:
    if not path.is_file():
        return False, f"database does not exist: {path}", set()
    try:
        uri = f"file:{path.as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            check = connection.execute("PRAGMA quick_check").fetchone()[0]
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
        return check == "ok", f"{path}; quick_check={check}", tables
    except sqlite3.Error as exc:  # pragma: no cover - diagnostic boundary
        return False, str(exc), set()
