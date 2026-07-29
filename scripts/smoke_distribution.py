from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
    )


def smoke_artifact(artifact: Path, temporary_root: Path) -> None:
    artifact_kind = "wheel" if artifact.suffix == ".whl" else "sdist"
    environment_dir = temporary_root / f"{artifact_kind}-venv"
    workspace_dir = temporary_root / f"{artifact_kind}-workspace"
    run("uv", "venv", "--python", sys.executable, str(environment_dir), cwd=temporary_root)
    python = environment_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    wha = environment_dir / ("Scripts/wha.exe" if os.name == "nt" else "bin/wha")
    run("uv", "pip", "install", "--python", str(python), str(artifact), cwd=temporary_root)
    initialized = run(str(wha), "init", str(workspace_dir), cwd=temporary_root)
    report = json.loads(initialized.stdout)
    if not report["healthy"]:
        raise RuntimeError(report)
    corpus = list((workspace_dir / "corpus/playbooks").rglob("playbook.yaml"))
    if len(corpus) != 4 or not (workspace_dir / "capabilities/catalog.yaml").is_file():
        raise RuntimeError(f"{artifact_kind} omitted bundled corpus or capability catalog")
    version = run(str(wha), "--version", cwd=temporary_root).stdout.strip()
    if version != "White Hat Agent Core 0.1.0":
        raise RuntimeError(f"unexpected version output from {artifact_kind}: {version}")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="white-hat-agent-distributions-") as temporary:
        temporary_root = Path(temporary)
        distribution_dir = temporary_root / "dist"
        run("uv", "build", "--out-dir", str(distribution_dir), cwd=root)
        wheels = sorted(distribution_dir.glob("*.whl"))
        sdists = sorted(distribution_dir.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sdists) != 1:
            raise RuntimeError(f"expected one wheel and one sdist, found {wheels=} {sdists=}")
        for artifact in (wheels[0], sdists[0]):
            smoke_artifact(artifact, temporary_root)
        print(f"distribution smoke tests passed: {wheels[0].name}, {sdists[0].name}")
