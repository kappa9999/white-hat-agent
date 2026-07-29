from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from verify_release_artifacts import distribution_files, verify_candidate


def run(*arguments: str, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )


def verify_cli(executable: Path, temporary_root: Path, expected_version: str, label: str) -> None:
    workspace = temporary_root / f"{label}-workspace"
    initialized = json.loads(run(str(executable), "init", str(workspace), cwd=temporary_root).stdout)
    if initialized.get("healthy") is not True:
        raise RuntimeError(f"{label} candidate initialized an unhealthy workspace: {initialized}")
    version = run(str(executable), "--version", cwd=temporary_root).stdout.strip()
    if version != f"White Hat Agent Core {expected_version}":
        raise RuntimeError(f"unexpected {label} version output: {version}")
    playbooks = list((workspace / "corpus/playbooks").rglob("playbook.yaml"))
    if len(playbooks) != 5 or not (workspace / "capabilities/catalog.yaml").is_file():
        raise RuntimeError(f"{label} candidate omitted bundled assets")


def smoke_distribution(artifact: Path, temporary_root: Path, expected_version: str) -> None:
    label = "wheel" if artifact.suffix == ".whl" else "sdist"
    environment = temporary_root / f"{label}-venv"
    run("uv", "venv", "--python", sys.executable, str(environment), cwd=temporary_root)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    executable = environment / ("Scripts/wha.exe" if os.name == "nt" else "bin/wha")
    run("uv", "pip", "install", "--python", str(python), str(artifact), cwd=temporary_root)
    verify_cli(executable, temporary_root, expected_version, label)


def smoke_installer(root: Path, wheel: Path, temporary_root: Path, expected_version: str) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required for the installer smoke test")
    environment = os.environ.copy()
    environment.update(
        {
            "UV_PYTHON_INSTALL_DIR": str(temporary_root / "installer-python"),
            "UV_TOOL_BIN_DIR": str(temporary_root / "installer-bin"),
            "UV_TOOL_DIR": str(temporary_root / "installer-tools"),
            "WHA_PACKAGE": str(wheel.resolve()),
            "WHA_SKIP_PATH_UPDATE": "1",
            "WHA_UV_BIN": uv,
        }
    )
    run("sh", "./install.sh", cwd=root, env=environment)
    verify_cli(temporary_root / "installer-bin/wha", temporary_root, expected_version, "installer-wheel")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke the exact wheel and sdist in a release candidate.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--candidate", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    candidate = args.candidate.resolve()
    manifest = verify_candidate(candidate)
    artifacts = distribution_files(candidate)
    with tempfile.TemporaryDirectory(prefix="white-hat-agent-release-smoke-") as temporary:
        temporary_root = Path(temporary)
        for artifact in artifacts:
            smoke_distribution(artifact, temporary_root, manifest["version"])
        wheel = next(artifact for artifact in artifacts if artifact.suffix == ".whl")
        smoke_installer(args.root.resolve(), wheel, temporary_root, manifest["version"])
    print(f"release candidate smoke passed: {', '.join(path.name for path in artifacts)}")


if __name__ == "__main__":
    main()
