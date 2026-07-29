from __future__ import annotations

import tempfile
import tomllib
from pathlib import Path

from release_smoke import run, smoke_distribution

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    with (root / "pyproject.toml").open("rb") as project_file:
        expected_version = tomllib.load(project_file)["project"]["version"]
    with tempfile.TemporaryDirectory(prefix="white-hat-agent-distributions-") as temporary:
        temporary_root = Path(temporary)
        distribution_dir = temporary_root / "dist"
        run("uv", "build", "--out-dir", str(distribution_dir), cwd=root)
        wheels = sorted(distribution_dir.glob("*.whl"))
        sdists = sorted(distribution_dir.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sdists) != 1:
            raise RuntimeError(f"expected one wheel and one sdist, found {wheels=} {sdists=}")
        for artifact in (wheels[0], sdists[0]):
            smoke_distribution(artifact, temporary_root, expected_version)
        print(f"distribution smoke tests passed: {wheels[0].name}, {sdists[0].name}")
