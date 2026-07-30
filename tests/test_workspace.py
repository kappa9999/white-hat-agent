from __future__ import annotations

import pytest

from white_hat_agent.workspace import Workspace


def test_workspace_init_is_idempotent_and_doctor_is_healthy(tmp_path) -> None:
    first = Workspace.initialize(tmp_path)
    second = Workspace.initialize(tmp_path)

    assert first.doctor().healthy
    assert second.doctor().healthy
    assert first.corpus.load().playbook_count == 6
    assert len(first.adapter_registry.all()) == 9
    assert first.state_database.is_file()


def test_workspace_rejects_paths_that_escape_root(tmp_path) -> None:
    (tmp_path / "whitehat.toml").write_text(
        """[whitehat]
corpus_dir = "../outside"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="escapes root"):
        Workspace.load(tmp_path)


def test_doctor_does_not_create_missing_state(tmp_path) -> None:
    (tmp_path / "whitehat.toml").write_text("[whitehat]\n", encoding="utf-8")
    workspace = Workspace.load(tmp_path)

    report = workspace.doctor()

    assert not report.healthy
    assert not workspace.state_database.exists()


def test_no_builtin_corpus_still_installs_capability_and_adapter_contracts(tmp_path) -> None:
    workspace = Workspace.initialize(tmp_path, copy_builtin_corpus=False)

    assert workspace.capability_catalog_path.is_file()
    assert workspace.adapter_catalog_path.is_file()
    assert list(workspace.corpus_dir.rglob("*.yaml")) == []
