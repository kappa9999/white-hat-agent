from __future__ import annotations

from pydantic import ValidationError

from white_hat_agent.fixtures import build_active_data_episode
from white_hat_agent.models import SurfaceEdge, SurfaceGraph


def test_episode_round_trip_preserves_canonical_digest() -> None:
    episode = build_active_data_episode()
    restored = type(episode).model_validate(episode.model_dump(mode="json"))

    assert restored == episode
    assert restored.digest() == episode.digest()
    assert len(episode.digest()) == 64


def test_strict_models_reject_unknown_fields() -> None:
    payload = build_active_data_episode().model_dump(mode="json")
    payload["hidden_state"] = "must not pass silently"

    try:
        type(build_active_data_episode()).model_validate(payload)
    except ValidationError as exc:
        assert "extra_forbidden" in str(exc)
    else:  # pragma: no cover - assertion aid
        raise AssertionError("unknown fields must be rejected")


def test_surface_graph_rejects_dangling_edges() -> None:
    episode = build_active_data_episode()
    dangling = SurfaceEdge(
        edge_id="edge-dangling",
        source="n-input",
        target="n-missing",
        relation="flows-to",
        confidence=0.8,
    )

    try:
        SurfaceGraph(nodes=episode.graph.nodes, edges=[dangling])
    except ValidationError as exc:
        assert "unknown endpoint" in str(exc)
    else:  # pragma: no cover - assertion aid
        raise AssertionError("dangling graph edges must be rejected")


def test_target_identity_changes_episode_digest() -> None:
    baseline = build_active_data_episode()
    changed = baseline.model_copy(deep=True)
    changed.objective.target.build_id = "fixture-build-2"

    assert changed.digest() != baseline.digest()
