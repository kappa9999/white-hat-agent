from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from pydantic import Field, model_validator

from .models import (
    DiscoveryEpisode,
    DiscoveryObservation,
    ExecutionMode,
    Hypothesis,
    Sha256,
    StrictModel,
    TargetIdentity,
)


class AdapterError(RuntimeError):
    """Base class for normalized adapter failures."""


class ReplayExhausted(AdapterError):
    """Raised when a replay has no observation for the selected probe."""


@runtime_checkable
class DiscoveryAdapter(Protocol):
    """Explicit execution boundary between planning and target interaction."""

    adapter_id: str
    capabilities: frozenset[str]
    modes: frozenset[ExecutionMode]

    def execute(self, episode: DiscoveryEpisode, hypothesis: Hypothesis) -> DiscoveryObservation:
        """Execute one typed probe and return a normalized observation."""


class ReplayRule(StrictModel):
    hypothesis_id: str = Field(min_length=1)
    hypothesis_revision: int = Field(ge=1)
    probe_digest: Sha256
    observation: DiscoveryObservation

    @model_validator(mode="after")
    def matching_observation(self) -> ReplayRule:
        if self.observation.hypothesis_id != self.hypothesis_id:
            raise ValueError("replay observation hypothesis does not match its rule")
        if self.observation.hypothesis_revision != self.hypothesis_revision:
            raise ValueError("replay observation revision does not match its rule")
        return self


class ReplayTranscript(StrictModel):
    transcript_id: str = Field(min_length=1)
    adapter_id: str = Field(min_length=1)
    target: TargetIdentity
    capabilities: list[str] = Field(default_factory=list)
    modes: list[ExecutionMode] = Field(default_factory=lambda: [ExecutionMode.OFFLINE])
    rules: list[ReplayRule] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_lists(self) -> ReplayTranscript:
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("transcript capabilities must be unique")
        if len(self.modes) != len(set(self.modes)):
            raise ValueError("transcript modes must be unique")
        observation_ids = [item.observation.observation_id for item in self.rules]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("transcript observation ids must be unique")
        return self


class ReplayAdapter:
    """Deterministic adapter for regression evaluations and offline rehearsals."""

    def __init__(self, transcript: ReplayTranscript) -> None:
        self.adapter_id = transcript.adapter_id
        # Keep adapter identity immutable even if the caller later mutates its episode model.
        self.target = transcript.target.model_copy(deep=True)
        self.capabilities = frozenset(transcript.capabilities)
        self.modes = frozenset(transcript.modes)
        self._rules: dict[tuple[str, int, str], deque[DiscoveryObservation]] = defaultdict(deque)
        for rule in transcript.rules:
            key = (rule.hypothesis_id, rule.hypothesis_revision, rule.probe_digest)
            self._rules[key].append(rule.observation)

    def execute(self, episode: DiscoveryEpisode, hypothesis: Hypothesis) -> DiscoveryObservation:
        if episode.objective.target != self.target:
            raise AdapterError("episode target identity does not match replay transcript")
        if hypothesis.probe.adapter_id != self.adapter_id:
            message = (
                f"probe requests adapter {hypothesis.probe.adapter_id}, "
                f"but replay adapter is {self.adapter_id}"
            )
            raise AdapterError(message)
        missing = set(hypothesis.probe.required_capabilities) - self.capabilities
        if missing:
            raise AdapterError(f"replay adapter lacks capabilities: {', '.join(sorted(missing))}")
        if hypothesis.probe.mode not in self.modes:
            raise AdapterError(f"replay adapter does not support mode: {hypothesis.probe.mode.value}")
        key = (hypothesis.hypothesis_id, hypothesis.revision, hypothesis.probe.digest())
        if not self._rules[key]:
            raise ReplayExhausted(
                f"no replay observation for {hypothesis.hypothesis_id} revision {hypothesis.revision}"
            )
        return self._rules[key].popleft().model_copy(deep=True)

    def remaining_rules(self) -> int:
        return sum(len(items) for items in self._rules.values())


def assert_adapter_compatible(
    adapter: DiscoveryAdapter, episode: DiscoveryEpisode, hypotheses: Iterable[Hypothesis]
) -> None:
    """Fail early when a plan cannot be executed by the selected adapter."""

    if not isinstance(adapter, DiscoveryAdapter):
        raise TypeError("adapter does not implement DiscoveryAdapter")
    for hypothesis in hypotheses:
        if hypothesis.probe.adapter_id != adapter.adapter_id:
            raise AdapterError(f"hypothesis {hypothesis.hypothesis_id} requests a different adapter")
        missing = set(hypothesis.probe.required_capabilities) - adapter.capabilities
        if missing:
            message = (
                f"hypothesis {hypothesis.hypothesis_id} needs missing capabilities: "
                f"{', '.join(sorted(missing))}"
            )
            raise AdapterError(message)
        if hypothesis.probe.mode not in adapter.modes:
            raise AdapterError(f"hypothesis {hypothesis.hypothesis_id} requests an unsupported mode")
