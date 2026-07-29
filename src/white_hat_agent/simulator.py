from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .adapters import DiscoveryAdapter, ReplayExhausted
from .episode import apply_observation
from .expansion import HypothesisGenerator, apply_expansion
from .models import (
    DiscoveryEpisode,
    DiscoveryPlan,
    ExpansionTrigger,
    HypothesisExpansionRecord,
    PlanMode,
    StrictModel,
)
from .planner import AdaptivePlanner


class SimulationHalt(StrEnum):
    COMPLETE = "complete"
    BUDGET_EXHAUSTED = "budget-exhausted"
    STALLED = "stalled"
    ADAPTER_EXHAUSTED = "adapter-exhausted"
    EXPANSION_LIMIT = "expansion-limit"
    CYCLE_LIMIT = "cycle-limit"


class SimulationStep(StrictModel):
    cycle: int = Field(ge=1)
    plan_id: str
    hypothesis_id: str
    observation_id: str
    attempt_id: str
    progress_delta: float = Field(ge=0.0, le=1.0)


class SimulationResult(StrictModel):
    halt_reason: SimulationHalt
    halt_detail: str
    cycles: int = Field(ge=0)
    plans: list[DiscoveryPlan]
    steps: list[SimulationStep]
    expansions: list[HypothesisExpansionRecord] = Field(default_factory=list)
    final_episode: DiscoveryEpisode


def run_simulation(
    episode: DiscoveryEpisode,
    adapter: DiscoveryAdapter,
    *,
    planner: AdaptivePlanner | None = None,
    generator: HypothesisGenerator | None = None,
    max_cycles: int = 100,
    max_expansions: int = 8,
    expansion_batch_limit: int = 8,
    continue_after_complete: bool = False,
) -> SimulationResult:
    """Run plan -> probe -> observe -> replan, one evidence boundary at a time."""

    if max_cycles < 1:
        raise ValueError("max_cycles must be positive")
    if max_expansions < 0:
        raise ValueError("max_expansions cannot be negative")
    if expansion_batch_limit < 1:
        raise ValueError("expansion_batch_limit must be positive")
    engine = planner or AdaptivePlanner()
    current = episode.model_copy(deep=True)
    plans: list[DiscoveryPlan] = []
    steps: list[SimulationStep] = []
    expansions: list[HypothesisExpansionRecord] = []
    executed_cycles = 0

    while executed_cycles < max_cycles:
        plan = engine.plan(current, limit=1)
        plans.append(plan)
        expansion_trigger = _expansion_trigger(plan, continue_after_complete)
        if expansion_trigger is not None and generator is not None:
            if len(expansions) >= max_expansions:
                return SimulationResult(
                    halt_reason=SimulationHalt.EXPANSION_LIMIT,
                    halt_detail=f"expansion limit reached: {max_expansions}",
                    cycles=executed_cycles,
                    plans=plans,
                    steps=steps,
                    expansions=expansions,
                    final_episode=current,
                )
            batch = generator.expand(current, plan, expansion_trigger, expansion_batch_limit)
            if batch is not None:
                current = apply_expansion(current, batch)
                expansions.append(current.expansions[-1])
                continue
        if not plan.selected:
            halt = _halt_from_plan(plan.mode)
            return SimulationResult(
                halt_reason=halt,
                halt_detail=plan.rationale[0] if plan.rationale else plan.mode.value,
                cycles=executed_cycles,
                plans=plans,
                steps=steps,
                expansions=expansions,
                final_episode=current,
            )

        selected_id = plan.selected[0].hypothesis_id
        selected = next(item for item in current.hypotheses if item.hypothesis_id == selected_id)
        try:
            observation = adapter.execute(current, selected)
        except ReplayExhausted as exc:
            return SimulationResult(
                halt_reason=SimulationHalt.ADAPTER_EXHAUSTED,
                halt_detail=str(exc),
                cycles=executed_cycles,
                plans=plans,
                steps=steps,
                expansions=expansions,
                final_episode=current,
            )
        current = apply_observation(current, observation)
        attempt = current.attempts[-1]
        executed_cycles += 1
        steps.append(
            SimulationStep(
                cycle=executed_cycles,
                plan_id=plan.plan_id,
                hypothesis_id=selected_id,
                observation_id=observation.observation_id,
                attempt_id=attempt.attempt_id,
                progress_delta=observation.progress_delta,
            )
        )

    return SimulationResult(
        halt_reason=SimulationHalt.CYCLE_LIMIT,
        halt_detail=f"cycle limit reached: {max_cycles}",
        cycles=max_cycles,
        plans=plans,
        steps=steps,
        expansions=expansions,
        final_episode=current,
    )


def _halt_from_plan(mode: PlanMode) -> SimulationHalt:
    if mode == PlanMode.COMPLETE:
        return SimulationHalt.COMPLETE
    if mode == PlanMode.BUDGET_EXHAUSTED:
        return SimulationHalt.BUDGET_EXHAUSTED
    return SimulationHalt.STALLED


def _expansion_trigger(plan: DiscoveryPlan, continue_after_complete: bool) -> ExpansionTrigger | None:
    if plan.mode == PlanMode.STALLED:
        return ExpansionTrigger.STALLED
    if plan.mode == PlanMode.PLATEAU_RECOVERY:
        return ExpansionTrigger.PLATEAU
    if plan.mode == PlanMode.COMPLETE and continue_after_complete:
        return ExpansionTrigger.CAMPAIGN_ROLLOVER
    return None
