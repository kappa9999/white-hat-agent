from __future__ import annotations

from dataclasses import dataclass

from .models import (
    MUTATION_RANK,
    AttemptOutcome,
    BlockedHypothesis,
    DiscoveryEpisode,
    DiscoveryPlan,
    GoalWeights,
    Hypothesis,
    HypothesisStatus,
    PlanMode,
    RankedHypothesis,
    stable_id,
)


@dataclass(frozen=True, slots=True)
class PlannerConfig:
    plateau_window: int = 3
    plateau_progress_threshold: float = 0.08
    productive_progress_threshold: float = 0.20
    recent_family_window: int = 6
    penalty_scale: float = 0.55

    def __post_init__(self) -> None:
        if self.plateau_window < 2:
            raise ValueError("plateau_window must be at least 2")
        if not 0 <= self.plateau_progress_threshold <= 1:
            raise ValueError("plateau_progress_threshold must be between 0 and 1")
        if not 0 <= self.productive_progress_threshold <= 1:
            raise ValueError("productive_progress_threshold must be between 0 and 1")
        if self.recent_family_window < 1:
            raise ValueError("recent_family_window must be positive")
        if not 0 <= self.penalty_scale <= 1:
            raise ValueError("penalty_scale must be between 0 and 1")


class AdaptivePlanner:
    """Ranks typed probes from immutable episode evidence.

    The planner adapts its effective goal function when progress stalls or a
    promising causal path appears. It never invents side effects: adapters own
    execution, while the episode manifest owns scope and capability facts.
    """

    def __init__(self, config: PlannerConfig | None = None) -> None:
        self.config = config or PlannerConfig()

    def detect_plateau(self, episode: DiscoveryEpisode) -> bool:
        recent = episode.attempts[-self.config.plateau_window :]
        if len(recent) < self.config.plateau_window:
            return False
        total_progress = sum(item.progress_delta for item in recent)
        productive = any(item.outcome == AttemptOutcome.SUCCEEDED for item in recent)
        return total_progress <= self.config.plateau_progress_threshold and not productive

    def effective_goal_weights(self, episode: DiscoveryEpisode, plateau: bool) -> GoalWeights:
        base = episode.objective.goal_weights
        updates: dict[str, float] = {}
        if plateau:
            updates = {
                "information_gain": min(10.0, base.information_gain * 1.35),
                "novelty": min(10.0, base.novelty * 1.50),
                "redundancy": min(10.0, base.redundancy * 1.30),
                "plateau_diversity_bonus": min(10.0, base.plateau_diversity_bonus * 1.50),
            }
        elif (
            episode.attempts
            and episode.attempts[-1].progress_delta >= self.config.productive_progress_threshold
        ):
            updates = {
                "impact": min(10.0, base.impact * 1.10),
                "evidence_strength": min(10.0, base.evidence_strength * 1.10),
                "causal_verifiability": min(10.0, base.causal_verifiability * 1.25),
            }
        return base.model_copy(update=updates)

    def plan(self, episode: DiscoveryEpisode, limit: int = 3) -> DiscoveryPlan:
        if limit < 1:
            raise ValueError("limit must be positive")
        budget_reasons = episode.budget.exhausted_reasons()
        plateau = self.detect_plateau(episode)
        weights = self.effective_goal_weights(episode, plateau)
        if budget_reasons:
            return self._final_plan(
                episode,
                PlanMode.BUDGET_EXHAUSTED,
                plateau,
                weights,
                [],
                [],
                budget_reasons,
            )

        candidates: list[RankedHypothesis] = []
        blocked: list[BlockedHypothesis] = []
        attempted_families = self._attempted_families(episode)
        recent_families = self._recent_families(episode)

        for hypothesis in episode.hypotheses:
            reasons = self._ineligibility_reasons(episode, hypothesis)
            if reasons:
                blocked.append(BlockedHypothesis(hypothesis_id=hypothesis.hypothesis_id, reasons=reasons))
                continue
            candidates.append(
                self._rank(
                    episode,
                    hypothesis,
                    weights,
                    plateau,
                    attempted_families,
                    recent_families,
                )
            )

        candidates.sort(key=lambda item: (-item.score, item.hypothesis_id))
        selected = self._select_diverse(candidates, limit, weights)
        blocked.sort(key=lambda item: item.hypothesis_id)

        if selected:
            mode = PlanMode.PLATEAU_RECOVERY if plateau else self._normal_mode(episode)
            rationale = [
                f"selected {len(selected)} of {len(candidates)} eligible hypotheses",
                "scores combine weighted expected discovery value, execution penalties, and diversity",
            ]
            if plateau:
                rationale.append(
                    "recent progress plateau increased novelty, information-gain, and diversity pressure"
                )
        else:
            terminal = {HypothesisStatus.REFUTED, HypothesisStatus.BLOCKED, HypothesisStatus.SUPPORTED}
            all_terminal = bool(episode.hypotheses) and all(
                item.status in terminal for item in episode.hypotheses
            )
            mode = PlanMode.COMPLETE if all_terminal else PlanMode.STALLED
            rationale = ["no eligible hypotheses remain"]

        return self._final_plan(episode, mode, plateau, weights, selected, blocked, rationale)

    def _normal_mode(self, episode: DiscoveryEpisode) -> PlanMode:
        if (
            episode.attempts
            and episode.attempts[-1].progress_delta >= self.config.productive_progress_threshold
        ):
            return PlanMode.EXPLOIT
        return PlanMode.EXPLORE

    def _attempted_families(self, episode: DiscoveryEpisode) -> set[str]:
        hypotheses = {item.hypothesis_id: item for item in episode.hypotheses}
        return {
            hypotheses[item.hypothesis_id].family.value
            for item in episode.attempts
            if item.hypothesis_id in hypotheses
        }

    def _recent_families(self, episode: DiscoveryEpisode) -> set[str]:
        hypotheses = {item.hypothesis_id: item for item in episode.hypotheses}
        recent = episode.attempts[-self.config.recent_family_window :]
        return {
            hypotheses[item.hypothesis_id].family.value for item in recent if item.hypothesis_id in hypotheses
        }

    def _ineligibility_reasons(self, episode: DiscoveryEpisode, hypothesis: Hypothesis) -> list[str]:
        reasons: list[str] = []
        if hypothesis.status in {HypothesisStatus.REFUTED, HypothesisStatus.BLOCKED}:
            reasons.append(f"terminal status: {hypothesis.status.value}")
        if hypothesis.status == HypothesisStatus.SUPPORTED:
            reasons.append("hypothesis is already supported; create a revised causal-verification probe")
        if hypothesis.blockers:
            reasons.extend(f"declared blocker: {item}" for item in hypothesis.blockers)
        if hypothesis.measures.objective_alignment < episode.objective.minimum_alignment:
            reasons.append("objective-alignment gate failed")

        allowed_capabilities = set(episode.objective.allowed_capabilities)
        missing = sorted(set(hypothesis.probe.required_capabilities) - allowed_capabilities)
        if missing:
            reasons.append(f"missing capabilities: {', '.join(missing)}")
        if hypothesis.probe.mode not in episode.objective.allowed_modes:
            reasons.append(f"execution mode is not available: {hypothesis.probe.mode.value}")
        if (
            MUTATION_RANK[hypothesis.probe.mutation_level]
            > MUTATION_RANK[episode.objective.maximum_mutation_level]
        ):
            reasons.append("probe mutation level exceeds the episode profile")
        if not episode.budget.can_afford(hypothesis.probe.cost_units):
            reasons.append("remaining budget cannot afford probe")

        by_id = {item.hypothesis_id: item for item in episode.hypotheses}
        incomplete_dependencies = [
            item
            for item in hypothesis.dependency_ids
            if item not in by_id or by_id[item].status != HypothesisStatus.SUPPORTED
        ]
        if incomplete_dependencies:
            reasons.append(f"unsatisfied dependencies: {', '.join(sorted(incomplete_dependencies))}")

        node_by_id = {item.node_id: item for item in episode.graph.nodes}
        weak_anchors = [
            node_id
            for node_id in hypothesis.anchor_node_ids
            if node_by_id[node_id].confidence < episode.objective.minimum_anchor_confidence
        ]
        if weak_anchors:
            reasons.append(f"anchor confidence below threshold: {', '.join(sorted(weak_anchors))}")

        attempts = [item for item in episode.attempts if item.hypothesis_id == hypothesis.hypothesis_id]
        if len(attempts) >= hypothesis.attempt_limit:
            reasons.append("hypothesis attempt limit reached")
        same_probe = [
            item
            for item in attempts
            if item.hypothesis_revision == hypothesis.revision
            and item.probe_digest == hypothesis.probe.digest()
            and item.outcome != AttemptOutcome.FAILED
        ]
        if same_probe:
            reasons.append("unchanged probe already produced a terminal observation")
        return reasons

    def _rank(
        self,
        episode: DiscoveryEpisode,
        hypothesis: Hypothesis,
        weights: GoalWeights,
        plateau: bool,
        attempted_families: set[str],
        recent_families: set[str],
    ) -> RankedHypothesis:
        measures = hypothesis.measures
        reward_terms = {
            "impact": (weights.impact, measures.impact),
            "reachability": (weights.reachability, measures.reachability),
            "evidence_strength": (weights.evidence_strength, measures.evidence_strength),
            "information_gain": (weights.information_gain, measures.information_gain),
            "novelty": (weights.novelty, measures.novelty),
            "causal_verifiability": (weights.causal_verifiability, measures.causal_verifiability),
            "transferability": (weights.transferability, measures.transferability),
        }
        penalty_terms = {
            "cost": (weights.cost, measures.cost),
            "blast_radius": (weights.blast_radius, measures.blast_radius),
            "redundancy": (weights.redundancy, measures.redundancy),
        }
        reward_weight = sum(weight for weight, _ in reward_terms.values())
        penalty_weight = sum(weight for weight, _ in penalty_terms.values())
        reward = sum(weight * value for weight, value in reward_terms.values()) / reward_weight
        penalty = sum(weight * value for weight, value in penalty_terms.values()) / penalty_weight
        score = 100.0 * max(0.0, reward - self.config.penalty_scale * penalty)
        bonuses: dict[str, float] = {}

        family = hypothesis.family.value
        if family not in recent_families:
            bonuses["recent-family-diversity"] = weights.diversity_bonus
        if plateau and family not in attempted_families:
            bonuses["plateau-untried-family"] = weights.plateau_diversity_bonus

        attempts = sum(item.hypothesis_id == hypothesis.hypothesis_id for item in episode.attempts)
        if attempts:
            bonuses["retry-penalty"] = -(weights.retry_penalty * attempts)
        score += sum(bonuses.values())
        reasons = [
            f"weighted reward={reward:.3f}",
            f"weighted penalty={penalty:.3f}",
            f"family={family}",
        ]
        return RankedHypothesis(
            hypothesis_id=hypothesis.hypothesis_id,
            family=hypothesis.family,
            score=round(score, 6),
            reward_score=round(reward, 6),
            penalty_score=round(penalty, 6),
            bonuses=bonuses,
            reasons=reasons,
        )

    def _select_diverse(
        self, candidates: list[RankedHypothesis], limit: int, weights: GoalWeights
    ) -> list[RankedHypothesis]:
        remaining = list(candidates)
        selected: list[RankedHypothesis] = []
        families: set[str] = set()
        while remaining and len(selected) < limit:
            best = max(
                remaining,
                key=lambda item: (
                    item.score + (weights.diversity_bonus if item.family.value not in families else 0.0),
                    -len(item.reasons),
                    item.hypothesis_id,
                ),
            )
            remaining.remove(best)
            selected.append(best)
            families.add(best.family.value)
        return selected

    def _final_plan(
        self,
        episode: DiscoveryEpisode,
        mode: PlanMode,
        plateau: bool,
        weights: GoalWeights,
        selected: list[RankedHypothesis],
        blocked: list[BlockedHypothesis],
        rationale: list[str],
    ) -> DiscoveryPlan:
        payload = {
            "episode_digest": episode.digest(),
            "mode": mode.value,
            "plateau": plateau,
            "selected": [item.model_dump(mode="json") for item in selected],
            "blocked": [item.model_dump(mode="json") for item in blocked],
            "weights": weights.model_dump(mode="json"),
            "config": {
                "plateau_window": self.config.plateau_window,
                "plateau_progress_threshold": self.config.plateau_progress_threshold,
                "productive_progress_threshold": self.config.productive_progress_threshold,
                "recent_family_window": self.config.recent_family_window,
                "penalty_scale": self.config.penalty_scale,
            },
        }
        return DiscoveryPlan(
            plan_id=stable_id("plan", payload),
            episode_id=episode.episode_id,
            episode_digest=episode.digest(),
            graph_revision=episode.graph.revision,
            mode=mode,
            plateau_detected=plateau,
            selected=selected,
            blocked=blocked,
            effective_goal_weights=weights,
            rationale=rationale,
        )
