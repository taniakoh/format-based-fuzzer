"""
Shared scheduler primitives for static and hybrid mutation planning.

The scheduler now learns from mutation payoff directly, not just coverage
prediction. Lightweight moving statistics track which semantic stages,
operators, fields, seed families, and guided mutations actually produce new
behaviors, then feed those scores back into future plans.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OutcomeStat:
    """Online payoff estimate with both empirical rate and EWMA."""

    attempts: int = 0
    successes: int = 0
    ewma: float = 0.5

    @property
    def success_rate(self) -> float:
        if self.attempts <= 0:
            return 0.0
        return self.successes / self.attempts

    def update(self, success: bool, alpha: float) -> None:
        self.attempts += 1
        if success:
            self.successes += 1
        target = 1.0 if success else 0.0
        self.ewma = ((1.0 - alpha) * self.ewma) + (alpha * target)

    def to_dict(self) -> dict[str, float]:
        return {
            "attempts": self.attempts,
            "successes": self.successes,
            "success_rate": round(self.success_rate, 4),
            "ewma": round(self.ewma, 4),
        }


class MutationPayoffTracker:
    """Track mutation payoff and turn it into scheduler hints."""

    EMA_ALPHA = 0.20
    PRIOR_SCORE = 0.50
    MIN_CONFIDENT_SAMPLES = 5
    MIN_OPERATOR_WEIGHT = 0.05
    BASE_SEMANTIC_PROBABILITY = 0.50
    MIN_SEMANTIC_PROBABILITY = 0.20
    MAX_SEMANTIC_PROBABILITY = 0.80
    BASE_GUIDED_RATIO = 0.70
    MIN_GUIDED_RATIO = 0.20
    MAX_GUIDED_RATIO = 0.90
    MAX_PREFERRED_FIELDS = 3

    def __init__(self, static_weights: dict[str, float]):
        self.static_weights = self._normalize_weights(static_weights)
        self.operator_stats: dict[str, OutcomeStat] = {}
        self.field_stats: dict[str, OutcomeStat] = {}
        self.guidance_stats: dict[str, OutcomeStat] = {}
        self.stage_stats: dict[str, OutcomeStat] = {}
        self.seed_family_stats: dict[str, OutcomeStat] = {}
        self.family_operator_stats: dict[str, OutcomeStat] = {}
        self.family_stage_stats: dict[str, OutcomeStat] = {}

    def plan(
        self,
        seed: bytes,
        *,
        base_blend: float = 1.0,
    ) -> dict[str, object]:
        seed_family = self.describe_seed_family(seed)
        return {
            "seed_family": seed_family,
            "weights": self._operator_weights(seed_family=seed_family, base_blend=base_blend),
            "semantic_probability": self._semantic_probability(seed_family),
            "guided_ratio": self._guided_ratio(seed_family),
            "preferred_fields": self._preferred_fields(seed_family),
        }

    def record_mutation_outcome(
        self,
        plan: dict[str, object],
        discovered_new_behavior: bool,
        semantic_trace: dict[str, object] | None = None,
        havoc_trace: dict[str, object] | None = None,
    ) -> None:
        seed_family = str(plan.get("seed_family", "unknown"))
        self._update_stat(self.seed_family_stats, seed_family, discovered_new_behavior)

        semantic_used = bool(semantic_trace and semantic_trace.get("applied"))
        stage_key = "semantic" if semantic_used else "havoc_only"
        self._update_stat(self.stage_stats, stage_key, discovered_new_behavior)
        self._update_stat(
            self.family_stage_stats,
            f"{seed_family}|{stage_key}",
            discovered_new_behavior,
        )

        if semantic_trace:
            op = semantic_trace.get("operation")
            if op:
                self._update_stat(
                    self.operator_stats,
                    f"semantic:{op}",
                    discovered_new_behavior,
                )
            field = semantic_trace.get("field")
            if field:
                self._update_stat(self.field_stats, str(field), discovered_new_behavior)
            guidance = semantic_trace.get("guidance")
            if guidance:
                self._update_stat(self.guidance_stats, str(guidance), discovered_new_behavior)

        if havoc_trace:
            for op in havoc_trace.get("operators", []):
                op_name = str(op)
                self._update_stat(
                    self.operator_stats,
                    f"havoc:{op_name}",
                    discovered_new_behavior,
                )
                self._update_stat(
                    self.family_operator_stats,
                    f"{seed_family}|{op_name}",
                    discovered_new_behavior,
                )
            for field in havoc_trace.get("fields", []):
                self._update_stat(self.field_stats, str(field), discovered_new_behavior)
            guided_iterations = int(havoc_trace.get("guided_iterations", 0))
            random_iterations = int(havoc_trace.get("random_iterations", 0))
            if guided_iterations > 0:
                self._update_stat(self.guidance_stats, "guided", discovered_new_behavior)
            if random_iterations > 0:
                self._update_stat(self.guidance_stats, "random", discovered_new_behavior)

    def export_mutation_stats(self) -> dict[str, object]:
        return {
            "operators": self._serialize_stats(self.operator_stats),
            "fields": self._serialize_stats(self.field_stats),
            "guidance": self._serialize_stats(self.guidance_stats),
            "stages": self._serialize_stats(self.stage_stats),
            "seed_families": self._serialize_stats(self.seed_family_stats),
            "family_operators": self._serialize_stats(self.family_operator_stats),
            "family_stages": self._serialize_stats(self.family_stage_stats),
        }

    def describe_seed_family(self, seed: bytes) -> str:
        text = seed.decode("latin-1", errors="replace")
        pieces: list[str] = []
        length = len(text)
        if length <= 7:
            pieces.append("len:short")
        elif length <= 20:
            pieces.append("len:medium")
        else:
            pieces.append("len:long")

        if "." in text:
            pieces.append(f"dots:{text.count('.')}")
        if ":" in text:
            pieces.append(f"colons:{text.count(':')}")
        if "::" in text:
            pieces.append("double_colon")
        if "%" in text:
            pieces.append("zone_id")
        if any(ch.isspace() for ch in text):
            pieces.append("whitespace")
        if any(ch in "abcdefABCDEF" for ch in text):
            pieces.append("hexish")
        if "-" in text:
            pieces.append("negativeish")
        if not pieces:
            pieces.append("plain")
        return "|".join(pieces)

    def _operator_weights(
        self,
        *,
        seed_family: str,
        base_blend: float,
    ) -> dict[str, float]:
        adjusted: dict[str, float] = {}
        for op, base_weight in self.static_weights.items():
            global_score = self._score(self.operator_stats.get(f"havoc:{op}"))
            family_score = self._score(self.family_operator_stats.get(f"{seed_family}|{op}"))
            payoff_boost = (0.60 * global_score) + (0.40 * family_score)
            learned_weight = max(self.MIN_OPERATOR_WEIGHT, payoff_boost)
            adjusted[op] = ((1.0 - base_blend) * base_weight) + (base_blend * learned_weight)
        return self._normalize_weights(adjusted)

    def _semantic_probability(self, seed_family: str) -> float:
        semantic_score = self._score(self.stage_stats.get("semantic"))
        havoc_only_score = self._score(self.stage_stats.get("havoc_only"))
        family_semantic = self._score(self.family_stage_stats.get(f"{seed_family}|semantic"))
        family_havoc = self._score(self.family_stage_stats.get(f"{seed_family}|havoc_only"))
        delta = ((semantic_score - havoc_only_score) * 0.60) + (
            (family_semantic - family_havoc) * 0.40
        )
        return self._clamp(
            self.BASE_SEMANTIC_PROBABILITY + (delta * 0.35),
            self.MIN_SEMANTIC_PROBABILITY,
            self.MAX_SEMANTIC_PROBABILITY,
        )

    def _guided_ratio(self, seed_family: str) -> float:
        guided_score = self._score(self.guidance_stats.get("guided"))
        random_score = self._score(self.guidance_stats.get("random"))
        family_guided = self._score(self.seed_family_stats.get(seed_family))
        delta = ((guided_score - random_score) * 0.70) + (
            (family_guided - self.PRIOR_SCORE) * 0.30
        )
        return self._clamp(
            self.BASE_GUIDED_RATIO + (delta * 0.25),
            self.MIN_GUIDED_RATIO,
            self.MAX_GUIDED_RATIO,
        )

    def _preferred_fields(self, seed_family: str) -> list[str]:
        del seed_family  # Reserved for later per-family field ranking.
        ranked = sorted(
            self.field_stats.items(),
            key=lambda item: self._score(item[1]),
            reverse=True,
        )
        return [name for name, _ in ranked[: self.MAX_PREFERRED_FIELDS]]

    def _score(self, stat: OutcomeStat | None) -> float:
        if stat is None or stat.attempts <= 0:
            return self.PRIOR_SCORE
        confidence = min(1.0, stat.attempts / self.MIN_CONFIDENT_SAMPLES)
        blended = (0.5 * stat.success_rate) + (0.5 * stat.ewma)
        return ((1.0 - confidence) * self.PRIOR_SCORE) + (confidence * blended)

    def _update_stat(
        self,
        bucket: dict[str, OutcomeStat],
        key: str,
        success: bool,
    ) -> None:
        stat = bucket.setdefault(key, OutcomeStat())
        stat.update(success, alpha=self.EMA_ALPHA)

    def _serialize_stats(self, stats: dict[str, OutcomeStat]) -> dict[str, dict[str, float]]:
        return {
            key: value.to_dict()
            for key, value in sorted(
                stats.items(),
                key=lambda item: (-item[1].success_rate, -item[1].attempts, item[0]),
            )
        }

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        return max(low, min(high, value))

    @staticmethod
    def _normalize_weights(weights: dict[str, float]) -> dict[str, float]:
        total = sum(max(0.0, value) for value in weights.values())
        if total <= 0:
            ops = list(weights.keys())
            uniform = 1.0 / max(1, len(ops))
            return {op: uniform for op in ops}
        return {op: max(0.0, value) / total for op, value in weights.items()}


class StaticScheduler:
    """Static scheduler plus online mutation-payoff learning."""

    def __init__(self, format_config: dict):
        self.payoff_tracker = MutationPayoffTracker(format_config["havoc_operators"])
        self.static_weights = dict(self.payoff_tracker.static_weights)

    def get_operator_weights(self, seed: bytes) -> dict[str, float]:
        return self.plan_mutation(seed)["weights"]

    def get_seed_priority(self, seed: bytes) -> float:  # noqa: ARG002
        family_score = self.payoff_tracker._score(  # noqa: SLF001
            self.payoff_tracker.seed_family_stats.get(
                self.payoff_tracker.describe_seed_family(seed)
            )
        )
        return 1.0 + ((family_score - self.payoff_tracker.PRIOR_SCORE) * 0.5)

    def plan_mutation(self, seed: bytes) -> dict[str, object]:
        plan = self.payoff_tracker.plan(seed, base_blend=1.0)
        plan.update(
            {
                "mode": "static",
                "confidence": 0.0,
                "blend": 0.0,
                "reason": "mutation_payoff_only",
            }
        )
        return plan

    def record_mutation_outcome(
        self,
        plan: dict[str, object],
        discovered_new_behavior: bool,
        semantic_trace: dict[str, object] | None = None,
        havoc_trace: dict[str, object] | None = None,
    ) -> None:
        self.payoff_tracker.record_mutation_outcome(
            plan=plan,
            discovered_new_behavior=discovered_new_behavior,
            semantic_trace=semantic_trace,
            havoc_trace=havoc_trace,
        )

    def export_mutation_stats(self) -> dict[str, object]:
        return self.payoff_tracker.export_mutation_stats()
