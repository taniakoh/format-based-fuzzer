"""
Corpus Manager - adaptive seed queue with feedback-driven selection.

Static seed priorities are still respected, but the queue now also biases
toward seeds that are newly discovered, historically productive, and not
selected too recently. Seeds that repeatedly fail to uncover new behavior
gradually cool off instead of consuming the same expensive executions.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable


@dataclass
class CorpusEntry:
    seed: bytes
    base_priority: float = 1.0
    rare_score: float = 0.0
    attempts: int = 0
    successes: int = 0
    added_round: int = 0
    last_selected_round: int = -1
    last_success_round: int = -1


class Corpus:
    def __init__(self):
        self._entries: list[CorpusEntry] = []
        self._index_by_seed: dict[bytes, int] = {}
        self._selection_round = 0

    def add(self, seed: bytes, priority: float = 1.0, rare_score: float = 0.0) -> None:
        existing_index = self._index_by_seed.get(seed)
        if existing_index is not None:
            entry = self._entries[existing_index]
            entry.base_priority = max(entry.base_priority, float(priority))
            entry.rare_score = max(entry.rare_score, float(rare_score))
            return

        entry = CorpusEntry(
            seed=seed,
            base_priority=max(0.05, float(priority)),
            rare_score=max(0.0, float(rare_score)),
            added_round=self._selection_round,
            last_success_round=self._selection_round,
        )
        self._index_by_seed[seed] = len(self._entries)
        self._entries.append(entry)

    def select(
        self,
        priority_fn: Callable[[bytes], float] | None = None,
    ) -> bytes:
        """Select one seed using adaptive, feedback-aware weighting."""
        if not self._entries:
            raise IndexError("cannot select from an empty corpus")

        weights = [self._selection_weight(entry, priority_fn) for entry in self._entries]
        chosen_index = random.choices(range(len(self._entries)), weights=weights, k=1)[0]
        chosen = self._entries[chosen_index]
        self._selection_round += 1
        chosen.last_selected_round = self._selection_round
        return chosen.seed

    def record_result(
        self,
        seed: bytes,
        discovered_new_behavior: bool,
        rarity_score: float = 0.0,
        cooldown_factor: float = 1.0,
    ) -> None:
        """Update the parent seed's payoff after one mutation/execution cycle."""
        index = self._index_by_seed.get(seed)
        if index is None:
            return

        entry = self._entries[index]
        entry.attempts += 1
        entry.rare_score = max(entry.rare_score * 0.92, float(rarity_score))
        entry.base_priority = max(0.02, entry.base_priority * max(0.05, float(cooldown_factor)))
        if discovered_new_behavior:
            entry.successes += 1
            entry.last_success_round = self._selection_round

    def __len__(self) -> int:
        return len(self._entries)

    def _selection_weight(
        self,
        entry: CorpusEntry,
        priority_fn: Callable[[bytes], float] | None,
    ) -> float:
        dynamic_priority = entry.base_priority
        if priority_fn is not None:
            try:
                dynamic_priority = max(dynamic_priority, float(priority_fn(entry.seed)))
            except Exception:
                dynamic_priority = entry.base_priority

        novelty_boost = 1.0 + (max(0, 6 - entry.attempts) * 0.15)
        success_bonus = 1.0 + (entry.successes * 0.75)
        failure_penalty = 1.0 / (1.0 + max(0, entry.attempts - entry.successes) * 0.18)

        rounds_since_selected = self._selection_round - entry.last_selected_round
        if entry.last_selected_round < 0:
            recency_penalty = 1.0
        else:
            recency_penalty = min(1.0, 0.35 + (max(0, rounds_since_selected) * 0.15))

        rounds_since_success = self._selection_round - entry.last_success_round
        if entry.last_success_round < 0:
            staleness_penalty = 1.0
        else:
            stale_rounds = max(0, rounds_since_success - 8)
            staleness_penalty = 1.0 / (1.0 + stale_rounds * 0.03)

        rare_edge_bonus = 1.0 + min(2.5, entry.rare_score) * 0.35

        return max(
            0.01,
            dynamic_priority
            * rare_edge_bonus
            * novelty_boost
            * success_bonus
            * failure_penalty
            * recency_penalty
            * staleness_penalty,
        )
