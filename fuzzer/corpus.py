"""
Corpus Manager — seed queue with priority-weighted selection.

Seeds are stored as bytes.  Priority scores (default 1.0) bias selection
toward inputs that are more likely to find new coverage.  In Phase 2 the
DL scheduler provides learned priority scores; Phase 1 uses uniform 1.0.
"""

import random


class Corpus:
    def __init__(self):
        self.seeds: list[bytes] = []
        self.priorities: list[float] = []

    def add(self, seed: bytes, priority: float = 1.0) -> None:
        self.seeds.append(seed)
        self.priorities.append(priority)

    def select(self) -> bytes:
        """Priority-weighted seed selection."""
        return random.choices(self.seeds, weights=self.priorities, k=1)[0]

    def __len__(self) -> int:
        return len(self.seeds)
