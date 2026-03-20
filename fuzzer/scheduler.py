"""
Phase 1 Scheduler — static operator weights from the format config.

In Phase 2 this module is replaced by dl/surrogate.py + DLScheduler, which
learns operator weights and seed priorities from observed coverage.  The
interface (get_operator_weights / get_seed_priority) is identical in both
phases so the main loop requires no changes.
"""


class StaticScheduler:
    """Phase 1: returns hand-coded weights directly from the format config."""

    def __init__(self, format_config: dict):
        self.weights = format_config["havoc_operators"]

    def get_operator_weights(self, seed: bytes) -> dict[str, float]:  # noqa: ARG002
        return self.weights

    def get_seed_priority(self, seed: bytes) -> float:  # noqa: ARG002
        return 1.0
