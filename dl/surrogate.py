"""
Module 6 - Neural Surrogate Model (Phase 2).

Predicts compressed coverage representation from input bytes.
Swap StaticScheduler for DLScheduler in main.py to activate.

Device selection: automatically uses CUDA if available, otherwise CPU.

Requires: torch>=2.2.0
"""

from __future__ import annotations

from collections import deque

from fuzzer.scheduler import MutationPayoffTracker


def get_device() -> str:
    """Return 'cuda' if a CUDA-capable GPU is available, else 'cpu'."""
    try:
        import torch

        device = "cuda" if torch.cuda.is_available() else "cpu"
        if device == "cuda":
            print(f"[DL] Using CUDA: {torch.cuda.get_device_name(0)}")
        else:
            print("[DL] CUDA not available - using CPU")
        return device
    except ImportError:
        return "cpu"


try:
    import torch
    import torch.nn as nn

    class CoverageSurrogate(nn.Module):
        """
        Input  : flattened seed bytes padded/truncated to MAX_LEN
        Output : predicted coverage (COV_DIM sigmoid values) + confidence scalar
        """

        MAX_LEN = 256
        COV_DIM = 128

        def __init__(self):
            super().__init__()
            self.embed = nn.Embedding(256, 8)
            self.encoder = nn.Sequential(
                nn.Flatten(),
                nn.Linear(self.MAX_LEN * 8, 512),
                nn.ReLU(),
                nn.Linear(512, 256),
                nn.ReLU(),
            )
            self.coverage_head = nn.Linear(256, self.COV_DIM)
            self.confidence_head = nn.Linear(256, 1)

        def forward(self, x: "torch.Tensor"):
            emb = self.embed(x)
            h = self.encoder(emb)
            coverage = torch.sigmoid(self.coverage_head(h))
            confidence = torch.sigmoid(self.confidence_head(h))
            return coverage, confidence

    def identify_hot_bytes(
        model: "CoverageSurrogate",
        seed: bytes,
        device: str | None = None,
    ) -> list[int]:
        """
        Compute gradient of predicted coverage w.r.t. each input byte position.
        Returns sorted list of byte indices most likely to increase coverage.
        """

        if device is None:
            device = get_device()
        max_len = CoverageSurrogate.MAX_LEN
        padded = list(seed[:max_len]) + [0] * (max_len - len(seed))
        x = torch.tensor([padded], dtype=torch.long, device=device)

        embed = model.embed(x).float()
        embed.retain_grad()
        embed.requires_grad_(True)

        flat = embed.view(1, -1)
        h = model.encoder(flat)
        coverage = torch.sigmoid(model.coverage_head(h))
        coverage.sum().backward()

        importance = embed.grad.abs().sum(dim=-1).squeeze()
        hot_bytes = importance.argsort(descending=True).tolist()
        return [i for i in hot_bytes if i < len(seed)]

except ImportError:
    class CoverageSurrogate:  # type: ignore[no-redef]
        pass

    def identify_hot_bytes(model, seed: bytes, device=None) -> list[int]:  # type: ignore[misc]
        return []


class DLScheduler:
    """
    Hybrid scheduler with a strong static fallback.

    The learned policy never permanently replaces the static one. Instead, it
    earns influence based on confidence, training maturity, and recent
    guided-vs-static outcomes.
    """

    WARMUP_SAMPLES = 20
    WARMUP_TRAINING_ROUNDS = 2
    RECENT_WINDOW = 12
    MIN_MODE_SAMPLES = 3
    MAX_GUIDED_BLEND = 0.85
    MIN_GUIDED_BLEND = 0.15
    BOOSTED_PRIORITY_SCALE = 0.75

    def __init__(
        self,
        model,
        trust_gate,
        format_config: dict,
        device: str | None = None,
    ):
        self.model = model
        self.trust_gate = trust_gate
        self.payoff_tracker = MutationPayoffTracker(format_config["havoc_operators"])
        self.static_weights = dict(self.payoff_tracker.static_weights)
        self.device = device if device is not None else get_device()
        self.training_samples_seen = 0
        self.training_rounds = 0
        self.last_training_loss: float | None = None
        self._recent_results: deque[tuple[str, bool]] = deque(maxlen=self.RECENT_WINDOW)
        self._last_plan = self._make_static_plan(b"")
        if hasattr(self.model, "to"):
            self.model.to(self.device)

    def get_operator_weights(self, seed: bytes) -> dict[str, float]:
        return self.plan_mutation(seed)["weights"]

    def get_seed_priority(self, seed: bytes) -> float:
        plan = self.plan_mutation(seed)
        family_score = self.payoff_tracker._score(  # noqa: SLF001
            self.payoff_tracker.seed_family_stats.get(str(plan["seed_family"]))
        )
        base_priority = 1.0 + ((family_score - self.payoff_tracker.PRIOR_SCORE) * 0.5)
        if plan["mode"] == "static":
            return base_priority
        confidence = float(plan["confidence"])
        blend = float(plan["blend"])
        return base_priority + (confidence * blend * self.BOOSTED_PRIORITY_SCALE)

    def plan_mutation(self, seed: bytes) -> dict[str, object]:
        plan = self._make_static_plan(seed)
        try:
            x = self._encode(seed)
            _, confidence = self.model(x)
            plan = self._make_plan(seed, float(confidence.item()))
        except Exception:
            pass
        self._last_plan = plan
        return plan

    def record_mutation_outcome(
        self,
        plan: dict[str, object],
        discovered_new_behavior: bool,
        semantic_trace: dict[str, object] | None = None,
        havoc_trace: dict[str, object] | None = None,
    ) -> None:
        mode = str(plan.get("mode", "static"))
        self._recent_results.append((mode, discovered_new_behavior))
        self.payoff_tracker.record_mutation_outcome(
            plan=plan,
            discovered_new_behavior=discovered_new_behavior,
            semantic_trace=semantic_trace,
            havoc_trace=havoc_trace,
        )

    def record_training(self, sample_count: int, loss: float | None = None) -> None:
        self.training_samples_seen = max(self.training_samples_seen, max(0, sample_count))
        self.training_rounds += 1
        self.last_training_loss = loss

    def load_runtime_metadata(self, metadata: dict | None) -> None:
        if not metadata:
            return
        self.training_samples_seen = int(metadata.get("training_samples_seen", 0))
        self.training_rounds = int(metadata.get("training_rounds", 0))
        loss = metadata.get("last_training_loss")
        self.last_training_loss = float(loss) if isinstance(loss, (int, float)) else None

    def export_runtime_metadata(self) -> dict[str, int | float | None]:
        return {
            "training_samples_seen": self.training_samples_seen,
            "training_rounds": self.training_rounds,
            "last_training_loss": self.last_training_loss,
        }

    def export_mutation_stats(self) -> dict[str, object]:
        return self.payoff_tracker.export_mutation_stats()

    def get_field_importance(self, seed: bytes) -> list[int]:
        return identify_hot_bytes(self.model, seed, device=self.device)

    def get_hot_bytes(self, seed: bytes) -> list[int]:
        try:
            x = self._encode(seed)
            _, confidence = self.model(x)
            if self.trust_gate(confidence.item()):
                return self.get_field_importance(seed)
        except Exception:
            pass
        return []

    def _encode(self, seed: bytes):
        import torch

        max_len = CoverageSurrogate.MAX_LEN
        padded = list(seed[:max_len]) + [0] * (max_len - len(seed))
        return torch.tensor([padded], dtype=torch.long, device=self.device)

    def _make_static_plan(self, seed: bytes) -> dict[str, object]:
        plan = self.payoff_tracker.plan(seed, base_blend=1.0)
        plan.update({
            "mode": "static",
            "confidence": 0.0,
            "blend": 0.0,
            "reason": "fallback",
        })
        return plan

    def _make_plan(self, seed: bytes, confidence_score: float) -> dict[str, object]:
        if not self.trust_gate(confidence_score):
            return self._static_reason(seed, "low_confidence", confidence_score)

        if self.training_samples_seen < self.WARMUP_SAMPLES:
            return self._static_reason(seed, "undertrained_samples", confidence_score)

        if self.training_rounds < self.WARMUP_TRAINING_ROUNDS:
            return self._static_reason(seed, "undertrained_rounds", confidence_score)

        recent_factor = self._recent_performance_factor()
        if recent_factor <= 0.0:
            return self._static_reason(seed, "recent_underperformance", confidence_score)

        confidence_factor = self._confidence_factor(confidence_score)
        blend = min(
            self.MAX_GUIDED_BLEND,
            max(self.MIN_GUIDED_BLEND, confidence_factor * recent_factor),
        )
        plan = self.payoff_tracker.plan(seed, base_blend=blend)
        plan.update({
            "mode": "guided",
            "confidence": confidence_score,
            "blend": blend,
            "reason": "hybrid_guidance",
        })
        return plan

    def _static_reason(
        self,
        seed: bytes,
        reason: str,
        confidence_score: float,
    ) -> dict[str, object]:
        plan = self.payoff_tracker.plan(seed, base_blend=1.0)
        plan.update({
            "mode": "static",
            "confidence": confidence_score,
            "blend": 0.0,
            "reason": reason,
        })
        return plan

    def _recent_performance_factor(self) -> float:
        guided = [hit for mode, hit in self._recent_results if mode == "guided"]
        static = [hit for mode, hit in self._recent_results if mode == "static"]

        if len(guided) < self.MIN_MODE_SAMPLES or len(static) < self.MIN_MODE_SAMPLES:
            return 0.5

        guided_rate = sum(guided) / len(guided)
        static_rate = sum(static) / len(static)
        delta = guided_rate - static_rate

        if delta <= -0.20:
            return 0.0
        if delta < 0.0:
            return 0.25
        if delta >= 0.20:
            return 1.0
        return 0.5 + (delta / 0.20) * 0.5

    def _confidence_factor(self, confidence_score: float) -> float:
        threshold = 0.75
        if confidence_score <= threshold:
            return 0.0
        span = max(1e-6, 1.0 - threshold)
        return min(1.0, (confidence_score - threshold) / span)
