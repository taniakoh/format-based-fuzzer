"""
Module 6 — Neural Surrogate Model (Phase 2).

Predicts compressed coverage representation from input bytes.
Swap StaticScheduler for DLScheduler in main.py to activate.

Device selection: automatically uses CUDA if available, otherwise CPU.

Requires: torch>=2.2.0
"""

# ── Device helper ──────────────────────────────────────────────────────────────

def get_device() -> str:
    """Return 'cuda' if a CUDA-capable GPU is available, else 'cpu'."""
    try:
        import torch
        device = "cuda" if torch.cuda.is_available() else "cpu"
        if device == "cuda":
            print(f"[DL] Using CUDA: {torch.cuda.get_device_name(0)}")
        else:
            print("[DL] CUDA not available — using CPU")
        return device
    except ImportError:
        return "cpu"


# ── Model ──────────────────────────────────────────────────────────────────────

try:
    import torch
    import torch.nn as nn

    class CoverageSurrogate(nn.Module):
        """
        Input  : flattened seed bytes padded/truncated to MAX_LEN
        Output : predicted coverage (COV_DIM sigmoid values) + confidence scalar
        """
        MAX_LEN = 256   # IP addresses are short; 256 bytes is generous
        COV_DIM = 128   # compressed coverage representation

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
            emb = self.embed(x)          # (batch, MAX_LEN, 8)
            h = self.encoder(emb)
            coverage = torch.sigmoid(self.coverage_head(h))
            confidence = torch.sigmoid(self.confidence_head(h))
            return coverage, confidence

    def identify_hot_bytes(model: "CoverageSurrogate", seed: bytes,
                           device: str | None = None) -> list[int]:
        """
        Compute gradient of predicted coverage w.r.t. each input byte position.
        Returns sorted list of byte indices most likely to increase coverage.
        """
        if device is None:
            device = get_device()
        MAX_LEN = CoverageSurrogate.MAX_LEN
        padded = list(seed[:MAX_LEN]) + [0] * (MAX_LEN - len(seed))
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
    # torch not installed — Phase 2 features unavailable
    class CoverageSurrogate:  # type: ignore[no-redef]
        pass

    def identify_hot_bytes(model, seed: bytes, device=None) -> list[int]:  # type: ignore[misc]
        return []


# ── DL Scheduler (Phase 2) ────────────────────────────────────────────────────

class DLScheduler:
    """
    Replaces StaticScheduler.  Provides DL-learned operator weights and
    seed priorities.  Falls back to static priors when model is untrustworthy.

    Device is auto-detected (CUDA if available, else CPU).
    """

    def __init__(self, model, trust_gate, format_config: dict,
                 device: str | None = None):
        self.model = model
        self.trust_gate = trust_gate
        self.static_weights = format_config["havoc_operators"]
        self.device = device if device is not None else get_device()
        if hasattr(self.model, "to"):
            self.model.to(self.device)

    def get_operator_weights(self, seed: bytes) -> dict[str, float]:
        try:
            x = self._encode(seed)
            _, confidence = self.model(x)
            if self.trust_gate(confidence.item()):
                return self._learned_weights()
        except Exception:
            pass
        return self.static_weights

    def get_seed_priority(self, seed: bytes) -> float:
        try:
            x = self._encode(seed)
            _, confidence = self.model(x)
            return float(confidence.item())
        except Exception:
            return 1.0

    def get_field_importance(self, seed: bytes) -> list[int]:
        return identify_hot_bytes(self.model, seed, device=self.device)

    def _encode(self, seed: bytes):
        import torch
        MAX_LEN = CoverageSurrogate.MAX_LEN
        padded = list(seed[:MAX_LEN]) + [0] * (MAX_LEN - len(seed))
        return torch.tensor([padded], dtype=torch.long, device=self.device)

    def _learned_weights(self) -> dict[str, float]:
        ops = list(self.static_weights.keys())
        w = 1.0 / len(ops)
        return {op: w for op in ops}
