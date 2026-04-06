"""
Phase 2 — Surrogate model training loop with checkpoint save/load.

The model is trained incrementally as new behaviors are discovered.
Checkpoints are saved to models/<target>_surrogate.pt so training
persists across fuzzing runs.

Requires: torch>=2.2.0
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent.parent


def _normalize_seed(seed: bytes, max_len: int) -> list[int]:
    """
    Encode seed bytes for model input.

    Keeps printable ASCII (0x20–0x7e) as-is; maps everything else to 0
    so the model sees a clean representation matching what the parser
    actually receives (havoc mutations can inject non-ASCII garbage that
    the parser never meaningfully processes).
    Pads or truncates to exactly max_len bytes.
    """
    normalized = [b if 0x20 <= b <= 0x7e else 0 for b in seed[:max_len]]
    normalized += [0] * max(0, max_len - len(seed))
    return normalized


MODELS_DIR = _HERE / "models"
CONFIDENCE_LOSS_WEIGHT = 0.25


def get_checkpoint_path(target: str) -> Path:
    return MODELS_DIR / f"{target}_surrogate.pt"


def save_checkpoint(model, target: str, metadata: dict | None = None) -> None:
    """Save model weights to disk."""
    try:
        import torch
        MODELS_DIR.mkdir(exist_ok=True)
        path = get_checkpoint_path(target)
        payload = {"model_state_dict": model.state_dict()}
        optimizer = getattr(model, "_optimizer", None)
        if optimizer is not None:
            payload["optimizer_state_dict"] = optimizer.state_dict()
        scheduler = getattr(model, "_scheduler", None)
        if scheduler is not None:
            payload["scheduler_state_dict"] = scheduler.state_dict()
        if metadata:
            payload["metadata"] = metadata
        torch.save(payload, path)
        print(f"[DL] Checkpoint saved → {path}")
    except Exception as e:
        print(f"[DL] Save failed: {e}")


def load_checkpoint(model, target: str, device: str) -> dict:
    """
    Load model weights from disk if a checkpoint exists.
    Returns {"loaded": bool, "metadata": dict}.
    """
    try:
        import torch
        path = get_checkpoint_path(target)
        if not path.exists():
            print(f"[DL] No checkpoint found at {path} — starting fresh")
            return {"loaded": False, "metadata": {}}
        state = torch.load(path, map_location=device)
        model_state = state
        if isinstance(state, dict) and "model_state_dict" in state:
            model_state = state["model_state_dict"]
        model.load_state_dict(model_state)
        optimizer = getattr(model, "_optimizer", None)
        if (
            optimizer is not None
            and isinstance(state, dict)
            and "optimizer_state_dict" in state
        ):
            optimizer.load_state_dict(state["optimizer_state_dict"])
        scheduler = getattr(model, "_scheduler", None)
        if (
            scheduler is not None
            and isinstance(state, dict)
            and "scheduler_state_dict" in state
        ):
            scheduler.load_state_dict(state["scheduler_state_dict"])
        print(f"[DL] Checkpoint loaded ← {path}")
        metadata = state.get("metadata", {}) if isinstance(state, dict) else {}
        return {"loaded": True, "metadata": metadata}
    except Exception as e:
        print(f"[DL] Load failed ({e}) — starting fresh")
        return {"loaded": False, "metadata": {}}


def _build_confidence_targets(coverage, target):
    """Score confidence by top-k overlap between predicted and true coverage."""
    import torch

    with torch.no_grad():
        target_counts = target.sum(dim=1).to(dtype=torch.int64)
        confidence_targets = torch.zeros(
            target.size(0), 1, device=target.device, dtype=coverage.dtype
        )

        for idx in range(target.size(0)):
            k = max(1, int(target_counts[idx].item()))
            topk = torch.topk(coverage[idx], k=k).indices
            overlap = target[idx, topk].sum()
            confidence_targets[idx, 0] = overlap / float(k)

    return confidence_targets


def compute_misprediction_rate(
    model,
    corpus_data: list[tuple[bytes, list[int]]],
    device: str | None = None,
) -> float:
    """
    Fraction of inputs where the surrogate mispredicts at least one coverage bit.

    A prediction is 'wrong' for a given input if any bit differs between the
    thresholded model output (>0.5) and the true coverage label.
    Returns 0.0 when torch is unavailable or corpus_data is empty.
    """
    try:
        import torch
        from dl.surrogate import CoverageSurrogate, get_device
    except ImportError:
        return 0.0

    if not corpus_data:
        return 0.0

    if device is None:
        device = get_device()

    MAX_LEN = CoverageSurrogate.MAX_LEN
    COV_DIM = CoverageSurrogate.COV_DIM

    model.eval()
    total_bit_errors = 0
    total_bits = 0
    with torch.no_grad():
        for seed, positions in corpus_data:
            padded = _normalize_seed(seed, MAX_LEN)
            x = torch.tensor([padded], dtype=torch.long, device=device)
            coverage, _ = model(x)
            pred_bits = (coverage.squeeze() > 0.5).tolist()
            true_bits = [False] * COV_DIM
            for pos in positions:
                true_bits[pos % COV_DIM] = True
            total_bit_errors += sum(p != t for p, t in zip(pred_bits, true_bits))
            total_bits += COV_DIM

    return total_bit_errors / total_bits if total_bits > 0 else 0.0


def train(model, corpus_data: list[tuple[bytes, list[int]]], epochs: int = 5,
          lr: float = 1e-3, device: str | None = None,
          optimizer=None, batch_size: int = 32,
          fixed_lr: bool = False) -> float:
    """
    Train the surrogate model on observed (seed, bitmap_positions) pairs.

    Parameters
    ----------
    model        : CoverageSurrogate instance
    corpus_data  : list of (seed_bytes, list_of_set_bitmap_positions)
    epochs       : training epochs per call
    lr           : learning rate
    device       : 'cpu' or 'cuda' — auto-detected if None

    Returns
    -------
    Final mean loss (for logging).
    """
    try:
        import torch
        import torch.nn as nn
        from torch.optim.lr_scheduler import CosineAnnealingLR
        from torch.utils.data import DataLoader, TensorDataset
        from dl.surrogate import CoverageSurrogate, get_device
    except ImportError:
        return 0.0  # torch not available

    if device is None:
        device = get_device()

    if not corpus_data:
        return 0.0

    MAX_LEN = CoverageSurrogate.MAX_LEN
    COV_DIM = CoverageSurrogate.COV_DIM
    batch_size = max(1, min(batch_size, len(corpus_data)))

    encoded_inputs = []
    encoded_targets = []
    for seed, positions in corpus_data:
        encoded_inputs.append(_normalize_seed(seed, MAX_LEN))

        target = [0.0] * COV_DIM
        for pos in positions:
            target[pos % COV_DIM] = 1.0
        encoded_targets.append(target)

    inputs = torch.tensor(encoded_inputs, dtype=torch.long)
    targets = torch.tensor(encoded_targets, dtype=torch.float32)
    dataloader = DataLoader(
        TensorDataset(inputs, targets),
        batch_size=batch_size,
        shuffle=True,
    )

    model.to(device)
    model.train()
    if optimizer is None:
        optimizer = getattr(model, "_optimizer", None)
    if optimizer is None:
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        model._optimizer = optimizer
    scheduler = None if fixed_lr else getattr(model, "_scheduler", None)
    if scheduler is None and not fixed_lr:
        scheduler = CosineAnnealingLR(optimizer, T_max=max(1, epochs), eta_min=lr * 0.01)
        model._scheduler = scheduler
    coverage_loss_fn = nn.BCELoss()
    confidence_loss_fn = nn.MSELoss()

    final_loss = 0.0
    for epoch in range(epochs):
        epoch_loss = 0.0
        sample_count = 0
        for x, target in dataloader:
            x = x.to(device)
            target = target.to(device)
            optimizer.zero_grad()
            coverage, confidence = model(x)
            coverage_loss = coverage_loss_fn(coverage, target)
            confidence_target = _build_confidence_targets(coverage, target)
            confidence_loss = confidence_loss_fn(confidence, confidence_target)
            loss = coverage_loss + (CONFIDENCE_LOSS_WEIGHT * confidence_loss)
            loss.backward()
            optimizer.step()
            batch_samples = x.size(0)
            epoch_loss += loss.item() * batch_samples
            sample_count += batch_samples

        final_loss = epoch_loss / sample_count if sample_count else 0.0
        if scheduler is not None:
            scheduler.step()

    model.eval()
    return final_loss
