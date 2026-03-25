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


def train(model, corpus_data: list[tuple[bytes, list[int]]], epochs: int = 5,
          lr: float = 1e-3, device: str | None = None,
          optimizer=None, batch_size: int = 32) -> float:
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
        padded = list(seed[:MAX_LEN]) + [0] * max(0, MAX_LEN - len(seed))
        encoded_inputs.append(padded)

        target = [0.0] * COV_DIM
        for pos in positions:
            if 0 <= pos < COV_DIM:
                target[pos] = 1.0
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

    model.eval()
    return final_loss
