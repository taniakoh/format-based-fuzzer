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


def get_checkpoint_path(target: str) -> Path:
    return MODELS_DIR / f"{target}_surrogate.pt"


def save_checkpoint(model, target: str) -> None:
    """Save model weights to disk."""
    try:
        import torch
        MODELS_DIR.mkdir(exist_ok=True)
        path = get_checkpoint_path(target)
        torch.save(model.state_dict(), path)
        print(f"[DL] Checkpoint saved → {path}")
    except Exception as e:
        print(f"[DL] Save failed: {e}")


def load_checkpoint(model, target: str, device: str) -> bool:
    """
    Load model weights from disk if a checkpoint exists.
    Returns True if loaded, False if starting fresh.
    """
    try:
        import torch
        path = get_checkpoint_path(target)
        if not path.exists():
            print(f"[DL] No checkpoint found at {path} — starting fresh")
            return False
        state = torch.load(path, map_location=device)
        model.load_state_dict(state)
        print(f"[DL] Checkpoint loaded ← {path}")
        return True
    except Exception as e:
        print(f"[DL] Load failed ({e}) — starting fresh")
        return False


def train(model, corpus_data: list[tuple[bytes, list[int]]], epochs: int = 5,
          lr: float = 1e-3, device: str | None = None) -> float:
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
        from dl.surrogate import CoverageSurrogate, get_device
    except ImportError:
        return 0.0  # torch not available

    if device is None:
        device = get_device()

    if not corpus_data:
        return 0.0

    MAX_LEN = CoverageSurrogate.MAX_LEN
    COV_DIM = CoverageSurrogate.COV_DIM

    model.to(device)
    model.train()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.BCELoss()

    final_loss = 0.0
    for epoch in range(epochs):
        epoch_loss = 0.0
        for seed, positions in corpus_data:
            padded = list(seed[:MAX_LEN]) + [0] * (MAX_LEN - len(seed))
            x = torch.tensor([padded], dtype=torch.long, device=device)

            target = torch.zeros(1, COV_DIM, device=device)
            for pos in positions:
                if pos < COV_DIM:
                    target[0, pos] = 1.0

            optimizer.zero_grad()
            coverage, _ = model(x)
            loss = loss_fn(coverage, target)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        final_loss = epoch_loss / len(corpus_data)

    model.eval()
    return final_loss
