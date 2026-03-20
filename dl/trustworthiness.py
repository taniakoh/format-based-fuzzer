"""
Trustworthiness gate for the DL surrogate (Phase 2).

Only use gradient guidance when the model is sufficiently confident.
Falls back to Havoc with static priors otherwise.
"""

CONFIDENCE_THRESHOLD = 0.75


def is_trustworthy(confidence_score: float) -> bool:
    return confidence_score >= CONFIDENCE_THRESHOLD
