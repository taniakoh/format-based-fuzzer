"""
Tier 1 — Structural Mutations.

For JSON targets this tier adds/removes/nests keys.  IP address strings have
no nested structure, so this module is a transparent pass-through; it exists
so the main loop can always instantiate a Tier 1 mutator without branching on
the format.
"""


class StructureMutator:
    """Pass-through structural mutator for non-JSON formats (IPv4 / IPv6)."""

    def mutate(self, data: bytes) -> bytes:
        return data
