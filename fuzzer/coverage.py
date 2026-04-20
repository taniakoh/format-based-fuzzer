"""
Module 5 - Coverage Analyzer.

Tracks a global behavior bitmap. In fallback behavior-hash mode, a seed is
"interesting" if it sets any previously-zero bit.

For real AFL++ QEMU runs, the analyzer can instead apply AFL-style novelty
tracking on the raw trace bitmap: hit counts are bucketized and compared
against a virgin map so both new edges and newly reached hit-count buckets
count as interesting.
"""

BITMAP_SIZE = 65536
_VIRGIN_BYTE = 0xFF
_COUNT_CLASS_LOOKUP = bytes(
    [0]
    + [1]
    + [2]
    + [4]
    + [8] * 4
    + [16] * 8
    + [32] * 16
    + [64] * 96
    + [128] * 128
)


class CoverageAnalyzer:
    def __init__(self, use_afl_hit_count_buckets: bool = False):
        self.use_afl_hit_count_buckets = use_afl_hit_count_buckets
        self.global_bitmap = bytearray(BITMAP_SIZE)
        self.virgin_bitmap = bytearray([_VIRGIN_BYTE]) * BITMAP_SIZE
        self.slot_hit_counts = [0] * BITMAP_SIZE
        self.edge_count = 0  # unique bitmap slots seen at least once

    def is_interesting(self, bitmap: bytes) -> bool:
        """Return True if this run discovered new coverage."""
        return self.observe(bitmap)["is_interesting"]

    def observe(self, bitmap: bytes) -> dict[str, float | int | bool]:
        """Record one coverage observation and return novelty/rarity metadata."""
        if self.use_afl_hit_count_buckets:
            return self._observe_afl(bitmap)

        new_edges = False
        rarity_score = 0.0
        active_slots = 0
        new_slot_count = 0
        for i, byte in enumerate(bitmap):
            if not byte:
                continue

            active_slots += 1
            seen = self.slot_hit_counts[i]
            rarity_score += 1.0 / (1.0 + seen)
            self.slot_hit_counts[i] = seen + 1

            if not self.global_bitmap[i]:
                self.global_bitmap[i] = byte
                self.edge_count += 1
                new_edges = True
                new_slot_count += 1

        rarity_score += new_slot_count * 1.5
        return {
            "is_interesting": new_edges,
            "rarity_score": rarity_score,
            "active_slots": active_slots,
            "new_slots": new_slot_count,
        }

    def _observe_afl(self, bitmap: bytes) -> dict[str, float | int | bool]:
        """Apply AFL-style novelty and compute a rarity score for raw trace bitmaps."""
        new_edges = False
        rarity_score = 0.0
        active_slots = 0
        new_slot_count = 0
        for i, byte in enumerate(bitmap):
            bucketed = _COUNT_CLASS_LOOKUP[byte]
            if not bucketed:
                continue

            active_slots += 1
            seen = self.slot_hit_counts[i]
            rarity_score += 1.0 / (1.0 + seen)
            self.slot_hit_counts[i] = seen + 1

            if bucketed & self.virgin_bitmap[i]:
                # Count every new hit-count bucket as a new event, matching AFL
                # semantics where reaching edge X for the 2nd, 4th, 8th... time
                # is treated as novel coverage distinct from the first hit.
                self.global_bitmap[i] = 1
                self.virgin_bitmap[i] &= ~bucketed
                self.edge_count += 1
                new_edges = True
                new_slot_count += 1

        rarity_score += new_slot_count * 1.5
        return {
            "is_interesting": new_edges,
            "rarity_score": rarity_score,
            "active_slots": active_slots,
            "new_slots": new_slot_count,
        }

    def coverage_summary(self) -> dict:
        return {
            "behaviors_covered": self.edge_count,
            "bitmap_density": self.edge_count / BITMAP_SIZE,
        }
