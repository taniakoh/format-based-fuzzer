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
        self.edge_count = 0  # unique bitmap slots seen at least once

    def is_interesting(self, bitmap: bytes) -> bool:
        """Return True if this run discovered new coverage."""
        if self.use_afl_hit_count_buckets:
            return self._is_interesting_afl(bitmap)

        new_edges = False
        for i, byte in enumerate(bitmap):
            if byte and not self.global_bitmap[i]:
                self.global_bitmap[i] = byte
                self.edge_count += 1
                new_edges = True
        return new_edges

    def _is_interesting_afl(self, bitmap: bytes) -> bool:
        """Apply AFL-style virgin-bitmap novelty to a raw trace bitmap."""
        new_edges = False
        for i, byte in enumerate(bitmap):
            bucketed = _COUNT_CLASS_LOOKUP[byte]
            if not bucketed:
                continue

            if bucketed & self.virgin_bitmap[i]:
                # Count every new hit-count bucket as a new event, matching AFL
                # semantics where reaching edge X for the 2nd, 4th, 8th... time
                # is treated as novel coverage distinct from the first hit.
                self.global_bitmap[i] = 1
                self.virgin_bitmap[i] &= ~bucketed
                self.edge_count += 1
                new_edges = True
        return new_edges

    def coverage_summary(self) -> dict:
        return {
            "behaviors_covered": self.edge_count,
            "bitmap_density": self.edge_count / BITMAP_SIZE,
        }
