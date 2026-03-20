"""
Module 5 — Coverage Analyzer.

Tracks a global behavior bitmap.  A seed is "interesting" if it sets any
previously-zero bit — i.e., it triggers a new unique parser behavior.

Because our targets are opaque PyInstaller bundles (no AFL instrumentation),
the bitmap is populated by the Executor using behavior hashing rather than
real edge-coverage bitmaps.  The CoverageAnalyzer itself is format-agnostic
and works identically whether the bitmap comes from AFL or from behavior hashes.
"""

BITMAP_SIZE = 65536


class CoverageAnalyzer:
    def __init__(self):
        self.global_bitmap = bytearray(BITMAP_SIZE)
        self.edge_count = 0        # unique "behaviors" seen

    def is_interesting(self, bitmap: bytes) -> bool:
        """Return True if this run set any previously-zero bit."""
        new_edges = False
        for i, byte in enumerate(bitmap):
            if byte and not self.global_bitmap[i]:
                self.global_bitmap[i] = byte
                self.edge_count += 1
                new_edges = True
        return new_edges

    def coverage_summary(self) -> dict:
        return {
            "behaviors_covered": self.edge_count,
            "bitmap_density": self.edge_count / BITMAP_SIZE,
        }
