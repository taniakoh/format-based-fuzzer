from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import main
from evaluation.collect_metrics import MetricsCollector
from fuzzer.executor import BugType, RunResult
from fuzzer.oracle import OracleVerdict


def _result(
    *,
    bug_type: str,
    exception: str,
    traceback_text: str = "",
    parser_bug_type: str | None = None,
    parser_filename: str = "",
    parser_lineno: int | None = None,
) -> RunResult:
    return RunResult(
        input_str="seed",
        bug_type=bug_type,
        exit_code=None,
        stdout="",
        stderr="",
        exception_msg=exception,
        traceback=traceback_text,
        oracle=OracleVerdict(False, None, "test"),
        parser_reported_bug_type=parser_bug_type,
        parser_reported_message=exception,
        parser_reported_exc_type="FunctionalBug" if parser_bug_type else "",
        parser_reported_filename=parser_filename,
        parser_reported_lineno=parser_lineno,
    )


class MetricsSemanticsTests(unittest.TestCase):
    def test_live_collector_excludes_oracle_mismatch_from_unique_bugs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collector = MetricsCollector("ipv4", out_dir=Path(tmp))
            collector.write_fuzzer_config({"executor_mode": "Linux"})
            collector.record_execution(
                b"case",
                _result(
                    bug_type=BugType.ORACLE_MISMATCH,
                    exception="oracle mismatch",
                ),
                b"\x00" * 8,
            )
            collector.finalize()

            unique_bugs = json.loads((Path(tmp) / "unique_bugs.json").read_text(encoding="utf-8"))
            unique_findings = json.loads((Path(tmp) / "unique_findings.json").read_text(encoding="utf-8"))
            summary = json.loads((Path(tmp) / "bug_coverage_summary.json").read_text(encoding="utf-8"))

            self.assertEqual(unique_bugs["unique_bug_count"], 0)
            self.assertEqual(unique_findings["unique_finding_count"], 1)
            self.assertEqual(summary["totals"]["unique_real_bugs"], 0)
            self.assertEqual(summary["totals"]["unique_findings"], 1)

    def test_live_collector_keeps_unique_findings_separate_from_unique_bugs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collector = MetricsCollector("ipv4", out_dir=Path(tmp))
            collector.write_fuzzer_config({"executor_mode": "Linux"})

            tb_one = (
                "Traceback (most recent call last):\n"
                '  File "parser.py", line 10, in run\n'
                "FunctionalBug: first message"
            )
            tb_two = (
                "Traceback (most recent call last):\n"
                '  File "parser.py", line 10, in run\n'
                "FunctionalBug: second message"
            )
            for traceback_text, exception in (
                (tb_one, "FunctionalBug: first message"),
                (tb_two, "FunctionalBug: second message"),
            ):
                collector.record_execution(
                    b"case",
                    _result(
                        bug_type=BugType.FUNCTIONAL,
                        exception=exception,
                        traceback_text=traceback_text,
                        parser_bug_type=BugType.FUNCTIONAL,
                        parser_filename="parser.py",
                        parser_lineno=10,
                    ),
                    b"\x01" * 8,
                )

            collector.finalize()

            unique_bugs = json.loads((Path(tmp) / "unique_bugs.json").read_text(encoding="utf-8"))
            unique_findings = json.loads((Path(tmp) / "unique_findings.json").read_text(encoding="utf-8"))
            stats_text = (Path(tmp) / "stats.txt").read_text(encoding="utf-8")

            self.assertEqual(unique_bugs["unique_bug_count"], 1)
            self.assertEqual(unique_findings["unique_finding_count"], 2)
            self.assertIn("Coverage slots", stats_text)
            self.assertNotIn("Coverage percent:", stats_text)

    def test_atheris_postprocess_uses_parser_only_unique_bug_policy_and_line_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            results_dir = Path(tmp) / "json"
            crashes_dir = results_dir / "crashes"
            crashes_dir.mkdir(parents=True)

            for name in ("mismatch", "site-a", "site-b"):
                (crashes_dir / name).write_bytes(name.encode("utf-8"))

            (results_dir / "coverage_replay.json").write_text(
                json.dumps(
                    {
                        "final": {
                            "lines_hit": 30,
                            "lines_total": 60,
                            "line_coverage_percent": 50.0,
                        },
                        "rows": [],
                    }
                ),
                encoding="utf-8",
            )

            original = main._classify_atheris_crash

            def fake_classify(_target: str, crash_file: Path) -> dict[str, object]:
                if crash_file.name == "mismatch":
                    return {
                        "bug_type": BugType.ORACLE_MISMATCH,
                        "exception": "oracle mismatch",
                        "traceback": "",
                        "exc_type": "",
                    }
                if crash_file.name == "site-a":
                    return {
                        "bug_type": BugType.FUNCTIONAL,
                        "exception": "FunctionalBug: first",
                        "traceback": (
                            "Traceback (most recent call last):\n"
                            '  File "parser.py", line 22, in run\n'
                            "FunctionalBug: first"
                        ),
                        "exc_type": "FunctionalBug",
                    }
                return {
                    "bug_type": BugType.FUNCTIONAL,
                    "exception": "FunctionalBug: second",
                    "traceback": (
                        "Traceback (most recent call last):\n"
                        '  File "parser.py", line 22, in run\n'
                        "FunctionalBug: second"
                    ),
                    "exc_type": "FunctionalBug",
                }

            try:
                main._classify_atheris_crash = fake_classify
                main._postprocess_atheris_results("json", results_dir, crashes_dir, 12.5)
            finally:
                main._classify_atheris_crash = original

            unique_bugs = json.loads((results_dir / "unique_bugs.json").read_text(encoding="utf-8"))
            unique_findings = json.loads((results_dir / "unique_findings.json").read_text(encoding="utf-8"))
            summary = json.loads((results_dir / "bug_coverage_summary.json").read_text(encoding="utf-8"))
            bugs_jsonl = (results_dir / "bugs.jsonl").read_text(encoding="utf-8").splitlines()

            self.assertEqual(unique_bugs["unique_bug_count"], 1)
            self.assertIsNone(unique_bugs["parser_site_unique_bug_count"])
            self.assertFalse(unique_bugs["parser_site_unique_bug_count_supported"])
            self.assertEqual(unique_findings["unique_finding_count"], 3)
            self.assertEqual(len(bugs_jsonl), 3)
            self.assertEqual(summary["totals"]["unique_real_bugs"], 1)
            self.assertEqual(summary["totals"]["unique_findings"], 3)
            self.assertEqual(summary["run_scalars"]["lines_hit"], 30)
            self.assertEqual(summary["run_scalars"]["lines_total"], 60)
            self.assertEqual(summary["run_scalars"]["line_coverage_percent"], 50.0)


if __name__ == "__main__":
    unittest.main()
