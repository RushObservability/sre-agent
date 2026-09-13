import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "security_report", Path(__file__).with_name("security-report.py")
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class SecurityReportTests(unittest.TestCase):
    def summarize(self, value, outcome="success"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text(json.dumps(value))
            return report.summarize(path, outcome)

    def test_clean_scan(self):
        text, warning = self.summarize({"Results": [{"Vulnerabilities": []}]})
        self.assertIn("No fixable high or critical", text)
        self.assertIsNone(warning)

    def test_findings_do_not_raise(self):
        text, warning = self.summarize(
            {"Results": [{"Vulnerabilities": [
                {"Severity": "CRITICAL"}, {"Severity": "HIGH"}, {"Severity": "HIGH"}
            ]}]}, "failure"
        )
        self.assertIn("1 critical, 2 high", text)
        self.assertIsNotNone(warning)

    def test_findings_are_reported_even_if_action_returns_success(self):
        _, warning = self.summarize({"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]})
        self.assertIn("1 high", warning)

    def test_failure_with_empty_report_is_not_clean(self):
        text, warning = self.summarize({"Results": [{}]}, "failure")
        self.assertIn("did not complete successfully", text)
        self.assertIsNotNone(warning)

    def test_missing_and_malformed_reports_are_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"
            for contents in [None, "not json"]:
                if contents is not None:
                    path.write_text(contents)
                text, warning = report.summarize(path, "failure")
                self.assertIn("not a clean result", text)
                self.assertIsNotNone(warning)
        for value in [{}, {"Results": []}, {"Results": "invalid"},
                      {"Results": [None]}, {"Results": [{"Vulnerabilities": "bad"}]},
                      {"Results": [{"Vulnerabilities": {}}]}]:
            text, warning = self.summarize(value)
            self.assertIn("not a clean result", text)
            self.assertIsNotNone(warning)

    def test_cli_writes_artifact_and_job_summary_without_blocking_release(self):
        script = Path(__file__).with_name("security-report.py").resolve()
        for value in [None, {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]}]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "report.json"
                if value is not None:
                    path.write_text(json.dumps(value))
                job_summary = Path(directory) / "job-summary.md"
                result = subprocess.run(
                    [sys.executable, str(script), str(path)], cwd=directory,
                    env={**os.environ, "SCAN_OUTCOME": "failure", "GITHUB_STEP_SUMMARY": str(job_summary)},
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("::warning title=Container security report::", result.stdout)
                self.assertEqual(
                    job_summary.read_text(),
                    (Path(directory) / "vulnerability-summary.md").read_text(),
                )


if __name__ == "__main__":
    unittest.main()
