"""Summarize advisory Trivy findings without treating scan errors as clean scans."""

import json
import os
from pathlib import Path
import sys


def summarize(report_path, outcome):
    heading = "## Container vulnerability report\n\n"
    policy = (
        "Policy: fixable HIGH and CRITICAL vulnerabilities, advisory only. "
        "CVE findings do not block publication.\n\n"
    )
    try:
        report = json.loads(Path(report_path).read_text())
        results = report["Results"]
        if not isinstance(results, list) or not results:
            raise ValueError("no scan targets")
        counts = {"HIGH": 0, "CRITICAL": 0}
        for result in results:
            findings = result.get("Vulnerabilities")
            if findings is None:
                findings = []
            if not isinstance(findings, list):
                raise ValueError("invalid findings")
            for finding in findings:
                severity = finding["Severity"]
                if severity in counts:
                    counts[severity] += 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        message = "Scan unavailable: report missing, invalid, or without scan targets."
        return heading + policy + message + " This is not a clean result.\n", message

    total = sum(counts.values())
    if total:
        status = f"Findings reported: {counts['CRITICAL']} critical, {counts['HIGH']} high."
        warning = status
    elif outcome != "success":
        status = "Scan did not complete successfully. Do not treat this as a clean result."
        warning = status
    else:
        status = "No fixable high or critical vulnerabilities reported."
        warning = None
    summary = heading + policy + status + "\n\n"
    summary += "| Severity | Findings |\n|---|---:|\n"
    summary += f"| Critical | {counts['CRITICAL']} |\n| High | {counts['HIGH']} |\n\n"
    summary += (
        "See the JSON report for affected packages and fixed versions. "
        "This policy excludes unfixed and lower-severity findings. "
        "The SPDX SBOM is published separately.\n"
    )
    return summary, warning


def main():
    summary, warning = summarize(sys.argv[1], os.environ.get("SCAN_OUTCOME", "unknown"))
    Path("vulnerability-summary.md").write_text(summary)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a") as output:
            output.write(summary)
    print(summary)
    if warning:
        # Warning text is fixed text plus counts, never package-controlled content.
        print(f"::warning title=Container security report::{warning}")


if __name__ == "__main__":
    main()
