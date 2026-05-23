# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Observability dashboard: generates reports for engineering leaders."""
from __future__ import annotations

import json  # noqa: TID251
import logging
from datetime import datetime, timezone
from pathlib import Path

from orchestrator import RemediationTask, SessionStatus

logger = logging.getLogger(__name__)


def generate_markdown_report(
    tasks: list[RemediationTask],
    scan_timestamp: str | None = None,
    repo: str = "raspberry-apple/superset",
) -> str:
    """Generate a Markdown report summarizing the remediation pipeline run."""
    timestamp = scan_timestamp or datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    total = len(tasks)
    succeeded = [t for t in tasks if t.status == SessionStatus.SUCCEEDED]
    failed = [t for t in tasks if t.status == SessionStatus.FAILED]
    timed_out = [t for t in tasks if t.status == SessionStatus.TIMED_OUT]
    running = [t for t in tasks if t.status == SessionStatus.RUNNING]
    pending = [t for t in tasks if t.status == SessionStatus.PENDING]

    # Compute average duration for completed tasks
    completed = succeeded + failed + timed_out
    durations = [
        t.duration_seconds
        for t in completed
        if t.duration_seconds
    ]
    avg_duration = sum(durations) / len(durations) if durations else 0

    success_rate = f"{len(succeeded) / total * 100:.0f}%" if total > 0 else "N/A"

    # Build the report
    lines = [
        "# 🛡️ Vulnerability Remediation Report",
        "",
        f"**Repository:** [{repo}](https://github.com/{repo})",
        f"**Scan Time:** {timestamp}",
        "**Pipeline Version:** 1.0.0",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Vulnerabilities | {total} |",
        f"| Remediated | {len(succeeded)} |",
        f"| Failed | {len(failed)} |",
        f"| Timed Out | {len(timed_out)} |",
        f"| In Progress | {len(running)} |",
        f"| Pending | {len(pending)} |",
        f"| **Success Rate** | **{success_rate}** |",
        f"| Avg. Remediation Time | {avg_duration / 60:.1f} min |",
        "",
        "---",
        "",
    ]

    # Severity breakdown
    severity_counts: dict[str, int] = {}
    for task in tasks:
        sev = task.vulnerability.severity.value.upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.extend([
        "## Severity Breakdown",
        "",
        "| Severity | Count | Remediated |",
        "|----------|-------|------------|",
    ])
    for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
        count = severity_counts.get(sev, 0)
        remediated = sum(
            1
            for t in succeeded
            if t.vulnerability.severity.value.upper() == sev
        )
        if count > 0:
            lines.append(f"| {sev} | {count} | {remediated} |")
    lines.extend(["", "---", ""])

    # Ecosystem breakdown
    python_tasks = [t for t in tasks if t.vulnerability.ecosystem == "python"]
    npm_tasks = [t for t in tasks if t.vulnerability.ecosystem == "npm"]
    py_ok = sum(
        1 for t in python_tasks
        if t.status == SessionStatus.SUCCEEDED
    )
    npm_ok = sum(
        1 for t in npm_tasks
        if t.status == SessionStatus.SUCCEEDED
    )
    lines.extend([
        "## Ecosystem Breakdown",
        "",
        "| Ecosystem | Vulnerabilities | Remediated |",
        "|-----------|----------------|------------|",
        f"| Python (pip) | {len(python_tasks)} | {py_ok} |",
        f"| JavaScript (npm) | {len(npm_tasks)} | {npm_ok} |",
        "",
        "---",
        "",
    ])

    # Detailed task table
    lines.extend([
        "## Task Details",
        "",
        "| # | Package | CVE | Severity | Status | Issue | PR | Devin Session |",
        "|---|---------|-----|----------|--------|-------|----|---------------|",
    ])
    for i, task in enumerate(tasks, 1):
        v = task.vulnerability
        status_emoji = {
            SessionStatus.SUCCEEDED: "✅",
            SessionStatus.FAILED: "❌",
            SessionStatus.TIMED_OUT: "⏱️",
            SessionStatus.RUNNING: "🔄",
            SessionStatus.PENDING: "⏳",
        }.get(task.status, "❓")

        issue_link = (
            f"[#{task.github_issue_number}]({task.github_issue_url})"
            if task.github_issue_number
            else "—"
        )
        pr_link = (
            f"[PR]({task.pull_request_url})" if task.pull_request_url else "—"
        )
        session_link = (
            f"[View]({task.devin_session_url})"
            if task.devin_session_url
            else "—"
        )

        sev_str = v.severity.value.upper()
        status_str = f"{status_emoji} {task.status.value}"
        row = (
            f"| {i} | `{v.package}` | `{v.cve_id}` "
            f"| {sev_str} | {status_str} "
            f"| {issue_link} | {pr_link} "
            f"| {session_link} |"
        )
        lines.append(row)

    lines.extend(["", "---", ""])

    # Failed tasks detail
    if failed or timed_out:
        lines.extend(["## Failures & Timeouts", ""])
        for task in failed + timed_out:
            lines.extend([
                f"### {task.vulnerability.package} ({task.vulnerability.cve_id})",
                f"- **Status:** {task.status.value}",
                f"- **Error:** {task.error_message or 'Unknown'}",
                f"- **Session:** {task.devin_session_url or 'N/A'}",
                "",
            ])
        lines.extend(["---", ""])

    # Footer
    pipeline_url = (
        f"https://github.com/{repo}"
        "/tree/master/.github/vuln-remediation"
    )
    lines.extend([
        "## How to Read This Report",
        "",
        "_This report is auto-generated by the "
        "Devin vulnerability remediation pipeline._",
        "",
        "- **Success Rate** = remediated / total "
        "vulnerabilities with available fixes",
        "- **Avg. Remediation Time** = mean duration "
        "of completed Devin sessions",
        "- Failures typically indicate breaking API "
        "changes requiring manual review",
        "- Each Devin session link provides "
        "full logs and diffs",
        "",
        "---",
        f"_Generated at {timestamp} by "
        f"[vuln-remediation-pipeline]({pipeline_url})_",
    ])

    return "\n".join(lines)


def generate_json_report(
    tasks: list[RemediationTask],
    scan_timestamp: str | None = None,
    repo: str = "raspberry-apple/superset",
) -> dict[str, object]:
    """Generate a structured JSON report."""
    timestamp = scan_timestamp or datetime.now(timezone.utc).isoformat()

    total = len(tasks)
    succeeded = sum(1 for t in tasks if t.status == SessionStatus.SUCCEEDED)
    failed = sum(1 for t in tasks if t.status == SessionStatus.FAILED)
    timed_out = sum(1 for t in tasks if t.status == SessionStatus.TIMED_OUT)

    return {
        "meta": {
            "repo": repo,
            "scan_timestamp": timestamp,
            "pipeline_version": "1.0.0",
        },
        "summary": {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
            "timed_out": timed_out,
            "success_rate": succeeded / total if total > 0 else 0,
        },
        "tasks": [t.to_dict() for t in tasks],
    }


def save_reports(
    tasks: list[RemediationTask],
    output_dir: str = "reports",
    repo: str = "raspberry-apple/superset",
) -> tuple[str, str]:
    """Save both Markdown and JSON reports. Returns (md_path, json_path)."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
    scan_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    md_path = output / f"report_{timestamp_str}.md"
    json_path = output / f"report_{timestamp_str}.json"

    md_content = generate_markdown_report(tasks, scan_ts, repo)
    md_path.write_text(md_content)

    json_content = generate_json_report(tasks, scan_ts, repo)
    json_path.write_text(json.dumps(json_content, indent=2))

    logger.info("Reports saved to %s and %s", md_path, json_path)
    return str(md_path), str(json_path)
