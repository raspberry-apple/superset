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
"""Main entry point for the vulnerability remediation pipeline.

Usage:
    # Full pipeline: scan → create issues → trigger Devin → report
    python pipeline.py --mode full

    # Scan only: just identify vulnerabilities
    python pipeline.py --mode scan

    # Report only: generate report from previous run
    python pipeline.py --mode report --input results.json
"""

from __future__ import annotations

import argparse
import json  # noqa: TID251
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from config import PipelineConfig
from dashboard import generate_markdown_report, save_reports
from orchestrator import Orchestrator, RemediationTask, SessionStatus
from scanner import run_full_scan, Severity, Vulnerability

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("pipeline")


def _task_from_dict(
    t: dict[str, object],
) -> RemediationTask:
    """Deserialize a task dict into a RemediationTask."""
    v = t["vulnerability"]
    assert isinstance(v, dict)
    return RemediationTask(
        vulnerability=Vulnerability(
            package=str(v["package"]),
            current_version=str(v["current_version"]),
            cve_id=str(v["cve_id"]),
            severity=Severity.from_string(str(v["severity"])),
            fix_versions=list(v.get("fix_versions", [])),
            description=str(v.get("description", "")),
            ecosystem=str(v.get("ecosystem", "python")),
        ),
        github_issue_number=t.get("github_issue_number"),  # type: ignore[arg-type]
        github_issue_url=t.get("github_issue_url"),  # type: ignore[arg-type]
        devin_session_id=t.get("devin_session_id"),  # type: ignore[arg-type]
        devin_session_url=t.get("devin_session_url"),  # type: ignore[arg-type]
        pull_request_url=t.get("pull_request_url"),  # type: ignore[arg-type]
        status=SessionStatus(t.get("status", "pending")),
    )


def run_scan(config: PipelineConfig) -> list[Vulnerability]:
    """Step 1: Scan for vulnerabilities."""
    logger.info("=" * 60)
    logger.info("STEP 1: Scanning for vulnerabilities")
    logger.info("=" * 60)

    vulns = run_full_scan(
        python_requirements=config.python_requirements,
        frontend_dir=config.frontend_dir,
        severity_threshold=config.severity_threshold,
    )

    logger.info("Found %d actionable vulnerabilities:", len(vulns))
    for v in vulns:
        fix = v.recommended_fix_version or "no fix"
        logger.info(
            "  [%s] %s %s@%s → %s",
            v.severity.value.upper(),
            v.cve_id,
            v.package,
            v.current_version,
            fix,
        )

    return vulns


def run_remediation(
    config: PipelineConfig, vulns: list[Vulnerability]
) -> list[RemediationTask]:
    """Step 2-4: Create issues, start Devin sessions, monitor."""
    logger.info("=" * 60)
    logger.info("STEP 2: Creating remediation tasks")
    logger.info("=" * 60)

    orchestrator = Orchestrator(config=config)
    tasks = orchestrator.create_tasks(vulns)
    skipped = len(vulns) - len(tasks)
    logger.info(
        "Created %d remediation tasks (%d skipped: no fix)",
        len(tasks),
        skipped,
    )

    if not tasks:
        return tasks

    logger.info("=" * 60)
    logger.info("STEP 3: Creating GitHub issues and Devin sessions")
    logger.info("=" * 60)

    orchestrator.run_pipeline()

    # Print summary
    summary = orchestrator.get_results_summary()
    logger.info("=" * 60)
    logger.info("PIPELINE COMPLETE")
    logger.info("  Total: %s", summary["total_tasks"])
    logger.info("  Succeeded: %s", summary["succeeded"])
    logger.info("  Failed: %s", summary["failed"])
    logger.info("  Success Rate: %s", summary["success_rate"])
    logger.info("=" * 60)

    return tasks


def run_report(
    tasks: list[RemediationTask],
    config: PipelineConfig,
    output_dir: str = "reports",
) -> None:
    """Step 5: Generate and save reports."""
    logger.info("=" * 60)
    logger.info("STEP 4: Generating reports")
    logger.info("=" * 60)

    md_path, json_path = save_reports(tasks, output_dir, config.github_repo)
    logger.info("Markdown report: %s", md_path)
    logger.info("JSON report: %s", json_path)

    # Also print the markdown report to stdout
    md_content = generate_markdown_report(
        tasks,
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        config.github_repo,
    )
    print("\n" + md_content)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vulnerability remediation pipeline powered by Devin API"
    )
    parser.add_argument(
        "--mode",
        choices=["full", "scan", "report"],
        default="full",
        help=(
            "Pipeline mode: 'full' (scan+fix+report), "
            "'scan' (scan only), 'report' (from saved JSON)"
        ),
    )
    parser.add_argument(
        "--input",
        help="Path to JSON results file (for --mode report)",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for report output (default: reports/)",
    )
    parser.add_argument(
        "--severity",
        default="moderate",
        choices=["low", "moderate", "high", "critical"],
        help="Minimum severity threshold (default: moderate)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and create issues but skip Devin session creation",
    )
    args = parser.parse_args()

    config = PipelineConfig(severity_threshold=args.severity)

    if args.mode == "scan":
        vulns = run_scan(config)
        # Save raw scan results
        output = Path(args.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        scan_path = output / "scan_results.json"
        scan_path.write_text(json.dumps([v.to_dict() for v in vulns], indent=2))
        logger.info("Scan results saved to %s", scan_path)

    elif args.mode == "report":
        if not args.input:
            logger.error("--input required for report mode")
            sys.exit(1)
        raw = Path(args.input).read_text()
        data = json.loads(raw)  # noqa: TID251
        task_list = data.get("tasks", data) if isinstance(data, dict) else data
        tasks = [_task_from_dict(t) for t in task_list]
        run_report(tasks, config, args.output_dir)

    elif args.mode == "full":
        # Validate required env vars
        if not config.devin_api_token and not args.dry_run:
            logger.error("DEVIN_API_TOKEN env var required for full mode")
            logger.error("Set it or use --dry-run to skip Devin sessions")
            sys.exit(1)

        vulns = run_scan(config)
        if not vulns:
            logger.info("No vulnerabilities found. Exiting.")
            return

        if args.dry_run:
            logger.info("DRY RUN: skipping issue creation and Devin sessions")
            tasks = [RemediationTask(vulnerability=v) for v in vulns if v.has_fix]
        else:
            tasks = run_remediation(config, vulns)

        run_report(tasks, config, args.output_dir)


if __name__ == "__main__":
    main()
