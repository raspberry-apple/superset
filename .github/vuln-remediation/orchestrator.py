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
"""Orchestrator that creates and manages Devin sessions to remediate vulnerabilities."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum

import requests

from config import PipelineConfig
from scanner import Vulnerability

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass
class RemediationTask:
    """Tracks a single vulnerability remediation attempt."""

    vulnerability: Vulnerability
    github_issue_number: int | None = None
    github_issue_url: str | None = None
    devin_session_id: str | None = None
    devin_session_url: str | None = None
    pull_request_url: str | None = None
    status: SessionStatus = SessionStatus.PENDING
    started_at: float | None = None
    completed_at: float | None = None
    error_message: str | None = None

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "vulnerability": self.vulnerability.to_dict(),
            "github_issue_number": self.github_issue_number,
            "github_issue_url": self.github_issue_url,
            "devin_session_id": self.devin_session_id,
            "devin_session_url": self.devin_session_url,
            "pull_request_url": self.pull_request_url,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
        }


@dataclass
class Orchestrator:
    """Manages the full remediation lifecycle: issues → Devin sessions → PRs."""

    config: PipelineConfig
    tasks: list[RemediationTask] = field(default_factory=list)

    # -- GitHub Issue Management --

    def _ensure_labels_exist(self) -> None:
        """Create labels in the repo if they don't already exist."""
        owner, repo = self.config.github_repo.split("/")
        for label_name in self.config.issue_labels:
            resp = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}/labels/{label_name}",
                headers=self.config.github_api_headers,
                timeout=10,
            )
            if resp.status_code == 404:
                color_map = {
                    "security": "d73a4a",
                    "vulnerability": "e99695",
                    "automated": "0075ca",
                }
                requests.post(
                    f"https://api.github.com/repos/{owner}/{repo}/labels",
                    headers=self.config.github_api_headers,
                    json={
                        "name": label_name,
                        "color": color_map.get(label_name, "ededed"),
                    },
                    timeout=10,
                )

    def create_github_issue(self, vuln: Vulnerability) -> tuple[int, str]:
        """Create a GitHub issue for a vulnerability. Returns (issue_number, issue_url)."""
        owner, repo = self.config.github_repo.split("/")
        resp = requests.post(
            f"https://api.github.com/repos/{owner}/{repo}/issues",
            headers=self.config.github_api_headers,
            json={
                "title": vuln.issue_title,
                "body": vuln.issue_body,
                "labels": self.config.issue_labels,
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        issue_number: int = data["number"]
        issue_url: str = data["html_url"]
        logger.info("Created issue #%d: %s", issue_number, vuln.issue_title)
        return issue_number, issue_url

    # -- Devin Session Management --

    def _build_remediation_prompt(self, task: RemediationTask) -> str:
        """Build the prompt for a Devin remediation session."""
        vuln = task.vulnerability

        if vuln.ecosystem == "python":
            return f"""You are remediating a security vulnerability in the Apache Superset repository.

## Vulnerability
- **CVE:** {vuln.cve_id}
- **Package:** {vuln.package}
- **Current Version:** {vuln.current_version}
- **Target Version:** {vuln.recommended_fix_version or 'latest secure version'}
- **GitHub Issue:** {task.github_issue_url or 'N/A'}

## Instructions
1. Check `requirements/base.in` and `pyproject.toml` for the version constraint on `{vuln.package}`
2. Update the version pin to `>={vuln.recommended_fix_version or 'latest'}` while respecting upper bounds
3. Regenerate `requirements/base.txt` by running: `uv pip compile pyproject.toml requirements/base.in -o requirements/base.txt`
4. Run the relevant test suite to verify no breakage: `pytest tests/unit_tests/ -x -q --timeout=120`
5. If tests fail due to API changes, fix the affected call sites
6. Run `pre-commit run --all-files` to ensure code quality
7. Create a PR with:
   - Title: `fix(security): upgrade {vuln.package} to {vuln.recommended_fix_version} [{vuln.cve_id}]`
   - Reference issue {task.github_issue_url or ''}
   - Include a summary of what changed and any API migration notes

## Important
- Do NOT modify unrelated files
- If the upgrade requires significant code changes (>10 files), document the scope and stop for review
- Close the linked GitHub issue in the PR description with `Fixes #{task.github_issue_number}`
"""
        else:  # npm
            return f"""You are remediating a security vulnerability in the Apache Superset frontend.

## Vulnerability
- **Advisory:** {vuln.cve_id}
- **Package:** {vuln.package}
- **Severity:** {vuln.severity.value.upper()}
- **GitHub Issue:** {task.github_issue_url or 'N/A'}

## Instructions
1. Navigate to `superset-frontend/`
2. Check if `{vuln.package}` is a direct or transitive dependency
3. If direct: update version in `package.json`, run `npm install`
4. If transitive: add an override in `package.json` under `overrides` field, or upgrade the parent package
5. Run `npm audit` to verify the vulnerability is resolved
6. Run `npm run test` to verify no breakage
7. Run `npm run lint` for code quality
8. Create a PR with:
   - Title: `fix(security): remediate {vuln.package} vulnerability [{vuln.cve_id}]`
   - Reference issue {task.github_issue_url or ''}

## Important
- Do NOT modify unrelated files
- Close the linked GitHub issue with `Fixes #{task.github_issue_number}`
"""

    def create_devin_session(self, task: RemediationTask) -> str:
        """Create a Devin session to remediate a vulnerability. Returns session_id."""
        prompt = self._build_remediation_prompt(task)
        vuln = task.vulnerability

        resp = requests.post(
            f"{self.config.devin_api_base}/sessions",
            headers=self.config.devin_api_headers,
            json={
                "prompt": prompt,
                "idempotent": True,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        session_id: str = data["session_id"]
        session_url: str = data.get("url", f"https://app.devin.ai/sessions/{session_id}")
        logger.info(
            "Created Devin session %s for %s %s",
            session_id,
            vuln.package,
            vuln.cve_id,
        )
        return session_id

    def poll_session_status(self, session_id: str) -> dict[str, object]:
        """Poll a Devin session for its current status."""
        resp = requests.get(
            f"{self.config.devin_api_base}/session/{session_id}",
            headers=self.config.devin_api_headers,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    # -- Orchestration --

    def create_tasks(self, vulnerabilities: list[Vulnerability]) -> list[RemediationTask]:
        """Create remediation tasks for a list of vulnerabilities."""
        self.tasks = [RemediationTask(vulnerability=v) for v in vulnerabilities if v.has_fix]
        skipped = [v for v in vulnerabilities if not v.has_fix]
        if skipped:
            logger.warning(
                "Skipping %d vulnerabilities with no fix: %s",
                len(skipped),
                ", ".join(f"{v.package}@{v.cve_id}" for v in skipped),
            )
        return self.tasks

    def run_pipeline(self) -> list[RemediationTask]:
        """Execute the full pipeline: create issues → start Devin sessions → monitor."""
        if not self.tasks:
            logger.info("No tasks to process")
            return self.tasks

        # Step 1: Ensure labels exist
        try:
            self._ensure_labels_exist()
        except Exception:
            logger.warning("Could not create labels (may lack permissions)")

        # Step 2: Create GitHub issues
        for task in self.tasks:
            try:
                issue_number, issue_url = self.create_github_issue(task.vulnerability)
                task.github_issue_number = issue_number
                task.github_issue_url = issue_url
            except Exception as e:
                logger.error(
                    "Failed to create issue for %s: %s",
                    task.vulnerability.package,
                    e,
                )
                task.status = SessionStatus.FAILED
                task.error_message = f"Issue creation failed: {e}"

        # Step 3: Start Devin sessions (respecting concurrency limit)
        active_sessions: list[RemediationTask] = []
        pending_tasks = [t for t in self.tasks if t.status == SessionStatus.PENDING]

        for task in pending_tasks:
            # Wait if at concurrency limit
            while len(active_sessions) >= self.config.max_concurrent_sessions:
                active_sessions = self._poll_active_sessions(active_sessions)
                if len(active_sessions) >= self.config.max_concurrent_sessions:
                    time.sleep(30)

            try:
                session_id = self.create_devin_session(task)
                task.devin_session_id = session_id
                task.devin_session_url = (
                    f"https://app.devin.ai/sessions/{session_id}"
                )
                task.status = SessionStatus.RUNNING
                task.started_at = time.time()
                active_sessions.append(task)
            except Exception as e:
                logger.error(
                    "Failed to create Devin session for %s: %s",
                    task.vulnerability.package,
                    e,
                )
                task.status = SessionStatus.FAILED
                task.error_message = f"Session creation failed: {e}"

        # Step 4: Wait for all active sessions to complete
        while active_sessions:
            active_sessions = self._poll_active_sessions(active_sessions)
            if active_sessions:
                logger.info("%d sessions still active", len(active_sessions))
                time.sleep(30)

        return self.tasks

    def _poll_active_sessions(
        self, active: list[RemediationTask]
    ) -> list[RemediationTask]:
        """Poll active sessions and update their status. Returns still-active tasks."""
        still_active: list[RemediationTask] = []
        for task in active:
            if not task.devin_session_id:
                continue
            try:
                status_data = self.poll_session_status(task.devin_session_id)
                session_status = status_data.get("status", "")
                status_detail = status_data.get("status_detail", "")

                if session_status == "stopped" or status_detail == "finished":
                    task.status = SessionStatus.SUCCEEDED
                    task.completed_at = time.time()
                    # Try to extract PR URL from structured output
                    structured = status_data.get("structured_output", {})
                    if isinstance(structured, dict):
                        task.pull_request_url = structured.get("pull_request_url")
                    logger.info(
                        "Session %s completed for %s",
                        task.devin_session_id,
                        task.vulnerability.package,
                    )
                elif session_status == "error":
                    task.status = SessionStatus.FAILED
                    task.completed_at = time.time()
                    task.error_message = f"Devin session error: {status_detail}"
                elif (
                    task.started_at
                    and time.time() - task.started_at
                    > self.config.session_timeout_seconds
                ):
                    task.status = SessionStatus.TIMED_OUT
                    task.completed_at = time.time()
                    task.error_message = "Session timed out"
                else:
                    still_active.append(task)
            except Exception as e:
                logger.error(
                    "Error polling session %s: %s", task.devin_session_id, e
                )
                still_active.append(task)

        return still_active

    def get_results_summary(self) -> dict[str, object]:
        """Return a structured summary of all task results."""
        total = len(self.tasks)
        succeeded = sum(1 for t in self.tasks if t.status == SessionStatus.SUCCEEDED)
        failed = sum(1 for t in self.tasks if t.status == SessionStatus.FAILED)
        timed_out = sum(1 for t in self.tasks if t.status == SessionStatus.TIMED_OUT)
        running = sum(1 for t in self.tasks if t.status == SessionStatus.RUNNING)
        pending = sum(1 for t in self.tasks if t.status == SessionStatus.PENDING)

        return {
            "total_tasks": total,
            "succeeded": succeeded,
            "failed": failed,
            "timed_out": timed_out,
            "running": running,
            "pending": pending,
            "success_rate": f"{succeeded / total * 100:.1f}%" if total > 0 else "N/A",
            "tasks": [t.to_dict() for t in self.tasks],
        }
